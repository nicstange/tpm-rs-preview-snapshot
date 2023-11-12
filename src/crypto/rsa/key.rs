// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use alloc::vec::Vec;

use super::crt_impl;
use super::{encrypt_impl, keygen_impl};
use crate::crypto::{io_slices, rng};
use crate::interface;
use crate::utils::{self, cfg_zeroize};
use cmpa::{self, MpMutUInt, MpUIntCommon as _};
use core::{convert, mem};

pub struct RsaPublicKey {
    modulus: Vec<u8>,
    public_exponent: Vec<u8>,
}

impl RsaPublicKey {
    fn new(modulus: Vec<u8>, public_exponent: Vec<u8>) -> Self {
        Self {
            modulus,
            public_exponent,
        }
    }

    pub fn encrypt(&self, x: &mut [u8]) -> Result<(), interface::TpmErr> {
        if x.len() < self.modulus_len() {
            return Err(tpm_err_rc!(NO_RESULT));
        }
        encrypt_impl::encrypt(
            x,
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&self.modulus),
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&self.public_exponent),
        )
    }

    pub fn modulus_len(&self) -> usize {
        self.modulus.len()
    }
}

impl<'a> convert::TryFrom<&'a RsaPublicKey> for (u32, interface::Tpm2bPublicKeyRsa<'a>) {
    type Error = interface::TpmErr;

    fn try_from(value: &'a RsaPublicKey) -> Result<Self, Self::Error> {
        let public_exponent = cmpa::MpBigEndianUIntByteSlice::from_bytes(&value.public_exponent);
        let public_exponent = public_exponent
            .try_into_u32()
            .map_err(|_| tpm_err_internal!())?;

        Ok((
            public_exponent,
            interface::Tpm2bPublicKeyRsa {
                buffer: interface::TpmBufferRef::Stable(&value.modulus).into(),
            },
        ))
    }
}

impl<'a> convert::TryFrom<(u32, interface::Tpm2bPublicKeyRsa<'a>)> for RsaPublicKey {
    type Error = interface::TpmErr;

    fn try_from(value: (u32, interface::Tpm2bPublicKeyRsa<'a>)) -> Result<Self, Self::Error> {
        let mut public_exponent_buf = utils::try_alloc_vec(mem::size_of::<u32>())?;
        let mut public_exponent =
            cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut public_exponent_buf);
        public_exponent.set_to_u32(value.0);
        let public_exponent = cmpa::MpBigEndianUIntByteSlice::from_bytes(&public_exponent_buf);
        if !keygen_impl::public_exponent_is_valid(&public_exponent) {
            return Err(tpm_err_rc!(NO_RESULT));
        }
        // The modulus will be copied anyway, no need to explictly stabilize the buffer
        // as the copy will be stable.
        let mut modulus_buf = utils::try_alloc_vec(value.1.buffer.len())?;
        modulus_buf.copy_from_slice(&value.1.buffer);
        let modulus = cmpa::MpBigEndianUIntByteSlice::from_bytes(&modulus_buf);
        let (modulus_is_nonzero, modulus_last_set_bit) = cmpa::ct_find_last_set_bit_mp(&modulus);
        if modulus_is_nonzero.unwrap() == 0 || modulus_last_set_bit < 8 * modulus.len() {
            return Err(tpm_err_rc!(NO_RESULT));
        }

        Ok(Self {
            modulus: modulus_buf,
            public_exponent: public_exponent_buf,
        })
    }
}

pub struct RsaPrivateKey {
    priv_key: crt_impl::RsaPrivateKeyCrt,
}

impl RsaPrivateKey {
    fn new(privkey: crt_impl::RsaPrivateKeyCrt) -> Self {
        Self { priv_key: privkey }
    }

    fn decrypt(&self, y: &mut [u8]) -> Result<(), interface::TpmErr> {
        self.priv_key.decrypt(y)
    }
}

impl cfg_zeroize::Zeroize for RsaPrivateKey {
    fn zeroize(&mut self) {
        self.priv_key.zeroize()
    }
}

impl cfg_zeroize::ZeroizeOnDrop for RsaPrivateKey {}

impl convert::TryFrom<&RsaPrivateKey> for interface::Tpm2bPrivateKeyRsa<'static> {
    type Error = interface::TpmErr;

    fn try_from(value: &RsaPrivateKey) -> Result<Self, Self::Error> {
        Self::try_from(&value.priv_key)
    }
}

pub struct RsaKey {
    pub_key: RsaPublicKey,
    priv_key: Option<RsaPrivateKey>,
}

impl RsaKey {
    pub fn generate(
        modulus_nbits: usize,
        public_exponent: Vec<u8>,
        rng: &mut dyn rng::RngCore,
        additional_rng_generate_input: Option<&io_slices::IoSlices>,
    ) -> Result<Self, interface::TpmErr> {
        if modulus_nbits % (2 * 8) != 0 {
            return Err(tpm_err_rc!(NO_RESULT));
        }

        // p and q will be of equal lengths.
        let p_len = modulus_nbits / (2 * 8);
        let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p_len);
        let mut p_buf = utils::try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
        let mut q_buf = utils::try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;

        keygen_impl::gen_prime_pair_nist_sp800_56br2(
            &mut p_buf,
            &mut q_buf,
            modulus_nbits,
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&public_exponent),
            rng,
            additional_rng_generate_input,
        )
        .map_err(interface::TpmErr::from)?;

        let mut modulus_buf = utils::try_alloc_vec::<u8>(2 * p_len)?;
        let mut modulus = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut modulus_buf);
        modulus.copy_from(&cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&p_buf));
        cmpa::ct_mul_trunc_mp_mp(
            &mut modulus,
            p_len,
            &cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&q_buf),
        );

        let priv_key = crt_impl::RsaPrivateKeyCrt::new_from_p_q(
            p_len,
            p_buf,
            p_len,
            q_buf,
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&public_exponent),
        )?;

        let pub_key = RsaPublicKey::new(modulus_buf, public_exponent);

        Ok(Self {
            pub_key,
            priv_key: Some(RsaPrivateKey::new(priv_key)),
        })
    }

    pub fn pub_key(&self) -> &RsaPublicKey {
        &self.pub_key
    }

    pub fn priv_key(&self) -> Option<&RsaPrivateKey> {
        self.priv_key.as_ref()
    }

    pub fn encrypt(&self, x: &mut [u8]) -> Result<(), interface::TpmErr> {
        self.pub_key.encrypt(x)
    }

    pub fn decrypt(&self, y: &mut [u8]) -> Result<(), interface::TpmErr> {
        if y.len() < self.pub_key.modulus_len()
            || cmpa::ct_lt_mp_mp(
                &cmpa::MpBigEndianUIntByteSlice::from_bytes(y),
                &cmpa::MpBigEndianUIntByteSlice::from_bytes(&self.pub_key.modulus),
            )
            .unwrap()
                == 0
        {
            return Err(tpm_err_rc!(NO_RESULT));
        }
        self.priv_key.as_ref().ok_or(tpm_err_rc!(KEY))?.decrypt(y)
    }
}

impl cfg_zeroize::Zeroize for RsaKey {
    fn zeroize(&mut self) {
        if let Some(k) = self.priv_key.as_mut() {
            k.zeroize();
        }
    }
}

impl cfg_zeroize::ZeroizeOnDrop for RsaKey {}

impl<'a>
    convert::TryFrom<(
        u32,
        interface::Tpm2bPublicKeyRsa<'a>,
        Option<interface::Tpm2bPrivateKeyRsa<'a>>,
    )> for RsaKey
{
    type Error = interface::TpmErr;

    fn try_from(
        value: (
            u32,
            interface::Tpm2bPublicKeyRsa<'a>,
            Option<interface::Tpm2bPrivateKeyRsa<'a>>,
        ),
    ) -> Result<Self, Self::Error> {
        let pub_key = RsaPublicKey::try_from((value.0, value.1))?;
        let priv_key = match &value.2 {
            Some(priv_key) => {
                // Stabilize the private key, i.e. the first prime factor. Strictly speaking it
                // is not needed, because RsaPrivateKeyCrt will make itself a copy
                // early anyway. But for the sake of code robustness, still do it.
                let mut p =
                    interface::TpmBuffer::from(interface::TpmBufferRef::from(&priv_key.buffer));
                p.stabilize()?;
                let priv_key = crt_impl::RsaPrivateKeyCrt::new_from_p(
                    &cmpa::MpBigEndianUIntByteSlice::from_bytes(&pub_key.modulus),
                    &cmpa::MpBigEndianUIntByteSlice::from_bytes(&p),
                    &cmpa::MpBigEndianUIntByteSlice::from_bytes(&pub_key.public_exponent),
                )?;
                Some(priv_key)
            }
            None => None,
        };
        Ok(Self {
            pub_key,
            priv_key: priv_key.map(RsaPrivateKey::new),
        })
    }
}

#[cfg(test)]
pub fn test_key() -> RsaKey {
    // This is the modulus corresponding to the prime pair for the sha256 testcase
    // in keygen_impl.
    const TEST_MODULUS: [u8; 256] = cmpa::hexstr::bytes_from_hexstr_cnst::<256>(
        "bdc4ef4fe35fe8b60f24312470a8c6e59215da963dbcf933b1eacc82b9fa7a69\
         3a4d57bd4d55e1493a70d2798ce2818d0cf9e241ae0aac40218de2abe790bffb\
         4e8f83c3d0c5704e3c79910e6cff4d7faf39965e0dcb50d2bfe32be1080dbfb8\
         9726fbfba76fd5e000d8e6b455994b26a4ae22fef5768fe74c3728db7bcd94ea\
         3d20dfafa6c37e717ca96c2e37712f0997132bf9c1c1a4f2bc903a7101eb9585\
         75dc413560bb4d3f8cd5125cb285d67938cd3613f020381617a354e655297a8a\
         aec16711b105a55a25698a45b6f34266be5657de846b37b877411e727e9df99f\
         6110efe6c61e2093922a234360773aac3b19d71d7676bbcda62b19f2085a9823",
    );

    // First prime factor of the TEST_MODULUS.
    const TEST_P: [u8; 128] = cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
        "c13469df9fbc5ddc9b33713299d2911609ae5a772cb253a9634071639130bb47\
         4e2820a3bd859a631e660f1b28d2a03942ee2ad7fa68d94a8870ef70ba534792\
         d4b62426ae7e5b4c7c85087f358266b31b8cfebe9379744abfbbc6298f158189\
         bd503f5657dc64ea2031a6537ee24625b44c935e28c12b8b2c2b46db50c3aaa1",
    );

    let modulus = interface::Tpm2bPublicKeyRsa {
        buffer: interface::TpmBuffer::Borrowed(interface::TpmBufferRef::Stable(&TEST_MODULUS)),
    };
    let p = interface::Tpm2bPrivateKeyRsa {
        buffer: interface::TpmBuffer::Borrowed(interface::TpmBufferRef::Stable(&TEST_P)),
    };
    let e = cmpa::MpBigEndianUIntByteSlice::from_bytes(keygen_impl::MIN_PUBLIC_EXPONENT)
        .try_into_u32()
        .unwrap();
    RsaKey::try_from((e, modulus, Some(p))).unwrap()
}
