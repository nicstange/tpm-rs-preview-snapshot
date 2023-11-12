// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;

use super::io_slices;
use crypto_common;
use digest::{self, Digest};
use hmac::{Hmac, Mac};
#[cfg(feature = "sha1")]
use sha1;
#[cfg(any(feature = "sha256", feature = "sha384", feature = "sha512"))]
use sha2;
#[cfg(any(feature = "sha3_256", feature = "sha3_384", feature = "sha3_512"))]
use sha3;
#[cfg(feature = "sm3_256")]
use sm3;

use crate::interface;
use crate::utils;

pub const fn hash_alg_digest_len(alg: interface::TpmiAlgHash) -> u8 {
    match alg {
        #[cfg(feature = "sha1")]
        interface::TpmiAlgHash::Sha1 => 20u8,
        #[cfg(feature = "sha256")]
        interface::TpmiAlgHash::Sha256 => 32u8,
        #[cfg(feature = "sha384")]
        interface::TpmiAlgHash::Sha384 => 48u8,
        #[cfg(feature = "sha512")]
        interface::TpmiAlgHash::Sha512 => 64u8,
        #[cfg(feature = "sha3_256")]
        interface::TpmiAlgHash::Sha3_256 => 32u8,
        #[cfg(feature = "sha3_384")]
        interface::TpmiAlgHash::Sha3_384 => 48u8,
        #[cfg(feature = "sha3_512")]
        interface::TpmiAlgHash::Sha3_512 => 64u8,
        #[cfg(feature = "sm3_256")]
        interface::TpmiAlgHash::Sm3_256 => 32u8,
    }
}

pub const fn hash_alg_preimage_security_strength(alg: interface::TpmiAlgHash) -> Option<u16> {
    // Refer to NIST SP 800-57, part 1 for preimage resistance security strength
    // values of the SHA{1,2,3} family of hash algorithms.
    match alg {
        #[cfg(feature = "sha1")]
        interface::TpmiAlgHash::Sha1 => {
            // Sha1 is being phased out.
            None
        }
        #[cfg(feature = "sha256")]
        interface::TpmiAlgHash::Sha256 => Some(256u16),
        #[cfg(feature = "sha384")]
        interface::TpmiAlgHash::Sha384 => Some(384u16),
        #[cfg(feature = "sha512")]
        interface::TpmiAlgHash::Sha512 => Some(512u16),
        #[cfg(feature = "sha3_256")]
        interface::TpmiAlgHash::Sha3_256 => Some(256u16),
        #[cfg(feature = "sha3_384")]
        interface::TpmiAlgHash::Sha3_384 => Some(384u16),
        #[cfg(feature = "sha3_512")]
        interface::TpmiAlgHash::Sha3_512 => Some(512u16),
        #[cfg(feature = "sm3_256")]
        interface::TpmiAlgHash::Sm3_256 => {
            // Can't find an accessible document specifying the
            // preimage resistance security strength of SM3.
            None
        }
    }
}

pub const fn hash_alg_select_for_preimage_security_strength(
    strength: usize,
    minimize_digest_len: bool,
) -> Result<interface::TpmiAlgHash, interface::TpmErr> {
    // Refer to NIST SP 800-57, part 1 for preimage resistance security strength
    // values of the SHA{1,2,3} family of hash algorithms.
    // This selection function is used primarily when there's some choice of freedom
    // for implementations, e.g. when instantiating a Hash_DRBG construction for
    // key generation. For performance reasons, favor
    // - SHA2 over SHA3, independent of minimize_digest_len,
    // - SHA2-384 over SHA2-256 if !minimize_digest_len --  the former uses 64bits
    //   internally,
    // - SHA2-512 over SHA2-384 if !minimize_digest_len -- the effort is the same,
    //   but the former yields more bits per run.
    // SHA1 is getting phased out by NIST, don't use.
    // How SM3 relates to the NIST families is unknown to me, preferring one over
    // the other probably depends on policy anyway. Furthermore, there's no
    // easily accessible document specifying the preimage resistance security
    // strength -- don't use it either for now.
    if !minimize_digest_len {
        if strength <= 512 && cfg!(feature = "sha512") {
            return Ok(interface::TpmiAlgHash::Sha512);
        } else if strength <= 384 && cfg!(feature = "sha384") {
            return Ok(interface::TpmiAlgHash::Sha384);
        }
    }

    if strength <= 256 {
        if cfg!(feature = "sha256") {
            return Ok(interface::TpmiAlgHash::Sha256);
        } else if cfg!(feature = "sha3_256") {
            return Ok(interface::TpmiAlgHash::Sha3_256);
        }
    }

    if strength <= 384 {
        if cfg!(feature = "sha384") {
            return Ok(interface::TpmiAlgHash::Sha384);
        } else if cfg!(feature = "sha3_384") {
            return Ok(interface::TpmiAlgHash::Sha3_384);
        }
    }

    if strength <= 512 {
        if cfg!(feature = "sha512") {
            return Ok(interface::TpmiAlgHash::Sha512);
        } else if cfg!(feature = "sha3_512") {
            return Ok(interface::TpmiAlgHash::Sha3_512);
        }
    }

    Err(tpm_err_rc!(KEY_SIZE))
}

#[derive(Clone)]
pub enum HashInstance {
    #[cfg(feature = "sha1")]
    Sha1(sha1::Sha1),
    #[cfg(feature = "sha256")]
    Sha256(sha2::Sha256),
    #[cfg(feature = "sha384")]
    Sha384(sha2::Sha384),
    #[cfg(feature = "sha512")]
    Sha512(sha2::Sha512),
    #[cfg(feature = "sha3_256")]
    Sha3_256(sha3::Sha3_256),
    #[cfg(feature = "sha3_384")]
    Sha3_384(sha3::Sha3_384),
    #[cfg(feature = "sha3_512")]
    Sha3_512(sha3::Sha3_512),
    #[cfg(feature = "sm3_256")]
    Sm3_256(sm3::Sm3),
}

impl HashInstance {
    pub fn new(alg: interface::TpmiAlgHash) -> Self {
        match alg {
            #[cfg(feature = "sha1")]
            interface::TpmiAlgHash::Sha1 => Self::Sha1(sha1::Sha1::new()),
            #[cfg(feature = "sha256")]
            interface::TpmiAlgHash::Sha256 => Self::Sha256(sha2::Sha256::new()),
            #[cfg(feature = "sha384")]
            interface::TpmiAlgHash::Sha384 => Self::Sha384(sha2::Sha384::new()),
            #[cfg(feature = "sha512")]
            interface::TpmiAlgHash::Sha512 => Self::Sha512(sha2::Sha512::new()),
            #[cfg(feature = "sm3_256")]
            interface::TpmiAlgHash::Sm3_256 => Self::Sm3_256(sm3::Sm3::new()),
            #[cfg(feature = "sha3_256")]
            interface::TpmiAlgHash::Sha3_256 => Self::Sha3_256(sha3::Sha3_256::new()),
            #[cfg(feature = "sha3_384")]
            interface::TpmiAlgHash::Sha3_384 => Self::Sha3_384(sha3::Sha3_384::new()),
            #[cfg(feature = "sha3_512")]
            interface::TpmiAlgHash::Sha3_512 => Self::Sha3_512(sha3::Sha3_512::new()),
        }
    }

    pub fn update(&mut self, mut data: io_slices::IoSlices) {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha256")]
            Self::Sha256(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha384")]
            Self::Sha384(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha512")]
            Self::Sha512(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
        }
    }

    pub fn finalize_into_reset(&mut self, digest: &mut [u8]) {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(instance) => {
                let digest: &mut crypto_common::Output<sha1::Sha1> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
            #[cfg(feature = "sha256")]
            Self::Sha256(instance) => {
                let digest: &mut crypto_common::Output<sha2::Sha256> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
            #[cfg(feature = "sha384")]
            Self::Sha384(instance) => {
                let digest: &mut crypto_common::Output<sha2::Sha384> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
            #[cfg(feature = "sha512")]
            Self::Sha512(instance) => {
                let digest: &mut crypto_common::Output<sha2::Sha512> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(instance) => {
                let digest: &mut crypto_common::Output<sha3::Sha3_256> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(instance) => {
                let digest: &mut crypto_common::Output<sha3::Sha3_384> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(instance) => {
                let digest: &mut crypto_common::Output<sha3::Sha3_512> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(instance) => {
                let digest: &mut crypto_common::Output<sm3::Sm3> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
        }
    }

    pub fn finalize_into(mut self, digest: &mut [u8]) {
        self.finalize_into_reset(digest)
    }

    pub fn finalize_reset(&mut self) -> Result<interface::TpmtHa<'static>, interface::TpmErr> {
        let digest_len = self.digest_len();
        let mut digest_buf = utils::try_alloc_zeroizing_vec::<u8>(digest_len)?;
        self.finalize_into_reset(&mut digest_buf);
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(_) =>
            {
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sha1(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
            #[cfg(feature = "sha256")]
            Self::Sha256(_) =>
            {
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sha256(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
            #[cfg(feature = "sha384")]
            Self::Sha384(_) =>
            {
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sha384(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
            #[cfg(feature = "sha512")]
            Self::Sha512(_) =>
            {
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sha512(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(_) =>
            {
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sha3_256(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(_) =>
            {
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sha3_384(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(_) =>
            {
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sha3_512(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(_) =>
            {
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sm3_256(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
        }
    }

    pub fn finalize(mut self) -> Result<interface::TpmtHa<'static>, interface::TpmErr> {
        self.finalize_reset()
    }

    pub fn digest_len(&self) -> usize {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(_) => <sha1::Sha1 as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha256")]
            Self::Sha256(_) => <sha2::Sha256 as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha384")]
            Self::Sha384(_) => <sha2::Sha384 as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha512")]
            Self::Sha512(_) => <sha2::Sha512 as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(_) => <sha3::Sha3_256 as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(_) => <sha3::Sha3_384 as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(_) => <sha3::Sha3_512 as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(_) => <sm3::Sm3 as crypto_common::OutputSizeUser>::output_size(),
        }
    }
}

#[derive(Clone)]
pub enum HmacInstance {
    #[cfg(feature = "sha1")]
    Sha1(Hmac<sha1::Sha1>),
    #[cfg(feature = "sha256")]
    Sha256(Hmac<sha2::Sha256>),
    #[cfg(feature = "sha384")]
    Sha384(Hmac<sha2::Sha384>),
    #[cfg(feature = "sha512")]
    Sha512(Hmac<sha2::Sha512>),
    #[cfg(feature = "sha3_256")]
    Sha3_256(Hmac<sha3::Sha3_256>),
    #[cfg(feature = "sha3_384")]
    Sha3_384(Hmac<sha3::Sha3_384>),
    #[cfg(feature = "sha3_512")]
    Sha3_512(Hmac<sha3::Sha3_512>),
    #[cfg(feature = "sm3_256")]
    Sm3_256(Hmac<sm3::Sm3>),
}

impl HmacInstance {
    pub fn new(alg: interface::TpmiAlgHash, key: &[u8]) -> Self {
        match alg {
            #[cfg(feature = "sha1")]
            interface::TpmiAlgHash::Sha1 => {
                Self::Sha1(Hmac::<sha1::Sha1>::new_from_slice(key).unwrap())
            }
            #[cfg(feature = "sha256")]
            interface::TpmiAlgHash::Sha256 => {
                Self::Sha256(Hmac::<sha2::Sha256>::new_from_slice(key).unwrap())
            }
            #[cfg(feature = "sha384")]
            interface::TpmiAlgHash::Sha384 => {
                Self::Sha384(Hmac::<sha2::Sha384>::new_from_slice(key).unwrap())
            }
            #[cfg(feature = "sha512")]
            interface::TpmiAlgHash::Sha512 => {
                Self::Sha512(Hmac::<sha2::Sha512>::new_from_slice(key).unwrap())
            }
            #[cfg(feature = "sha3_256")]
            interface::TpmiAlgHash::Sha3_256 => {
                Self::Sha3_256(Hmac::<sha3::Sha3_256>::new_from_slice(key).unwrap())
            }
            #[cfg(feature = "sha3_384")]
            interface::TpmiAlgHash::Sha3_384 => {
                Self::Sha3_384(Hmac::<sha3::Sha3_384>::new_from_slice(key).unwrap())
            }
            #[cfg(feature = "sha3_512")]
            interface::TpmiAlgHash::Sha3_512 => {
                Self::Sha3_512(Hmac::<sha3::Sha3_512>::new_from_slice(key).unwrap())
            }
            #[cfg(feature = "sm3_256")]
            interface::TpmiAlgHash::Sm3_256 => {
                Self::Sm3_256(Hmac::<sm3::Sm3>::new_from_slice(key).unwrap())
            }
        }
    }

    pub fn update(&mut self, mut data: io_slices::IoSlices) {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha256")]
            Self::Sha256(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha384")]
            Self::Sha384(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha512")]
            Self::Sha512(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(instance) => {
                while let Some(data) = data.take_first() {
                    digest::Update::update(instance, data);
                }
            }
        }
    }

    pub fn finalize_into(self, digest: &mut [u8]) {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha1::Sha1>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
            #[cfg(feature = "sha256")]
            Self::Sha256(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha2::Sha256>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
            #[cfg(feature = "sha384")]
            Self::Sha384(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha2::Sha384>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
            #[cfg(feature = "sha512")]
            Self::Sha512(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha2::Sha512>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha3::Sha3_256>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha3::Sha3_384>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha3::Sha3_512>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sm3::Sm3>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
        }
    }

    pub fn finalize(self) -> Result<interface::TpmtHa<'static>, interface::TpmErr> {
        let digest_len = self.digest_len();
        let mut digest_buf = utils::try_alloc_zeroizing_vec::<u8>(digest_len)?;
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha1::Sha1>> =
                    digest_buf.as_mut_slice().into();
                digest::FixedOutput::finalize_into(instance, digest);
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sha1(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
            #[cfg(feature = "sha256")]
            Self::Sha256(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha2::Sha256>> =
                    digest_buf.as_mut_slice().into();
                digest::FixedOutput::finalize_into(instance, digest);
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sha256(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
            #[cfg(feature = "sha384")]
            Self::Sha384(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha2::Sha384>> =
                    digest_buf.as_mut_slice().into();
                digest::FixedOutput::finalize_into(instance, digest);
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sha384(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
            #[cfg(feature = "sha512")]
            Self::Sha512(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha2::Sha512>> =
                    digest_buf.as_mut_slice().into();
                digest::FixedOutput::finalize_into(instance, digest);
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sha512(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha3::Sha3_256>> =
                    digest_buf.as_mut_slice().into();
                digest::FixedOutput::finalize_into(instance, digest);
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sha3_256(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha3::Sha3_384>> =
                    digest_buf.as_mut_slice().into();
                digest::FixedOutput::finalize_into(instance, digest);
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sha3_384(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha3::Sha3_512>> =
                    digest_buf.as_mut_slice().into();
                digest::FixedOutput::finalize_into(instance, digest);
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sha3_512(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sm3::Sm3>> =
                    digest_buf.as_mut_slice().into();
                digest::FixedOutput::finalize_into(instance, digest);
                #[allow(clippy::useless_conversion)]
                Ok(interface::TpmtHa::Sm3_256(interface::TpmBuffer::Owned(
                    digest_buf.into(),
                )))
            }
        }
    }

    pub fn digest_len(&self) -> usize {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(_) => <Hmac<sha1::Sha1> as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha256")]
            Self::Sha256(_) => <Hmac<sha2::Sha256> as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha384")]
            Self::Sha384(_) => <Hmac<sha2::Sha384> as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha512")]
            Self::Sha512(_) => <Hmac<sha2::Sha512> as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(_) => {
                <Hmac<sha3::Sha3_256> as crypto_common::OutputSizeUser>::output_size()
            }
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(_) => {
                <Hmac<sha3::Sha3_384> as crypto_common::OutputSizeUser>::output_size()
            }
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(_) => {
                <Hmac<sha3::Sha3_512> as crypto_common::OutputSizeUser>::output_size()
            }
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(_) => <Hmac<sm3::Sm3> as crypto_common::OutputSizeUser>::output_size(),
        }
    }
}

#[cfg(test)]
macro_rules! cfg_select_hash {
    (($f:literal, $id:ident)) => {
        #[cfg(feature = $f)]
        return interface::TpmiAlgHash::$id;
        #[cfg(not(feature = $f))]
        {
            "Force compile error for no hash configured"
        }
    };
    (($f:literal, $id:ident), $(($f_more:literal, $id_more:ident)),+) => {
        #[cfg(feature = $f)]
        return interface::TpmiAlgHash::$id;
        #[cfg(not(feature = $f))]
        {
            cfg_select_hash!($(($f_more, $id_more)),+)
        }
    };
}

#[cfg(test)]
pub fn test_hash_alg() -> interface::TpmiAlgHash {
    cfg_select_hash!(
        ("sha512", Sha512),
        ("sha256", Sha256),
        ("sha3_512", Sha3_512),
        ("sha3_256", Sha3_256),
        ("sha384", Sha384),
        ("sha3_384", Sha3_384),
        ("sha1", Sha1),
        ("sm3_256", Sm3_256)
    );
}
