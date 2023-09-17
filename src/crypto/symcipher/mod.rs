extern crate alloc;
use crate::crypto::{io_slices, rng};
use crate::interface;
use crate::utils::{self, cfg_zeroize};
use alloc::vec::Vec;
use cipher::{BlockDecryptMut as _, BlockEncryptMut as _, IvState as _, StreamCipher as _};
use core::convert;
use core::ops::Deref as _;
use crypto_common::{
    BlockSizeUser as _, IvSizeUser as _, KeyInit as _, KeyIvInit as _, KeySizeUser as _,
};

#[cfg(feature = "aes")]
use aes;
#[cfg(feature = "camellia")]
use camellia;
#[cfg(feature = "cbc")]
use cbc;
#[cfg(feature = "cfb")]
use cfb_mode;
#[cfg(feature = "ctr")]
mod ctr_impl;
#[cfg(feature = "ecb")]
use ecb;
#[cfg(feature = "ofb")]
use ofb;
#[cfg(feature = "sm4")]
use sm4;

#[cfg(feature = "aes")]
#[derive(Clone, Copy)]
pub enum SymBlockCipherAesKeySize {
    Aes128,
    Aes192,
    Aes256,
}

#[cfg(feature = "camellia")]
#[derive(Clone, Copy)]
pub enum SymBlockCipherCamelliaKeySize {
    Camellia128,
    Camellia192,
    Camellia256,
}

#[cfg(feature = "sm4")]
#[derive(Clone, Copy)]
pub enum SymBlockCipherSm4KeySize {
    Sm4_128,
}

#[derive(Clone, Copy)]
pub enum SymBlockCipherAlg {
    #[cfg(feature = "aes")]
    Aes(SymBlockCipherAesKeySize),
    #[cfg(feature = "camellia")]
    Camellia(SymBlockCipherCamelliaKeySize),
    #[cfg(feature = "sm4")]
    Sm4(SymBlockCipherSm4KeySize),
}

macro_rules! match_on_block_alg {
    ($block_cipher_value:expr, $m:ident $(, $($args:tt),*)?) => {
        match $block_cipher_value {
            #[cfg(feature = "aes")]
            SymBlockCipherAlg::Aes(key_size) => {
                match key_size {
                    SymBlockCipherAesKeySize::Aes128 => {
                        $m!($($($args),*,)? Aes, 128)
                    },
                    SymBlockCipherAesKeySize::Aes192 => {
                        $m!($($($args),*,)? Aes, 192)
                    },
                    SymBlockCipherAesKeySize::Aes256 => {
                        $m!($($($args),*,)? Aes, 256)
                    },
                }
            },
            #[cfg(feature = "camellia")]
            SymBlockCipherAlg::Camellia(key_size) => {
                match key_size {
                    SymBlockCipherCamelliaKeySize::Camellia128 => {
                        $m!($($($args),*,)? Camellia, 128)
                    },
                    SymBlockCipherCamelliaKeySize::Camellia192 => {
                        $m!($($($args),*,)? Camellia, 192)
                    },
                    SymBlockCipherCamelliaKeySize::Camellia256 => {
                        $m!($($($args),*,)? Camellia, 256)
                    },
                }
            },
            #[cfg(feature = "sm4")]
            SymBlockCipherAlg::Sm4(key_size) => {
                match key_size {
                    SymBlockCipherSm4KeySize::Sm4_128 => {
                        $m!($($($args),*,)? Sm4, 128)
                    },
                }
            },
        }
    };
}

macro_rules! block_alg_id_to_impl {
    (Aes, 128) => {
        aes::Aes128
    };
    (Aes, 192) => {
        aes::Aes192
    };
    (Aes, 256) => {
        aes::Aes256
    };
    (Camellia, 128) => {
        camellia::Camellia128
    };
    (Camellia, 192) => {
        camellia::Camellia192
    };
    (Camellia, 256) => {
        camellia::Camellia256
    };
    (Sm4, 128) => {
        sm4::Sm4
    };
}

impl SymBlockCipherAlg {
    pub fn key_len(&self) -> usize {
        macro_rules! key_len_for_block_alg {
            ($block_alg_id:ident,
             $key_size:tt) => {{
                let key_len = <block_alg_id_to_impl!($block_alg_id, $key_size)>::key_size();
                debug_assert_eq!(8 * key_len, $key_size);
                key_len
            }};
        }
        match_on_block_alg!(self, key_len_for_block_alg)
    }

    pub fn block_len(&self) -> usize {
        macro_rules! block_alg_block_len {
            ($block_alg_id:ident,
             $key_size:tt) => {
                <block_alg_id_to_impl!($block_alg_id, $key_size)>::block_size()
            };
        }
        match_on_block_alg!(self, block_alg_block_len)
    }

    pub fn iv_len_for_mode(&self, mode: interface::TpmiAlgCipherMode) -> usize {
        SymBlockModeImpl::new(mode, *self).iv_len()
    }

    pub fn msg_len_alignment_for_mode(&self, mode: interface::TpmiAlgCipherMode) -> usize {
        SymBlockModeImpl::new(mode, *self).msg_len_alignment()
    }
}

impl convert::TryFrom<(interface::TpmiAlgSymObject, u16)> for SymBlockCipherAlg {
    type Error = interface::TpmErr;

    fn try_from(value: (interface::TpmiAlgSymObject, u16)) -> Result<Self, Self::Error> {
        let (block_alg, key_size) = value;

        match block_alg {
            #[cfg(feature = "aes")]
            interface::TpmiAlgSymObject::Aes => match key_size {
                128 => Ok(Self::Aes(SymBlockCipherAesKeySize::Aes128)),
                192 => Ok(Self::Aes(SymBlockCipherAesKeySize::Aes192)),
                256 => Ok(Self::Aes(SymBlockCipherAesKeySize::Aes256)),
                _ => Err(tpm_err_rc!(VALUE)),
            },
            #[cfg(feature = "camellia")]
            interface::TpmiAlgSymObject::Camellia => match key_size {
                128 => Ok(Self::Camellia(SymBlockCipherCamelliaKeySize::Camellia128)),
                192 => Ok(Self::Camellia(SymBlockCipherCamelliaKeySize::Camellia192)),
                256 => Ok(Self::Camellia(SymBlockCipherCamelliaKeySize::Camellia256)),
                _ => Err(tpm_err_rc!(VALUE)),
            },
            #[cfg(feature = "sm4")]
            interface::TpmiAlgSymObject::Sm4 => match key_size {
                128 => Ok(Self::Sm4(SymBlockCipherSm4KeySize::Sm4_128)),
                _ => Err(tpm_err_rc!(VALUE)),
            },
        }
    }
}

impl convert::From<&SymBlockCipherAlg> for (interface::TpmiAlgSymObject, u16) {
    fn from(value: &SymBlockCipherAlg) -> Self {
        match value {
            SymBlockCipherAlg::Aes(key_size) => (
                interface::TpmiAlgSymObject::Aes,
                match key_size {
                    SymBlockCipherAesKeySize::Aes128 => 128,
                    SymBlockCipherAesKeySize::Aes192 => 192,
                    SymBlockCipherAesKeySize::Aes256 => 256,
                },
            ),
            SymBlockCipherAlg::Camellia(key_size) => (
                interface::TpmiAlgSymObject::Camellia,
                match key_size {
                    SymBlockCipherCamelliaKeySize::Camellia128 => 128,
                    SymBlockCipherCamelliaKeySize::Camellia192 => 192,
                    SymBlockCipherCamelliaKeySize::Camellia256 => 256,
                },
            ),
            SymBlockCipherAlg::Sm4(key_size) => (
                interface::TpmiAlgSymObject::Sm4,
                match key_size {
                    SymBlockCipherSm4KeySize::Sm4_128 => 128,
                },
            ),
        }
    }
}

pub struct SymBlockCipherKey {
    block_alg: SymBlockCipherAlg,
    key: cfg_zeroize::Zeroizing<Vec<u8>>,
}

impl SymBlockCipherKey {
    pub fn get_block_alg(&self) -> SymBlockCipherAlg {
        self.block_alg
    }

    pub fn generate(
        block_alg: SymBlockCipherAlg,
        rng: &mut dyn rng::RngCore,
        additional_rng_generate_input: Option<&io_slices::IoSlices>,
    ) -> Result<Self, interface::TpmErr> {
        let mut key = utils::try_alloc_zeroizing_vec::<u8>(block_alg.key_len())?;
        rng.generate(
            &mut io_slices::IoSlicesMut::new(&mut [Some(&mut key)]),
            additional_rng_generate_input,
        )?;
        Ok(Self { block_alg, key })
    }

    pub fn encrypt(
        &self,
        mode: interface::TpmiAlgCipherMode,
        iv: &[u8],
        dst: &mut [u8],
        src: &[u8],
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), interface::TpmErr> {
        SymBlockModeImpl::new(mode, self.block_alg).encrypt(&self.key, iv, dst, src, iv_out)
    }

    pub fn encrypt_in_place(
        &self,
        mode: interface::TpmiAlgCipherMode,
        iv: &[u8],
        msg: &mut [u8],
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), interface::TpmErr> {
        SymBlockModeImpl::new(mode, self.block_alg).encrypt_in_place(&self.key, iv, msg, iv_out)
    }

    pub fn decrypt(
        &self,
        mode: interface::TpmiAlgCipherMode,
        iv: &[u8],
        dst: &mut [u8],
        src: &[u8],
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), interface::TpmErr> {
        SymBlockModeImpl::new(mode, self.block_alg).decrypt(&self.key, iv, dst, src, iv_out)
    }

    pub fn decrypt_in_place(
        &self,
        mode: interface::TpmiAlgCipherMode,
        iv: &[u8],
        msg: &mut [u8],
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), interface::TpmErr> {
        SymBlockModeImpl::new(mode, self.block_alg).decrypt_in_place(&self.key, iv, msg, iv_out)
    }
}

impl convert::TryFrom<(SymBlockCipherAlg, &[u8])> for SymBlockCipherKey {
    type Error = interface::TpmErr;

    fn try_from(value: (SymBlockCipherAlg, &[u8])) -> Result<Self, Self::Error> {
        let (block_alg, supplied_key) = value;

        if supplied_key.len() != block_alg.key_len() {
            return Err(tpm_err_rc!(KEY_SIZE));
        }

        let mut key = utils::try_alloc_zeroizing_vec::<u8>(block_alg.key_len())?;
        key.copy_from_slice(supplied_key);

        Ok(Self { block_alg, key })
    }
}

impl cfg_zeroize::ZeroizeOnDrop for SymBlockCipherKey {}

struct SymBlockModeImpl {
    mode: interface::TpmiAlgCipherMode,
    block_alg: SymBlockCipherAlg,
}

macro_rules! match_on_mode {
    ($mode_value:expr, $m:ident $(, $($args:tt),*)?) => {
        match $mode_value {
            #[cfg(feature = "ctr")]
            interface::TpmiAlgCipherMode::Ctr => {
                $m!($($($args),*,)? Ctr)
            },
            #[cfg(feature = "ofb")]
            interface::TpmiAlgCipherMode::Ofb => {
                $m!($($($args),*,)? Ofb)
            },
            #[cfg(feature = "cbc")]
            interface::TpmiAlgCipherMode::Cbc => {
                $m!($($($args),*,)? Cbc)
            },
            #[cfg(feature = "cfb")]
            interface::TpmiAlgCipherMode::Cfb => {
                $m!($($($args),*,)? Cfb)
            },
            #[cfg(feature = "ecb")]
            interface::TpmiAlgCipherMode::Ecb => {
                $m!($($($args),*,)? Ecb)
            },
        }
    };
}

macro_rules! mode_id_to_enc_impl {
    (Ctr, $block_alg_impl:ty) => {
        ctr_impl::Encryptor::<$block_alg_impl>
    };
    (Ofb, $block_alg_impl:ty) => {
        ofb::Ofb::<$block_alg_impl>
    };
    (Cbc, $block_alg_impl:ty) => {
        cbc::Encryptor::<$block_alg_impl>
    };
    (Cfb, $block_alg_impl:ty) => {
        cfb_mode::Encryptor::<$block_alg_impl>
    };
    (Ecb, $block_alg_impl:ty) => {
        ecb::Encryptor::<$block_alg_impl>
    };
}

macro_rules! mode_id_to_dec_impl {
    (Ctr, $block_alg_impl:ty) => {
        ctr_impl::Decryptor::<$block_alg_impl>
    };
    (Ofb, $block_alg_impl:ty) => {
        ofb::Ofb::<$block_alg_impl>
    };
    (Cbc, $block_alg_impl:ty) => {
        cbc::Decryptor::<$block_alg_impl>
    };
    (Cfb, $block_alg_impl:ty) => {
        cfb_mode::Decryptor::<$block_alg_impl>
    };
    (Ecb, $block_alg_impl:ty) => {
        ecb::Decryptor::<$block_alg_impl>
    };
}

impl SymBlockModeImpl {
    fn new(mode: interface::TpmiAlgCipherMode, block_alg: SymBlockCipherAlg) -> Self {
        Self { mode, block_alg }
    }

    fn iv_len(&self) -> usize {
        macro_rules! iv_len_for_mode_and_block_alg {
            (Ecb $(, $($args:tt),*)?) => {
                0
            };
            ($mode_id:tt,
             $block_alg_id:ident,
             $key_size:tt) => {
                <mode_id_to_enc_impl!($mode_id, block_alg_id_to_impl!($block_alg_id, $key_size))>::iv_size()
            };
        }

        match_on_mode!(
            self.mode,
            match_on_block_alg,
            { &self.block_alg },
            iv_len_for_mode_and_block_alg
        )
    }

    fn msg_len_alignment(&self) -> usize {
        macro_rules! msg_len_alignment_for_mode {
            (Ctr $(, $($args:tt),*)?) => {
                1
            };
            (Ofb $(, $($args:tt),*)?) => {
                1
            };
            (Cfb $(, $($args:tt),*)?) => {
                1
            };
            ($mode_id:tt $(, $($args:tt),*)?) => {
                self.block_alg.block_len()
            };
        }
        match_on_mode!(self.mode, msg_len_alignment_for_mode)
    }

    fn encrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        dst: &mut [u8],
        src: &[u8],
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), interface::TpmErr> {
        if src.len() != dst.len() || key.len() != self.block_alg.key_len() {
            return Err(tpm_err_internal!());
        }

        macro_rules! encryptor_new_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let iv_len = <mode_id_to_enc_impl!(
                    $mode_id,
                    block_alg_id_to_impl!($block_alg_id, $key_size)
                )>::iv_size();
                if iv.len() != iv_len {
                    return Err(tpm_err_rc!(NO_RESULT));
                } else if let Some(iv_out) = &iv_out {
                    if iv_out.len() != iv_len {
                        return Err(tpm_err_rc!(NO_RESULT));
                    }
                }
                <mode_id_to_enc_impl!(
                                            $mode_id,
                                            block_alg_id_to_impl!($block_alg_id, $key_size)
                                        )>::new(key.into(), iv.into())
            }};
        }

        macro_rules! encryptor_new_no_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                if iv.len() != 0 {
                    return Err(tpm_err_rc!(NO_RESULT));
                } else if let Some(iv_out) = iv_out {
                    if iv_out.len() != 0 {
                        return Err(tpm_err_rc!(NO_RESULT));
                    }
                }
                <mode_id_to_enc_impl!(
                                            $mode_id,
                                            block_alg_id_to_impl!($block_alg_id, $key_size)
                                        )>::new(key.into())
            }};
        }

        // Modes with IV implementing the cipher::BlockEncryptMut trait and only capable
        // of handling messages with length aligned to the block size.
        macro_rules! encrypt_aligned_with_block_encrypt_mode_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let block_len = <block_alg_id_to_impl!($block_alg_id, $key_size)>::block_size();
                if src.len() % block_len != 0 {
                    return Err(tpm_err_rc!(SIZE));
                }
                let mut enc = encryptor_new_iv!($mode_id, $block_alg_id, $key_size);
                let dst_chunks = dst.chunks_exact_mut(block_len);
                let src_chunks = src.chunks_exact(block_len);
                for (dst_chunk, src_chunk) in dst_chunks.zip(src_chunks) {
                    enc.encrypt_block_b2b_mut(src_chunk.into(), dst_chunk.into());
                }
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice(enc.iv_state().deref());
                }
            }};
        }

        // Modes without IV implementing the cipher::BlockEncryptMut trait and only
        // capable of handling messages with length aligned to the block size.
        macro_rules! encrypt_aligned_with_block_encrypt_mode_no_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let block_len = <block_alg_id_to_impl!($block_alg_id, $key_size)>::block_size();
                if src.len() % block_len != 0 {
                    return Err(tpm_err_rc!(SIZE));
                }
                let mut enc = encryptor_new_no_iv!($mode_id, $block_alg_id, $key_size);
                let dst_chunks = dst.chunks_exact_mut(block_len);
                let src_chunks = src.chunks_exact(block_len);
                for (dst_chunk, src_chunk) in dst_chunks.zip(src_chunks) {
                    enc.encrypt_block_b2b_mut(src_chunk.into(), dst_chunk.into());
                }
            }};
        }

        // Modes with IV implementing the cipher::BlockEncryptMut trait and capable of
        // handling messages with any length.
        macro_rules! encrypt_unaligned_with_block_encrypt_mode_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let block_len = <block_alg_id_to_impl!($block_alg_id, $key_size)>::block_size();
                let mut block_buf = if src.len() % block_len != 0 {
                    utils::try_alloc_zeroizing_vec::<u8>(block_len)?
                } else {
                    cfg_zeroize::Zeroizing::<Vec<u8>>::from(Vec::new())
                };
                let mut enc = encryptor_new_iv!($mode_id, $block_alg_id, $key_size);
                let mut dst_chunks = dst.chunks_exact_mut(block_len);
                let mut src_chunks = src.chunks_exact(block_len);
                for (dst_chunk, src_chunk) in (&mut dst_chunks).zip(&mut src_chunks) {
                    enc.encrypt_block_b2b_mut(src_chunk.into(), dst_chunk.into());
                }
                let dst_remainder = dst_chunks.into_remainder();
                let src_remainder = src_chunks.remainder();
                if !src_remainder.is_empty() {
                    let l = src_remainder.len();
                    block_buf[0..l].copy_from_slice(src_remainder);
                    enc.encrypt_block_mut(block_buf.as_mut_slice().into());
                    dst_remainder.copy_from_slice(&block_buf[0..l]);
                }
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice(enc.iv_state().deref());
                }
            }};
        }

        // Modes with IV implementing the cipher::StreamCipherCore trait.
        macro_rules! encrypt_unaligned_with_stream_cipher_core_mode_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let mut enc = encryptor_new_iv!($mode_id, $block_alg_id, $key_size);
                enc.apply_keystream_b2b(src, dst)
                    .map_err(|_| tpm_err_internal!())?;
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice(enc.get_core().iv_state().deref());
                }
            }};
        }

        macro_rules! encrypt_with_mode {
            (Ctr $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    encrypt_unaligned_with_block_encrypt_mode_iv,
                    Ctr
                )
            };
            (Ofb $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    encrypt_unaligned_with_stream_cipher_core_mode_iv,
                    Ofb
                )
            };
            (Cbc $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    encrypt_aligned_with_block_encrypt_mode_iv,
                    Cbc
                )
            };
            (Cfb $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    encrypt_unaligned_with_block_encrypt_mode_iv,
                    Cfb
                )
            };
            (Ecb $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    encrypt_aligned_with_block_encrypt_mode_no_iv,
                    Ecb
                )
            };
        }

        match_on_mode!(self.mode, encrypt_with_mode);

        Ok(())
    }

    fn encrypt_in_place(
        &self,
        key: &[u8],
        iv: &[u8],
        msg: &mut [u8],
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), interface::TpmErr> {
        if key.len() != self.block_alg.key_len() {
            return Err(tpm_err_internal!());
        }

        macro_rules! encryptor_new_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let iv_len = <mode_id_to_enc_impl!(
                    $mode_id,
                    block_alg_id_to_impl!($block_alg_id, $key_size)
                )>::iv_size();
                if iv.len() != iv_len {
                    return Err(tpm_err_rc!(NO_RESULT));
                } else if let Some(iv_out) = &iv_out {
                    if iv_out.len() != iv_len {
                        return Err(tpm_err_rc!(NO_RESULT));
                    }
                }
                <mode_id_to_enc_impl!(
                                            $mode_id,
                                            block_alg_id_to_impl!($block_alg_id, $key_size)
                                        )>::new(key.into(), iv.into())
            }};
        }

        macro_rules! encryptor_new_no_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                if iv.len() != 0 {
                    return Err(tpm_err_rc!(NO_RESULT));
                } else if let Some(iv_out) = iv_out {
                    if iv_out.len() != 0 {
                        return Err(tpm_err_rc!(NO_RESULT));
                    }
                }
                <mode_id_to_enc_impl!(
                                            $mode_id,
                                            block_alg_id_to_impl!($block_alg_id, $key_size)
                                        )>::new(key.into())
            }};
        }

        // Modes with IV implementing the cipher::BlockEncryptMut trait and only capable
        // of handling messages with length aligned to the block size.
        macro_rules! encrypt_aligned_with_block_encrypt_mode_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let block_len = <block_alg_id_to_impl!($block_alg_id, $key_size)>::block_size();
                if msg.len() % block_len != 0 {
                    return Err(tpm_err_rc!(SIZE));
                }
                let mut enc = encryptor_new_iv!($mode_id, $block_alg_id, $key_size);
                let msg_chunks = msg.chunks_exact_mut(block_len);
                for msg_chunk in msg_chunks {
                    enc.encrypt_block_mut(msg_chunk.into());
                }
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice(enc.iv_state().deref());
                }
            }};
        }

        // Modes without IV implementing the cipher::BlockEncryptMut trait and only
        // capable of handling messages with length aligned to the block size.
        macro_rules! encrypt_aligned_with_block_encrypt_mode_no_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let block_len = <block_alg_id_to_impl!($block_alg_id, $key_size)>::block_size();
                if msg.len() % block_len != 0 {
                    return Err(tpm_err_rc!(SIZE));
                }
                let mut enc = encryptor_new_no_iv!($mode_id, $block_alg_id, $key_size);
                let msg_chunks = msg.chunks_exact_mut(block_len);
                for msg_chunk in msg_chunks {
                    enc.encrypt_block_mut(msg_chunk.into());
                }
            }};
        }

        // Modes with IV implementing the cipher::BlockEncryptMut trait and capable of
        // handling messages with any length.
        macro_rules! encrypt_unaligned_with_block_encrypt_mode_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let block_len = <block_alg_id_to_impl!($block_alg_id, $key_size)>::block_size();
                let mut block_buf = if msg.len() % block_len != 0 {
                    utils::try_alloc_zeroizing_vec::<u8>(block_len)?
                } else {
                    cfg_zeroize::Zeroizing::<Vec<u8>>::from(Vec::new())
                };
                let mut enc = encryptor_new_iv!($mode_id, $block_alg_id, $key_size);
                let mut msg_chunks = msg.chunks_exact_mut(block_len);
                for msg_chunk in &mut msg_chunks {
                    enc.encrypt_block_mut(msg_chunk.into());
                }
                let msg_remainder = msg_chunks.into_remainder();
                if !msg_remainder.is_empty() {
                    let l = msg_remainder.len();
                    block_buf[0..l].copy_from_slice(msg_remainder);
                    enc.encrypt_block_mut(block_buf.as_mut_slice().into());
                    msg_remainder.copy_from_slice(&block_buf[0..l]);
                }
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice(enc.iv_state().deref());
                }
            }};
        }

        // Modes with IV implementing the cipher::StreamCipherCore trait.
        macro_rules! encrypt_unaligned_with_stream_cipher_core_mode_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let mut enc = encryptor_new_iv!($mode_id, $block_alg_id, $key_size);
                enc.apply_keystream(msg);
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice(enc.get_core().iv_state().deref());
                }
            }};
        }

        macro_rules! encrypt_with_mode {
            (Ctr $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    encrypt_unaligned_with_block_encrypt_mode_iv,
                    Ctr
                )
            };
            (Ofb $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    encrypt_unaligned_with_stream_cipher_core_mode_iv,
                    Ofb
                )
            };
            (Cbc $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    encrypt_aligned_with_block_encrypt_mode_iv,
                    Cbc
                )
            };
            (Cfb $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    encrypt_unaligned_with_block_encrypt_mode_iv,
                    Cfb
                )
            };
            (Ecb $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    encrypt_aligned_with_block_encrypt_mode_no_iv,
                    Ecb
                )
            };
        }

        match_on_mode!(self.mode, encrypt_with_mode);

        Ok(())
    }

    fn decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        dst: &mut [u8],
        src: &[u8],
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), interface::TpmErr> {
        if src.len() != dst.len() || key.len() != self.block_alg.key_len() {
            return Err(tpm_err_internal!());
        }

        macro_rules! decryptor_new_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let iv_len = <mode_id_to_dec_impl!(
                    $mode_id,
                    block_alg_id_to_impl!($block_alg_id, $key_size)
                )>::iv_size();
                if iv.len() != iv_len {
                    return Err(tpm_err_rc!(NO_RESULT));
                } else if let Some(iv_out) = &iv_out {
                    if iv_out.len() != iv_len {
                        return Err(tpm_err_rc!(NO_RESULT));
                    }
                }
                <mode_id_to_dec_impl!(
                                            $mode_id,
                                            block_alg_id_to_impl!($block_alg_id, $key_size)
                                        )>::new(key.into(), iv.into())
            }};
        }

        macro_rules! decryptor_new_no_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                if iv.len() != 0 {
                    return Err(tpm_err_rc!(NO_RESULT));
                } else if let Some(iv_out) = iv_out {
                    if iv_out.len() != 0 {
                        return Err(tpm_err_rc!(NO_RESULT));
                    }
                }
                <mode_id_to_dec_impl!(
                                            $mode_id,
                                            block_alg_id_to_impl!($block_alg_id, $key_size)
                                        )>::new(key.into())
            }};
        }

        // Modes with IV implementing the cipher::BlockDecryptMut trait and only capable
        // of handling messages with length aligned to the block size.
        macro_rules! decrypt_aligned_with_block_decrypt_mode_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let block_len = <block_alg_id_to_impl!($block_alg_id, $key_size)>::block_size();
                if src.len() % block_len != 0 {
                    return Err(tpm_err_rc!(SIZE));
                }
                let mut dec = decryptor_new_iv!($mode_id, $block_alg_id, $key_size);
                let dst_chunks = dst.chunks_exact_mut(block_len);
                let src_chunks = src.chunks_exact(block_len);
                for (dst_chunk, src_chunk) in dst_chunks.zip(src_chunks) {
                    dec.decrypt_block_b2b_mut(src_chunk.into(), dst_chunk.into());
                }
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice(dec.iv_state().deref());
                }
            }};
        }

        // Modes without IV implementing the cipher::BlockDecryptMut trait and only
        // capable of handling messages with length aligned to the block size.
        macro_rules! decrypt_aligned_with_block_decrypt_mode_no_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let block_len = <block_alg_id_to_impl!($block_alg_id, $key_size)>::block_size();
                if src.len() % block_len != 0 {
                    return Err(tpm_err_rc!(SIZE));
                }
                let mut dec = decryptor_new_no_iv!($mode_id, $block_alg_id, $key_size);
                let dst_chunks = dst.chunks_exact_mut(block_len);
                let src_chunks = src.chunks_exact(block_len);
                for (dst_chunk, src_chunk) in dst_chunks.zip(src_chunks) {
                    dec.decrypt_block_b2b_mut(src_chunk.into(), dst_chunk.into());
                }
            }};
        }

        // Modes with IV implementing the cipher::BlockDecryptMut trait and capable of
        // handling messages with any length.
        macro_rules! decrypt_unaligned_with_block_decrypt_mode_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let block_len = <block_alg_id_to_impl!($block_alg_id, $key_size)>::block_size();
                let mut block_buf = if src.len() % block_len != 0 {
                    utils::try_alloc_zeroizing_vec::<u8>(block_len)?
                } else {
                    cfg_zeroize::Zeroizing::<Vec<u8>>::from(Vec::new())
                };
                let mut dec = decryptor_new_iv!($mode_id, $block_alg_id, $key_size);
                let mut dst_chunks = dst.chunks_exact_mut(block_len);
                let mut src_chunks = src.chunks_exact(block_len);
                for (dst_chunk, src_chunk) in (&mut dst_chunks).zip(&mut src_chunks) {
                    dec.decrypt_block_b2b_mut(src_chunk.into(), dst_chunk.into());
                }
                let dst_remainder = dst_chunks.into_remainder();
                let src_remainder = src_chunks.remainder();
                if !src_remainder.is_empty() {
                    let l = src_remainder.len();
                    block_buf[0..l].copy_from_slice(src_remainder);
                    dec.decrypt_block_mut(block_buf.as_mut_slice().into());
                    dst_remainder.copy_from_slice(&block_buf[0..l]);
                }
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice(dec.iv_state().deref());
                }
            }};
        }

        // Modes with IV implementing the cipher::StreamCipherCore trait.
        macro_rules! decrypt_unaligned_with_stream_cipher_core_mode_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let mut dec = decryptor_new_iv!($mode_id, $block_alg_id, $key_size);
                dec.apply_keystream_b2b(src, dst)
                    .map_err(|_| tpm_err_internal!())?;
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice(dec.get_core().iv_state().deref());
                }
            }};
        }

        macro_rules! decrypt_with_mode {
            (Ctr $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    decrypt_unaligned_with_block_decrypt_mode_iv,
                    Ctr
                )
            };
            (Ofb $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    decrypt_unaligned_with_stream_cipher_core_mode_iv,
                    Ofb
                )
            };
            (Cbc $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    decrypt_aligned_with_block_decrypt_mode_iv,
                    Cbc
                )
            };
            (Cfb $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    decrypt_unaligned_with_block_decrypt_mode_iv,
                    Cfb
                )
            };
            (Ecb $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    decrypt_aligned_with_block_decrypt_mode_no_iv,
                    Ecb
                )
            };
        }

        match_on_mode!(self.mode, decrypt_with_mode);

        Ok(())
    }

    fn decrypt_in_place(
        &self,
        key: &[u8],
        iv: &[u8],
        msg: &mut [u8],
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), interface::TpmErr> {
        if key.len() != self.block_alg.key_len() {
            return Err(tpm_err_internal!());
        }

        macro_rules! decryptor_new_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let iv_len = <mode_id_to_dec_impl!(
                    $mode_id,
                    block_alg_id_to_impl!($block_alg_id, $key_size)
                )>::iv_size();
                if iv.len() != iv_len {
                    return Err(tpm_err_rc!(NO_RESULT));
                } else if let Some(iv_out) = &iv_out {
                    if iv_out.len() != iv_len {
                        return Err(tpm_err_rc!(NO_RESULT));
                    }
                }
                <mode_id_to_dec_impl!(
                                            $mode_id,
                                            block_alg_id_to_impl!($block_alg_id, $key_size)
                                        )>::new(key.into(), iv.into())
            }};
        }

        macro_rules! decryptor_new_no_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                if iv.len() != 0 {
                    return Err(tpm_err_rc!(NO_RESULT));
                } else if let Some(iv_out) = iv_out {
                    if iv_out.len() != 0 {
                        return Err(tpm_err_rc!(NO_RESULT));
                    }
                }
                <mode_id_to_dec_impl!(
                                            $mode_id,
                                            block_alg_id_to_impl!($block_alg_id, $key_size)
                                        )>::new(key.into())
            }};
        }

        // Modes with IV implementing the cipher::BlockDecryptMut trait and only capable
        // of handling messages with length aligned to the block size.
        macro_rules! decrypt_aligned_with_block_decrypt_mode_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let block_len = <block_alg_id_to_impl!($block_alg_id, $key_size)>::block_size();
                if msg.len() % block_len != 0 {
                    return Err(tpm_err_rc!(SIZE));
                }
                let mut dec = decryptor_new_iv!($mode_id, $block_alg_id, $key_size);
                let msg_chunks = msg.chunks_exact_mut(block_len);
                for msg_chunk in msg_chunks {
                    dec.decrypt_block_mut(msg_chunk.into());
                }
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice(dec.iv_state().deref());
                }
            }};
        }

        // Modes without IV implementing the cipher::BlockDecryptMut trait and only
        // capable of handling messages with length aligned to the block size.
        macro_rules! decrypt_aligned_with_block_decrypt_mode_no_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let block_len = <block_alg_id_to_impl!($block_alg_id, $key_size)>::block_size();
                if msg.len() % block_len != 0 {
                    return Err(tpm_err_rc!(SIZE));
                }
                let mut dec = decryptor_new_no_iv!($mode_id, $block_alg_id, $key_size);
                let msg_chunks = msg.chunks_exact_mut(block_len);
                for msg_chunk in msg_chunks {
                    dec.decrypt_block_mut(msg_chunk.into());
                }
            }};
        }

        // Modes with IV implementing the cipher::BlockDecryptMut trait and capable of
        // handling messages with any length.
        macro_rules! decrypt_unaligned_with_block_decrypt_mode_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let block_len = <block_alg_id_to_impl!($block_alg_id, $key_size)>::block_size();
                let mut block_buf = if msg.len() % block_len != 0 {
                    utils::try_alloc_zeroizing_vec::<u8>(block_len)?
                } else {
                    cfg_zeroize::Zeroizing::<Vec<u8>>::from(Vec::new())
                };
                let mut dec = decryptor_new_iv!($mode_id, $block_alg_id, $key_size);
                let mut msg_chunks = msg.chunks_exact_mut(block_len);
                for msg_chunk in &mut msg_chunks {
                    dec.decrypt_block_mut(msg_chunk.into());
                }
                let msg_remainder = msg_chunks.into_remainder();
                if !msg_remainder.is_empty() {
                    let l = msg_remainder.len();
                    block_buf[0..l].copy_from_slice(msg_remainder);
                    dec.decrypt_block_mut(block_buf.as_mut_slice().into());
                    msg_remainder.copy_from_slice(&block_buf[0..l]);
                }
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice(dec.iv_state().deref());
                }
            }};
        }

        // Modes with IV implementing the cipher::StreamCipherCore trait.
        macro_rules! decrypt_unaligned_with_stream_cipher_core_mode_iv {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt) => {{
                let mut dec = decryptor_new_iv!($mode_id, $block_alg_id, $key_size);
                dec.apply_keystream(msg);
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice(dec.get_core().iv_state().deref());
                }
            }};
        }

        macro_rules! decrypt_with_mode {
            (Ctr $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    decrypt_unaligned_with_block_decrypt_mode_iv,
                    Ctr
                )
            };
            (Ofb $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    decrypt_unaligned_with_stream_cipher_core_mode_iv,
                    Ofb
                )
            };
            (Cbc $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    decrypt_aligned_with_block_decrypt_mode_iv,
                    Cbc
                )
            };
            (Cfb $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    decrypt_unaligned_with_block_decrypt_mode_iv,
                    Cfb
                )
            };
            (Ecb $(, $($args:tt),*)?) => {
                match_on_block_alg!(
                    &self.block_alg,
                    decrypt_aligned_with_block_decrypt_mode_no_iv,
                    Ecb
                )
            };
        }

        match_on_mode!(self.mode, decrypt_with_mode);

        Ok(())
    }
}

#[cfg(test)]
fn test_encrypt_decrypt(mode: interface::TpmiAlgCipherMode, block_alg: SymBlockCipherAlg) {
    use alloc::vec;

    let key_len = block_alg.key_len();
    let key = vec![0xffu8; key_len];
    let key = SymBlockCipherKey::try_from((block_alg, key.as_slice())).unwrap();

    let block_len = block_alg.block_len();
    let msg_align = block_alg.msg_len_alignment_for_mode(mode);
    assert!(msg_align & (msg_align - 1) == 0); // Is a power of two.
    let msg_len = 3 * block_len - 1;
    let msg_len = (msg_len + msg_align - 1) & !(msg_align - 1);
    let mut msg = vec![0u8; msg_len];
    for (i, b) in msg.iter_mut().enumerate() {
        *b = (i % u8::MAX as usize) as u8
    }

    let iv_len = block_alg.iv_len_for_mode(mode);
    let iv = vec![0xccu8; iv_len];
    // Encrypt in two steps for testing the intermediate IV extraction code.
    let mut iv_out = vec![0u8; iv_len];
    let mut encrypted = vec![0u8; msg_len];
    key.encrypt(
        mode,
        &iv,
        &mut encrypted[..block_len],
        &msg[..block_len],
        Some(&mut iv_out),
    )
    .unwrap();
    key.encrypt(
        mode,
        &iv_out,
        &mut encrypted[block_len..],
        &msg[block_len..],
        None,
    )
    .unwrap();
    assert_ne!(&msg, &encrypted);

    // Decrypt, also in two steps, and compare the result with the original message.
    let mut decrypted = vec![0u8; msg_len];
    key.decrypt(
        mode,
        &iv,
        &mut decrypted[..2 * block_len],
        &encrypted[..2 * block_len],
        Some(&mut iv_out),
    )
    .unwrap();
    key.decrypt(
        mode,
        &iv_out,
        &mut decrypted[2 * block_len..],
        &encrypted[2 * block_len..],
        None,
    )
    .unwrap();
    assert_eq!(&msg, &decrypted);
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ctr_aes128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ofb_aes128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cbc_aes128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cfb_aes128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ecb_aes128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ctr_aes192() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ofb_aes192() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cbc_aes192() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cfb_aes192() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ecb_aes192() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ctr_aes256() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ofb_aes256() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cbc_aes256() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cfb_aes256() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ecb_aes256() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ctr_camellia128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ofb_camellia128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cbc_camellia128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cfb_camellia128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ecb_camellia128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ctr_camellia192() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ofb_camellia192() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cbc_camellia192() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cfb_camellia192() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ecb_camellia192() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ctr_camellia256() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ofb_camellia256() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cbc_camellia256() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cfb_camellia256() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ecb_camellia256() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ctr", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_ctr_sm4_128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "ofb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_ofb_sm4_128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "cbc", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_cbc_sm4_128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "cfb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_cfb_sm4_128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "ecb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_ecb_sm4_128() {
    test_encrypt_decrypt(
        interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(test)]
fn test_encrypt_decrypt_in_place(mode: interface::TpmiAlgCipherMode, block_alg: SymBlockCipherAlg) {
    use alloc::vec;

    let key_len = block_alg.key_len();
    let key = vec![0xffu8; key_len];
    let key = SymBlockCipherKey::try_from((block_alg, key.as_slice())).unwrap();

    let block_len = block_alg.block_len();
    let msg_align = block_alg.msg_len_alignment_for_mode(mode);
    assert!(msg_align & (msg_align - 1) == 0); // Is a power of two.
    let msg_len = 3 * block_len - 1;
    let msg_len = (msg_len + msg_align - 1) & !(msg_align - 1);
    let mut msg = vec![0u8; msg_len];
    for (i, b) in msg.iter_mut().enumerate() {
        *b = (i % u8::MAX as usize) as u8
    }

    let iv_len = block_alg.iv_len_for_mode(mode);
    let iv = vec![0xccu8; iv_len];
    // Encrypt in two steps for testing the intermediate IV extraction code.
    let mut iv_out = vec![0u8; iv_len];
    let mut encrypted = vec![0u8; msg_len];
    encrypted.copy_from_slice(&msg);
    key.encrypt_in_place(mode, &iv, &mut encrypted[..block_len], Some(&mut iv_out))
        .unwrap();
    key.encrypt_in_place(mode, &iv_out, &mut encrypted[block_len..], None)
        .unwrap();
    assert_ne!(&msg, &encrypted);

    // Decrypt, also in two steps, and compare the result with the original message.
    let decrypted = &mut encrypted;
    key.decrypt_in_place(
        mode,
        &iv,
        &mut decrypted[..2 * block_len],
        Some(&mut iv_out),
    )
    .unwrap();
    key.decrypt_in_place(mode, &iv_out, &mut decrypted[2 * block_len..], None)
        .unwrap();
    assert_eq!(&msg, decrypted);
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_aes128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_aes128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_aes128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_aes128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_aes128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_aes192() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_aes192() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_aes192() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_aes192() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_aes192() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_aes256() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_aes256() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_aes256() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_aes256() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_aes256() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_camellia128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_camellia128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_camellia128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_camellia128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_camellia128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_camellia192() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_camellia192() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_camellia192() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_camellia192() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_camellia192() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_camellia256() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_camellia256() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_camellia256() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_camellia256() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_camellia256() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ctr", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_sm4_128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "ofb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_sm4_128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "cbc", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_sm4_128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "cfb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_sm4_128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "ecb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_sm4_128() {
    test_encrypt_decrypt_in_place(
        interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}
