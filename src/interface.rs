// TCG TPM2 Structures interface code
// Autogenerated with gen-tpm2-cmd-interface version 0.1.0

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::all)]

extern crate alloc;
use alloc::vec::Vec;
use alloc::boxed::Box;
use core::cmp;
use core::convert;
use core::default;
use core::mem;
use core::ops;
use core::ptr;
#[cfg(feature = "zeroize")]
use zeroize;

#[derive(Clone, Copy, Debug)]
pub enum TpmErr {
    Rc(u32),
    InternalErr,
}

#[derive(Clone, Debug)]
pub enum TpmBufferRef<'a> {
    Unstable(&'a [u8]),
    Stable(&'a [u8]),
}

impl<'a> TpmBufferRef<'a> {
    pub fn len(&self) -> usize {
        <Self as ops::Deref>::deref(self).len()
    }

    pub fn consume(self, mid: usize) -> (Self, Self) {
        match self {
            Self::Unstable(slice) => {
                let split = slice.split_at(mid);
                (Self::Unstable(split.0), Self::Unstable(split.1))
            },
            Self::Stable(slice) => {
                let split = slice.split_at(mid);
                (Self::Stable(split.0), Self::Stable(split.1))
            },
        }
    }
}

impl<'a> ops::Deref for TpmBufferRef<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Unstable(slice) | Self::Stable(slice) => slice,
        }
    }
}

impl<'a> convert::From<&'a TpmBuffer<'a>> for TpmBufferRef<'a> {
    fn from(value: &'a TpmBuffer<'a>) -> Self {
        match value {
            TpmBuffer::Borrowed(b) => b.clone(),
            TpmBuffer::Owned(o) => TpmBufferRef::Stable(o.as_ref()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum TpmBuffer<'a> {
    Borrowed(TpmBufferRef<'a>),
    #[cfg(not(feature = "zeroize"))]
    Owned(Vec<u8>),
    #[cfg(feature = "zeroize")]
    Owned(zeroize::Zeroizing<Vec<u8>>),
}

impl<'a> TpmBuffer<'a> {
    pub fn stabilize(&mut self) -> Result<(), TpmErr> {
        match self {
            Self::Borrowed(b) => {
                match b {
                    TpmBufferRef::Stable(_) => (),
                    TpmBufferRef::Unstable(u) => {
                        let mut o = Vec::new();
                        o.try_reserve_exact(u.len()).map_err(|_| TpmErr::Rc(TpmRc::MEMORY))?;
                        o.extend_from_slice(u);
                        #[cfg(feature = "zeroize")]
                        let o = zeroize::Zeroizing::from(o);
                        *self = Self::Owned(o);
                    },
                }
            },
            Self::Owned(_) => (),
        };
        Ok(())
    }

    pub fn into_owned(self) -> Result<TpmBuffer<'static>, TpmErr> {
        let o = match self {
            Self::Borrowed(b) => {
                let mut o = Vec::new();
                o.try_reserve_exact(b.len()).map_err(|_| TpmErr::Rc(TpmRc::MEMORY))?;
                o.extend_from_slice(&b);
                #[cfg(feature = "zeroize")]
                let o = zeroize::Zeroizing::from(o);
                o
            },
            Self::Owned(o) => o,
        };
        Ok(TpmBuffer::<'static>::Owned(o))
    }
}

impl<'a> ops::Deref for TpmBuffer<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(b) => b.deref(),
            Self::Owned(o) => &o,
        }
    }
}

impl<'a> convert::From<TpmBufferRef<'a>> for TpmBuffer<'a> {
    fn from(value: TpmBufferRef<'a>) -> Self {
        Self::Borrowed(value)
    }
}

impl<'a> default::Default for TpmBuffer<'a> {
    fn default() -> Self {
        let o = Vec::new();
        #[cfg(feature = "zeroize")]
        let o = zeroize::Zeroizing::from(o);
        Self::Owned(o)
    }
}

impl<'a> PartialEq for TpmBuffer<'a> {
    fn eq(&self, other: &Self) -> bool {
        if matches!(self, Self::Borrowed(TpmBufferRef::Unstable(_)))
           || matches!(other, Self::Borrowed(TpmBufferRef::Unstable(_)))
        {
            return false;
        }

        <Self as ops::Deref>::deref(self) == <Self as ops::Deref>::deref(other)
    }
}

fn unmarshal_u8<'a>(buf: TpmBufferRef<'a>) -> Result<(TpmBufferRef<'a>, u8), TpmErr> {
    if buf.len() < mem::size_of::<u8>() {
        return Err(TpmErr::Rc(TpmRc::INSUFFICIENT));
    }
    let (consumed, buf) = buf.consume(mem::size_of::<u8>());
    let consumed: [u8; mem::size_of::<u8>()] = (&consumed as &[u8]).try_into().unwrap();
    let value = u8::from_be_bytes(consumed);
    Ok((buf, value))
}

fn unmarshal_i8<'a>(buf: TpmBufferRef<'a>) -> Result<(TpmBufferRef<'a>, i8), TpmErr> {
    if buf.len() < mem::size_of::<i8>() {
        return Err(TpmErr::Rc(TpmRc::INSUFFICIENT));
    }
    let (consumed, buf) = buf.consume(mem::size_of::<i8>());
    let consumed: [u8; mem::size_of::<i8>()] = (&consumed as &[u8]).try_into().unwrap();
    let value = i8::from_be_bytes(consumed);
    Ok((buf, value))
}

fn unmarshal_u16<'a>(buf: TpmBufferRef<'a>) -> Result<(TpmBufferRef<'a>, u16), TpmErr> {
    if buf.len() < mem::size_of::<u16>() {
        return Err(TpmErr::Rc(TpmRc::INSUFFICIENT));
    }
    let (consumed, buf) = buf.consume(mem::size_of::<u16>());
    let consumed: [u8; mem::size_of::<u16>()] = (&consumed as &[u8]).try_into().unwrap();
    let value = u16::from_be_bytes(consumed);
    Ok((buf, value))
}

fn unmarshal_i16<'a>(buf: TpmBufferRef<'a>) -> Result<(TpmBufferRef<'a>, i16), TpmErr> {
    if buf.len() < mem::size_of::<i16>() {
        return Err(TpmErr::Rc(TpmRc::INSUFFICIENT));
    }
    let (consumed, buf) = buf.consume(mem::size_of::<i16>());
    let consumed: [u8; mem::size_of::<i16>()] = (&consumed as &[u8]).try_into().unwrap();
    let value = i16::from_be_bytes(consumed);
    Ok((buf, value))
}

fn unmarshal_u32<'a>(buf: TpmBufferRef<'a>) -> Result<(TpmBufferRef<'a>, u32), TpmErr> {
    if buf.len() < mem::size_of::<u32>() {
        return Err(TpmErr::Rc(TpmRc::INSUFFICIENT));
    }
    let (consumed, buf) = buf.consume(mem::size_of::<u32>());
    let consumed: [u8; mem::size_of::<u32>()] = (&consumed as &[u8]).try_into().unwrap();
    let value = u32::from_be_bytes(consumed);
    Ok((buf, value))
}

fn unmarshal_i32<'a>(buf: TpmBufferRef<'a>) -> Result<(TpmBufferRef<'a>, i32), TpmErr> {
    if buf.len() < mem::size_of::<i32>() {
        return Err(TpmErr::Rc(TpmRc::INSUFFICIENT));
    }
    let (consumed, buf) = buf.consume(mem::size_of::<i32>());
    let consumed: [u8; mem::size_of::<i32>()] = (&consumed as &[u8]).try_into().unwrap();
    let value = i32::from_be_bytes(consumed);
    Ok((buf, value))
}

fn unmarshal_u64<'a>(buf: TpmBufferRef<'a>) -> Result<(TpmBufferRef<'a>, u64), TpmErr> {
    if buf.len() < mem::size_of::<u64>() {
        return Err(TpmErr::Rc(TpmRc::INSUFFICIENT));
    }
    let (consumed, buf) = buf.consume(mem::size_of::<u64>());
    let consumed: [u8; mem::size_of::<u64>()] = (&consumed as &[u8]).try_into().unwrap();
    let value = u64::from_be_bytes(consumed);
    Ok((buf, value))
}

fn unmarshal_i64<'a>(buf: TpmBufferRef<'a>) -> Result<(TpmBufferRef<'a>, i64), TpmErr> {
    if buf.len() < mem::size_of::<i64>() {
        return Err(TpmErr::Rc(TpmRc::INSUFFICIENT));
    }
    let (consumed, buf) = buf.consume(mem::size_of::<i64>());
    let consumed: [u8; mem::size_of::<i64>()] = (&consumed as &[u8]).try_into().unwrap();
    let value = i64::from_be_bytes(consumed);
    Ok((buf, value))
}

fn marshal_u8<'a>(buf: &mut [u8], value: u8) -> &mut [u8] {
    let (produced, buf) = buf.split_at_mut(mem::size_of::<u8>());
    let marshalled = value.to_be_bytes();
    produced.copy_from_slice(&marshalled);
    buf
}

fn marshal_i8<'a>(buf: &mut [u8], value: i8) -> &mut [u8] {
    let (produced, buf) = buf.split_at_mut(mem::size_of::<i8>());
    let marshalled = value.to_be_bytes();
    produced.copy_from_slice(&marshalled);
    buf
}

fn marshal_u16<'a>(buf: &mut [u8], value: u16) -> &mut [u8] {
    let (produced, buf) = buf.split_at_mut(mem::size_of::<u16>());
    let marshalled = value.to_be_bytes();
    produced.copy_from_slice(&marshalled);
    buf
}

fn marshal_i16<'a>(buf: &mut [u8], value: i16) -> &mut [u8] {
    let (produced, buf) = buf.split_at_mut(mem::size_of::<i16>());
    let marshalled = value.to_be_bytes();
    produced.copy_from_slice(&marshalled);
    buf
}

fn marshal_u32<'a>(buf: &mut [u8], value: u32) -> &mut [u8] {
    let (produced, buf) = buf.split_at_mut(mem::size_of::<u32>());
    let marshalled = value.to_be_bytes();
    produced.copy_from_slice(&marshalled);
    buf
}

fn marshal_i32<'a>(buf: &mut [u8], value: i32) -> &mut [u8] {
    let (produced, buf) = buf.split_at_mut(mem::size_of::<i32>());
    let marshalled = value.to_be_bytes();
    produced.copy_from_slice(&marshalled);
    buf
}

fn marshal_u64<'a>(buf: &mut [u8], value: u64) -> &mut [u8] {
    let (produced, buf) = buf.split_at_mut(mem::size_of::<u64>());
    let marshalled = value.to_be_bytes();
    produced.copy_from_slice(&marshalled);
    buf
}

fn marshal_i64<'a>(buf: &mut [u8], value: i64) -> &mut [u8] {
    let (produced, buf) = buf.split_at_mut(mem::size_of::<i64>());
    let marshalled = value.to_be_bytes();
    produced.copy_from_slice(&marshalled);
    buf
}

// TCG Algorithm Registry, page 11, table 3, TPM_ALG_ID constants
#[cfg(any(feature = "aes", feature = "camellia", feature = "cbc", feature = "cfb", feature = "ctr", feature = "ecb", feature = "ofb", feature = "sha1", feature = "sha256", feature = "sha384", feature = "sha3_256", feature = "sha3_384", feature = "sha3_512", feature = "sha512", feature = "sm3_256", feature = "sm4", feature = "tdes"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
enum TpmAlgId {
    #[cfg(feature = "tdes")]
    Tdes = 0x3u16,
    #[cfg(feature = "sha1")]
    Sha1 = 0x4u16,
    #[cfg(feature = "aes")]
    Aes = 0x6u16,
    #[cfg(feature = "sha256")]
    Sha256 = 0xbu16,
    #[cfg(feature = "sha384")]
    Sha384 = 0xcu16,
    #[cfg(feature = "sha512")]
    Sha512 = 0xdu16,
    #[cfg(feature = "sm3_256")]
    Sm3_256 = 0x12u16,
    #[cfg(feature = "sm4")]
    Sm4 = 0x13u16,
    #[cfg(feature = "camellia")]
    Camellia = 0x26u16,
    #[cfg(feature = "sha3_256")]
    Sha3_256 = 0x27u16,
    #[cfg(feature = "sha3_384")]
    Sha3_384 = 0x28u16,
    #[cfg(feature = "sha3_512")]
    Sha3_512 = 0x29u16,
    #[cfg(feature = "ctr")]
    Ctr = 0x40u16,
    #[cfg(feature = "ofb")]
    Ofb = 0x41u16,
    #[cfg(feature = "cbc")]
    Cbc = 0x42u16,
    #[cfg(feature = "cfb")]
    Cfb = 0x43u16,
    #[cfg(feature = "ecb")]
    Ecb = 0x44u16,
}

// TCG Algorithm Registry, page 15, table 4, TPM_ECC_CURVE constants
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TpmEccCurve {
    None = 0x0u16,
    #[cfg(feature = "ecc_nist_p192")]
    NistP192 = 0x1u16,
    #[cfg(feature = "ecc_nist_p224")]
    NistP224 = 0x2u16,
    #[cfg(feature = "ecc_nist_p256")]
    NistP256 = 0x3u16,
    #[cfg(feature = "ecc_nist_p384")]
    NistP384 = 0x4u16,
    #[cfg(feature = "ecc_nist_p521")]
    NistP521 = 0x5u16,
    #[cfg(feature = "ecc_bn_p256")]
    BnP256 = 0x10u16,
    #[cfg(feature = "ecc_bn_p638")]
    BnP638 = 0x11u16,
    #[cfg(feature = "ecc_sm2_p256")]
    Sm2P256 = 0x20u16,
    #[cfg(feature = "ecc_bp_p256_r1")]
    BpP256R1 = 0x30u16,
    #[cfg(feature = "ecc_bp_p384_r1")]
    BpP384R1 = 0x31u16,
    #[cfg(feature = "ecc_bp_p512_r1")]
    BpP512R1 = 0x32u16,
    #[cfg(feature = "ecc_curve_25519")]
    Curve25519 = 0x40u16,
    #[cfg(feature = "ecc_curve_448")]
    Curve448 = 0x41u16,
}

impl convert::TryFrom<u16> for TpmEccCurve {
    type Error = TpmErr;

    fn try_from(value: u16) -> Result<Self, TpmErr> {
        let result = match value {
            value if value == Self::None as u16 => Self::None,
            #[cfg(feature = "ecc_nist_p192")]
            value if value == Self::NistP192 as u16 => Self::NistP192,
            #[cfg(feature = "ecc_nist_p224")]
            value if value == Self::NistP224 as u16 => Self::NistP224,
            #[cfg(feature = "ecc_nist_p256")]
            value if value == Self::NistP256 as u16 => Self::NistP256,
            #[cfg(feature = "ecc_nist_p384")]
            value if value == Self::NistP384 as u16 => Self::NistP384,
            #[cfg(feature = "ecc_nist_p521")]
            value if value == Self::NistP521 as u16 => Self::NistP521,
            #[cfg(feature = "ecc_bn_p256")]
            value if value == Self::BnP256 as u16 => Self::BnP256,
            #[cfg(feature = "ecc_bn_p638")]
            value if value == Self::BnP638 as u16 => Self::BnP638,
            #[cfg(feature = "ecc_sm2_p256")]
            value if value == Self::Sm2P256 as u16 => Self::Sm2P256,
            #[cfg(feature = "ecc_bp_p256_r1")]
            value if value == Self::BpP256R1 as u16 => Self::BpP256R1,
            #[cfg(feature = "ecc_bp_p384_r1")]
            value if value == Self::BpP384R1 as u16 => Self::BpP384R1,
            #[cfg(feature = "ecc_bp_p512_r1")]
            value if value == Self::BpP512R1 as u16 => Self::BpP512R1,
            #[cfg(feature = "ecc_curve_25519")]
            value if value == Self::Curve25519 as u16 => Self::Curve25519,
            #[cfg(feature = "ecc_curve_448")]
            value if value == Self::Curve448 as u16 => Self::Curve448,
            _ => {
                return Err(TpmErr::Rc(TpmRc::CURVE));
            },
        };

        Ok(result)
    }
}

// TCG TPM2 Library, Part 2 -- Structures, page 54, table 16, TPM_RC constants
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TpmRc {
}

impl TpmRc {
    pub const SUCCESS: u32 = 0x0u32;
    pub const BAD_TAG: u32 = 0x1eu32;
    pub const VER1: u32 = 0x100u32;
    pub const INITIALIZE: u32 = Self::VER1 + 0x0u32;
    pub const FAILURE: u32 = Self::VER1 + 0x1u32;
    pub const SEQUENCE: u32 = Self::VER1 + 0x3u32;
    pub const PRIVATE: u32 = Self::VER1 + 0xbu32;
    pub const HMAC: u32 = Self::VER1 + 0x19u32;
    pub const DISABLED: u32 = Self::VER1 + 0x20u32;
    pub const EXCLUSIVE: u32 = Self::VER1 + 0x21u32;
    pub const AUTH_TYPE: u32 = Self::VER1 + 0x24u32;
    pub const AUTH_MISSING: u32 = Self::VER1 + 0x25u32;
    pub const POLICY: u32 = Self::VER1 + 0x26u32;
    pub const PCR: u32 = Self::VER1 + 0x27u32;
    pub const PCR_CHANGED: u32 = Self::VER1 + 0x28u32;
    pub const UPGRADE: u32 = Self::VER1 + 0x2du32;
    pub const TOO_MANY_CONTEXTS: u32 = Self::VER1 + 0x2eu32;
    pub const AUTH_UNAVAILABLE: u32 = Self::VER1 + 0x2fu32;
    pub const REBOOT: u32 = Self::VER1 + 0x30u32;
    pub const UNBALANCED: u32 = Self::VER1 + 0x31u32;
    pub const COMMAND_SIZE: u32 = Self::VER1 + 0x42u32;
    pub const COMMAND_CODE: u32 = Self::VER1 + 0x43u32;
    pub const AUTHSIZE: u32 = Self::VER1 + 0x44u32;
    pub const AUTH_CONTEXT: u32 = Self::VER1 + 0x45u32;
    pub const NV_RANGE: u32 = Self::VER1 + 0x46u32;
    pub const NV_SIZE: u32 = Self::VER1 + 0x47u32;
    pub const NV_LOCKED: u32 = Self::VER1 + 0x48u32;
    pub const NV_AUTHORIZATION: u32 = Self::VER1 + 0x49u32;
    pub const NV_UNINITIALIZED: u32 = Self::VER1 + 0x4au32;
    pub const NV_SPACE: u32 = Self::VER1 + 0x4bu32;
    pub const NV_DEFINED: u32 = Self::VER1 + 0x4cu32;
    pub const BAD_CONTEXT: u32 = Self::VER1 + 0x50u32;
    pub const CPHASH: u32 = Self::VER1 + 0x51u32;
    pub const PARENT: u32 = Self::VER1 + 0x52u32;
    pub const NEEDS_TEST: u32 = Self::VER1 + 0x53u32;
    pub const NO_RESULT: u32 = Self::VER1 + 0x54u32;
    pub const SENSITIVE: u32 = Self::VER1 + 0x55u32;
    pub const MAX_FM0: u32 = Self::VER1 + 0x7fu32;
    pub const FMT1: u32 = 0x80u32;
    pub const ASYMMETRIC: u32 = Self::FMT1 + 0x1u32;
    pub const ATTRIBUTES: u32 = Self::FMT1 + 0x2u32;
    pub const HASH: u32 = Self::FMT1 + 0x3u32;
    pub const VALUE: u32 = Self::FMT1 + 0x4u32;
    pub const HIERARCHY: u32 = Self::FMT1 + 0x5u32;
    pub const KEY_SIZE: u32 = Self::FMT1 + 0x7u32;
    pub const MGF: u32 = Self::FMT1 + 0x8u32;
    pub const MODE: u32 = Self::FMT1 + 0x9u32;
    pub const TYPE: u32 = Self::FMT1 + 0xau32;
    pub const HANDLE: u32 = Self::FMT1 + 0xbu32;
    pub const KDF: u32 = Self::FMT1 + 0xcu32;
    pub const RANGE: u32 = Self::FMT1 + 0xdu32;
    pub const AUTH_FAIL: u32 = Self::FMT1 + 0xeu32;
    pub const NONCE: u32 = Self::FMT1 + 0xfu32;
    pub const PP: u32 = Self::FMT1 + 0x10u32;
    pub const SCHEME: u32 = Self::FMT1 + 0x12u32;
    pub const SIZE: u32 = Self::FMT1 + 0x15u32;
    pub const SYMMETRIC: u32 = Self::FMT1 + 0x16u32;
    pub const TAG: u32 = Self::FMT1 + 0x17u32;
    pub const SELECTOR: u32 = Self::FMT1 + 0x18u32;
    pub const INSUFFICIENT: u32 = Self::FMT1 + 0x1au32;
    pub const SIGNATURE: u32 = Self::FMT1 + 0x1bu32;
    pub const KEY: u32 = Self::FMT1 + 0x1cu32;
    pub const POLICY_FAIL: u32 = Self::FMT1 + 0x1du32;
    pub const INTEGRITY: u32 = Self::FMT1 + 0x1fu32;
    pub const TICKET: u32 = Self::FMT1 + 0x20u32;
    pub const RESERVED_BITS: u32 = Self::FMT1 + 0x21u32;
    pub const BAD_AUTH: u32 = Self::FMT1 + 0x22u32;
    pub const EXPIRED: u32 = Self::FMT1 + 0x23u32;
    pub const POLICY_CC: u32 = Self::FMT1 + 0x24u32;
    pub const BINDING: u32 = Self::FMT1 + 0x25u32;
    pub const CURVE: u32 = Self::FMT1 + 0x26u32;
    pub const ECC_POINT: u32 = Self::FMT1 + 0x27u32;
    pub const WARN: u32 = 0x900u32;
    pub const CONTEXT_GAP: u32 = Self::WARN + 0x1u32;
    pub const OBJECT_MEMORY: u32 = Self::WARN + 0x2u32;
    pub const SESSION_MEMORY: u32 = Self::WARN + 0x3u32;
    pub const MEMORY: u32 = Self::WARN + 0x4u32;
    pub const SESSION_HANDLES: u32 = Self::WARN + 0x5u32;
    pub const OBJECT_HANDLES: u32 = Self::WARN + 0x6u32;
    pub const LOCALITY: u32 = Self::WARN + 0x7u32;
    pub const YIELDED: u32 = Self::WARN + 0x8u32;
    pub const CANCELED: u32 = Self::WARN + 0x9u32;
    pub const TESTING: u32 = Self::WARN + 0xau32;
    pub const REFERENCE_H0: u32 = Self::WARN + 0x10u32;
    pub const REFERENCE_H1: u32 = Self::WARN + 0x11u32;
    pub const REFERENCE_H2: u32 = Self::WARN + 0x12u32;
    pub const REFERENCE_H3: u32 = Self::WARN + 0x13u32;
    pub const REFERENCE_H4: u32 = Self::WARN + 0x14u32;
    pub const REFERENCE_H5: u32 = Self::WARN + 0x15u32;
    pub const REFERENCE_H6: u32 = Self::WARN + 0x16u32;
    pub const REFERENCE_S0: u32 = Self::WARN + 0x18u32;
    pub const REFERENCE_S1: u32 = Self::WARN + 0x19u32;
    pub const REFERENCE_S2: u32 = Self::WARN + 0x1au32;
    pub const REFERENCE_S3: u32 = Self::WARN + 0x1bu32;
    pub const REFERENCE_S4: u32 = Self::WARN + 0x1cu32;
    pub const REFERENCE_S5: u32 = Self::WARN + 0x1du32;
    pub const REFERENCE_S6: u32 = Self::WARN + 0x1eu32;
    pub const NV_RATE: u32 = Self::WARN + 0x20u32;
    pub const LOCKOUT: u32 = Self::WARN + 0x21u32;
    pub const RETRY: u32 = Self::WARN + 0x22u32;
    pub const NV_UNAVAILABLE: u32 = Self::WARN + 0x23u32;
    pub const NOT_USED: u32 = Self::WARN + 0x7fu32;
    pub const RC_H: u32 = 0x0u32;
    pub const RC_P: u32 = 0x40u32;
    pub const RC_S: u32 = 0x800u32;
    pub const RC_1: u32 = 0x100u32;
    pub const RC_2: u32 = 0x200u32;
    pub const RC_3: u32 = 0x300u32;
    pub const RC_4: u32 = 0x400u32;
    pub const RC_5: u32 = 0x500u32;
    pub const RC_6: u32 = 0x600u32;
    pub const RC_7: u32 = 0x700u32;
    pub const RC_8: u32 = 0x800u32;
    pub const RC_9: u32 = 0x900u32;
    pub const RC_A: u32 = 0xa00u32;
    pub const RC_B: u32 = 0xb00u32;
    pub const RC_C: u32 = 0xc00u32;
    pub const RC_D: u32 = 0xd00u32;
    pub const RC_E: u32 = 0xe00u32;
    pub const RC_F: u32 = 0xf00u32;
    pub const N_MASK: u32 = 0xf00u32;
}

// TCG TPM2 Library, Part 2 -- Structures, page 73, table 27, TPM_HT constants
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TpmHt {
}

impl TpmHt {
    pub const PCR: u8 = 0x0u8;
    pub const NV_INDEX: u8 = 0x1u8;
    pub const HMAC_SESSION: u8 = 0x2u8;
    pub const LOADED_SESSION: u8 = 0x2u8;
    pub const POLICY_SESSION: u8 = 0x3u8;
    pub const SAVED_SESSION: u8 = 0x3u8;
    pub const PERMANENT: u8 = 0x40u8;
    pub const TRANSIENT: u8 = 0x80u8;
    pub const PERSISTENT: u8 = 0x81u8;
    pub const AC: u8 = 0x90u8;
}

// TCG TPM2 Library, Part 2 -- Structures, page 107, table 65, TPMI_ALG_HASH type (without conditional values)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TpmiAlgHash {
    #[cfg(feature = "sha1")]
    Sha1 = TpmAlgId::Sha1 as u16,
    #[cfg(feature = "sha256")]
    Sha256 = TpmAlgId::Sha256 as u16,
    #[cfg(feature = "sha384")]
    Sha384 = TpmAlgId::Sha384 as u16,
    #[cfg(feature = "sha512")]
    Sha512 = TpmAlgId::Sha512 as u16,
    #[cfg(feature = "sm3_256")]
    Sm3_256 = TpmAlgId::Sm3_256 as u16,
    #[cfg(feature = "sha3_256")]
    Sha3_256 = TpmAlgId::Sha3_256 as u16,
    #[cfg(feature = "sha3_384")]
    Sha3_384 = TpmAlgId::Sha3_384 as u16,
    #[cfg(feature = "sha3_512")]
    Sha3_512 = TpmAlgId::Sha3_512 as u16,
}

impl convert::TryFrom<u16> for TpmiAlgHash {
    type Error = TpmErr;

    fn try_from(value: u16) -> Result<Self, TpmErr> {
        let result = match value {
            #[cfg(feature = "sha1")]
            value if value == Self::Sha1 as u16 => Self::Sha1,
            #[cfg(feature = "sha256")]
            value if value == Self::Sha256 as u16 => Self::Sha256,
            #[cfg(feature = "sha384")]
            value if value == Self::Sha384 as u16 => Self::Sha384,
            #[cfg(feature = "sha512")]
            value if value == Self::Sha512 as u16 => Self::Sha512,
            #[cfg(feature = "sm3_256")]
            value if value == Self::Sm3_256 as u16 => Self::Sm3_256,
            #[cfg(feature = "sha3_256")]
            value if value == Self::Sha3_256 as u16 => Self::Sha3_256,
            #[cfg(feature = "sha3_384")]
            value if value == Self::Sha3_384 as u16 => Self::Sha3_384,
            #[cfg(feature = "sha3_512")]
            value if value == Self::Sha3_512 as u16 => Self::Sha3_512,
            _ => {
                return Err(TpmErr::Rc(TpmRc::HASH));
            },
        };

        Ok(result)
    }
}

// TCG TPM2 Library, Part 2 -- Structures, page 108, table 68, TPMI_ALG_SYM_OBJECT type (without conditional values)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TpmiAlgSymObject {
    #[cfg(feature = "tdes")]
    Tdes = TpmAlgId::Tdes as u16,
    #[cfg(feature = "aes")]
    Aes = TpmAlgId::Aes as u16,
    #[cfg(feature = "sm4")]
    Sm4 = TpmAlgId::Sm4 as u16,
    #[cfg(feature = "camellia")]
    Camellia = TpmAlgId::Camellia as u16,
}

impl convert::TryFrom<u16> for TpmiAlgSymObject {
    type Error = TpmErr;

    fn try_from(value: u16) -> Result<Self, TpmErr> {
        let result = match value {
            #[cfg(feature = "tdes")]
            value if value == Self::Tdes as u16 => Self::Tdes,
            #[cfg(feature = "aes")]
            value if value == Self::Aes as u16 => Self::Aes,
            #[cfg(feature = "sm4")]
            value if value == Self::Sm4 as u16 => Self::Sm4,
            #[cfg(feature = "camellia")]
            value if value == Self::Camellia as u16 => Self::Camellia,
            _ => {
                return Err(TpmErr::Rc(TpmRc::SYMMETRIC));
            },
        };

        Ok(result)
    }
}

// TCG TPM2 Library, Part 2 -- Structures, page 110, table 75, TPMI_ALG_CIPHER_MODE type (without conditional values)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TpmiAlgCipherMode {
    #[cfg(feature = "ctr")]
    Ctr = TpmAlgId::Ctr as u16,
    #[cfg(feature = "ofb")]
    Ofb = TpmAlgId::Ofb as u16,
    #[cfg(feature = "cbc")]
    Cbc = TpmAlgId::Cbc as u16,
    #[cfg(feature = "cfb")]
    Cfb = TpmAlgId::Cfb as u16,
    #[cfg(feature = "ecb")]
    Ecb = TpmAlgId::Ecb as u16,
}

impl convert::TryFrom<u16> for TpmiAlgCipherMode {
    type Error = TpmErr;

    fn try_from(value: u16) -> Result<Self, TpmErr> {
        let result = match value {
            #[cfg(feature = "ctr")]
            value if value == Self::Ctr as u16 => Self::Ctr,
            #[cfg(feature = "ofb")]
            value if value == Self::Ofb as u16 => Self::Ofb,
            #[cfg(feature = "cbc")]
            value if value == Self::Cbc as u16 => Self::Cbc,
            #[cfg(feature = "cfb")]
            value if value == Self::Cfb as u16 => Self::Cfb,
            #[cfg(feature = "ecb")]
            value if value == Self::Ecb as u16 => Self::Ecb,
            _ => {
                return Err(TpmErr::Rc(TpmRc::MODE));
            },
        };

        Ok(result)
    }
}

// TCG TPM2 Library, Part 2 -- Structures, page 112, table 79, TPMT_HA structure (without conditional values)
#[derive(Debug, PartialEq)]
#[repr(C, u16)]
pub enum TpmtHa<'a> {
    #[cfg(feature = "sha1")]
    Sha1(TpmBuffer<'a>) = TpmAlgId::Sha1 as u16,
    #[cfg(feature = "sha256")]
    Sha256(TpmBuffer<'a>) = TpmAlgId::Sha256 as u16,
    #[cfg(feature = "sha384")]
    Sha384(TpmBuffer<'a>) = TpmAlgId::Sha384 as u16,
    #[cfg(feature = "sha512")]
    Sha512(TpmBuffer<'a>) = TpmAlgId::Sha512 as u16,
    #[cfg(feature = "sm3_256")]
    Sm3_256(TpmBuffer<'a>) = TpmAlgId::Sm3_256 as u16,
    #[cfg(feature = "sha3_256")]
    Sha3_256(TpmBuffer<'a>) = TpmAlgId::Sha3_256 as u16,
    #[cfg(feature = "sha3_384")]
    Sha3_384(TpmBuffer<'a>) = TpmAlgId::Sha3_384 as u16,
    #[cfg(feature = "sha3_512")]
    Sha3_512(TpmBuffer<'a>) = TpmAlgId::Sha3_512 as u16,
}

// TCG TPM2 Library, Part 2 -- Structures, page 149, table 174, TPM2B_PUBLIC_KEY_RSA structure
#[cfg(feature = "rsa")]
#[derive(Debug, PartialEq)]
pub struct Tpm2bPublicKeyRsa<'a> {
    pub buffer: TpmBuffer<'a>,
}

// TCG TPM2 Library, Part 2 -- Structures, page 149, table 176, TPM2B_PRIVATE_KEY_RSA structure
#[cfg(feature = "rsa")]
#[derive(Debug, PartialEq)]
pub struct Tpm2bPrivateKeyRsa<'a> {
    pub buffer: TpmBuffer<'a>,
}

// TCG TPM2 Library, Part 2 -- Structures, page 150, table 177, TPM2B_ECC_PARAMETER structure
#[derive(Debug, PartialEq)]
pub struct Tpm2bEccParameter<'a> {
    pub buffer: TpmBuffer<'a>,
}

impl<'a> Tpm2bEccParameter<'a> {
    pub fn stabilize(&mut self) -> Result<(), TpmErr> {
        self.buffer.stabilize()?;
        Ok(())
    }
}

// TCG TPM2 Library, Part 2 -- Structures, page 150, table 178, TPMS_ECC_POINT structure
#[cfg(feature = "ecc")]
#[derive(Debug, PartialEq)]
pub struct TpmsEccPoint<'a> {
    pub x: Tpm2bEccParameter<'a>,
    pub y: Tpm2bEccParameter<'a>,
}

#[cfg(feature = "ecc")]
impl<'a> TpmsEccPoint<'a> {
    pub fn stabilize(&mut self) -> Result<(), TpmErr> {
        self.x.stabilize()?;
        self.y.stabilize()?;
        Ok(())
    }
}
