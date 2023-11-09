use crate::interface;
use core::convert;

#[derive(Clone, Copy, Debug)]
pub enum NVError {
    TpmErr(interface::TpmErr),
    OperationNotSupported,
    IOBlockOutOfRange,
    IOBlockNotMapped,
    InvalidLayout,
    InvalidAuthTreeConfig,
    InvalidAuthTreeDimensions,
    UnalignedAuthTreeExtents,
    InvalidDigest,
    AuthenticationFailure,
}

impl convert::From<interface::TpmErr> for NVError {
    fn from(value: interface::TpmErr) -> Self {
        Self::TpmErr(value)
    }
}
