#![macro_use]

#[allow(unused)]
macro_rules! tpm_err_rc {
    ($rc:ident) => {
        crate::interface::TpmErr::Rc(crate::interface::TpmRc::$rc)
    };
}

#[allow(unused)]
macro_rules! tpm_err_internal {
    () => {
        crate::interface::TpmErr::InternalErr{}
    };
}
