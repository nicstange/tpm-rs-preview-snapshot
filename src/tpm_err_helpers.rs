// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

#![macro_use]

#[allow(unused)]
macro_rules! tpm_rc {
    ($rc:ident) => {
        crate::interface::TpmRc::$rc
    };
}

#[allow(unused)]
macro_rules! tpm_err_rc {
    ($rc:ident) => {
        crate::interface::TpmErr::Rc(tpm_rc!($rc))
    };
}

#[allow(unused)]
macro_rules! tpm_err_internal {
    () => {
        crate::interface::TpmErr::InternalErr{}
    };
}
