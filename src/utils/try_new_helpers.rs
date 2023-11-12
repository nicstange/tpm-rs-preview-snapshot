// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use alloc::{sync::Arc, vec::Vec, boxed::Box};

use super::cfg_zeroize;
use crate::interface;

#[cfg(feature = "use_allocator_api")]
#[inline(always)]
pub fn arc_try_new<T>(v: T) -> Result<Arc<T>, interface::TpmErr> {
    Arc::try_new(v).map_err(|_| tpm_err_rc!(MEMORY))?
}

#[cfg(not(feature = "use_allocator_api"))]
#[inline(always)]
pub fn arc_try_new<T>(v: T) -> Result<Arc<T>, interface::TpmErr> {
    Ok(Arc::new(v))
}

#[cfg(feature = "use_allocator_api")]
#[inline(always)]
pub fn box_try_new<T>(v: T) -> Result<Box<T>, interface::TpmErr> {
    Box::try_new(v).map_err(|_| tpm_err_rc!(MEMORY))?
}

#[cfg(not(feature = "use_allocator_api"))]
#[inline(always)]
pub fn box_try_new<T>(v: T) -> Result<Box<T>, interface::TpmErr> {
    Ok(Box::new(v))
}

pub fn try_alloc_zeroizing_vec<T: cfg_zeroize::Zeroize + Default + Clone>(
    len: usize,
) -> Result<cfg_zeroize::Zeroizing<Vec<T>>, interface::TpmErr> {
    let mut v = Vec::new();
    v.try_reserve_exact(len).map_err(|_| tpm_err_rc!(MEMORY))?;
    v.resize(len, T::default());
    Ok(v.into())
}

pub fn try_alloc_vec<T: Default + Clone>(len: usize) -> Result<Vec<T>, interface::TpmErr> {
    let mut v = Vec::new();
    v.try_reserve_exact(len).map_err(|_| tpm_err_rc!(MEMORY))?;
    v.resize(len, T::default());
    Ok(v)
}
