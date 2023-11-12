// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

#![no_std]
#![cfg_attr(feature = "use_allocator_api", feature(allocator_api))]

// Must come first, so that the helper macros are visible for the rest.
mod tpm_err_helpers;

mod crypto;
mod index_permutation;
mod interface;
mod leases;
mod nv;
mod session;
mod sessions;
mod sync_types;
mod utils;
