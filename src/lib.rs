#![no_std]
#![cfg_attr(feature = "use_allocator_api", feature(allocator_api))]

// Must come first, so that the helper macros are visible for the rest.
mod tpm_err_helpers;

mod index_permutation;
mod interface;
mod leases;
mod sync_types;
mod utils;
