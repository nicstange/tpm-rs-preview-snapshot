#![no_std]
#![cfg_attr(feature = "use_allocator_api", feature(allocator_api))]

// Must come first, so that the helper macros are visible for the rest.
mod tpm_err_helpers;

mod interface;
mod sync_types;
