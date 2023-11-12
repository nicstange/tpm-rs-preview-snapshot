// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use crate::crypto::io_slices;
use crate::interface;
use crate::utils;
use core::convert;

pub mod chained;
pub mod hash_drbg;
#[cfg(all(feature = "enable_x86_64_rdseed", target_arch = "x86_64"))]
pub mod x86_64_rdseed;

#[derive(Debug)]
pub enum RngGenerateError {
    ReseedRequired,
    TpmErr(interface::TpmErr),
}

impl convert::From<RngGenerateError> for interface::TpmErr {
    fn from(value: RngGenerateError) -> Self {
        match value {
            RngGenerateError::ReseedRequired => tpm_err_rc!(FAILURE),
            RngGenerateError::TpmErr(e) => e,
        }
    }
}

pub trait RngCore {
    fn generate(
        &mut self,
        output: &mut io_slices::IoSlicesMut,
        additional_input: Option<&io_slices::IoSlices>,
    ) -> Result<(), RngGenerateError>;
}

#[derive(Debug)]
pub enum RngReseedError {
    TpmErr(interface::TpmErr),
}

#[derive(Debug)]
pub enum RngReseedFromParentError {
    ParentGenerateFailure(RngGenerateError),
    TpmErr(interface::TpmErr),
}

pub trait ReseedableRngCore: RngCore + Sized {
    fn min_seed_entropy_len(&self) -> usize;

    fn reseed(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&io_slices::IoSlices>,
    ) -> Result<(), RngReseedError>;

    fn reseed_from_parent<P: RngCore>(
        &mut self,
        parent: &mut P,
        additional_input: Option<&io_slices::IoSlices>,
    ) -> Result<(), RngReseedFromParentError> {
        let entropy_len = self.min_seed_entropy_len();
        let mut entropy = utils::try_alloc_zeroizing_vec::<u8>(entropy_len)
            .map_err(RngReseedFromParentError::TpmErr)?;
        parent
            .generate(
                &mut io_slices::IoSlicesMut::new([Some(entropy.as_mut_slice())].as_mut_slice()),
                None,
            )
            .map_err(RngReseedFromParentError::ParentGenerateFailure)?;

        self.reseed(entropy.as_slice(), additional_input)
            .map_err(|e| match e {
                RngReseedError::TpmErr(e) => RngReseedFromParentError::TpmErr(e),
            })?;

        Ok(())
    }
}

#[cfg(test)]
pub fn test_rng() -> hash_drbg::HashDrbg {
    extern crate alloc;
    use alloc::vec;
    use super::hash;

    let hash_alg = hash::test_hash_alg();
    let min_entropy_len = hash_drbg::HashDrbg::min_seed_entropy_len(hash_alg);
    let entropy = vec![0u8; min_entropy_len];
    hash_drbg::HashDrbg::instantiate(hash_alg, &entropy, None, None).unwrap()
}
