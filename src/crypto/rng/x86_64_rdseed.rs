// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

#![cfg(all(feature = "enable_x86_64_rdseed", target_arch = "x86_64"))]

use super::{RngCore, RngGenerateError};
use crate::crypto::io_slices;
use crate::crypto::zeroize::Zeroize as _;
use crate::interface;
use core::arch::asm;
use core::mem;

#[derive(Debug)]
enum RdSeedError {
    MaxRetriesExhausted,
}

const MAX_RDSEED_RETRIES: u8 = 5;

#[inline(never)]
fn rdseed() -> Result<u64, RdSeedError> {
    let mut retries = 0;
    let result = loop {
        let result: u64;
        let success: u8;
        unsafe {
            asm!(
                "rdseed {result:r};\n\
                 setc {success};\n\
                 ",
                result = out(reg) result,
                success = out(reg_byte) success,
            );
        }

        if success != 1 {
            retries += 1;
            if retries >= MAX_RDSEED_RETRIES {
                return Err(RdSeedError::MaxRetriesExhausted);
            }
            continue;
        }
        break result;
    };
    Ok(result)
}

fn cpuid(mut eax: u32, mut ecx: u32) -> (u32, u32, u32, u32) {
    let rbx: u64;
    let edx: u32;

    unsafe {
        // rustc complains that LLVM uses "%bx" internally,
        // so it cannot be specified directly.
        asm!("mov {rbx:r}, rbx;\n\
              cpuid;\n\
              xchg {rbx:r}, rbx;\n\
              ",
             inout("ax") eax,
             rbx = out(reg) rbx,
             inout("cx") ecx,
             out("dx") edx
        );
    }
    (eax, rbx as u32, ecx, edx)
}

fn cpuid_max_function() -> u32 {
    let (eax, _, _, _) = cpuid(0x0000_0000u32, 0);
    eax
}

fn cpu_has_rdseed() -> bool {
    if cpuid_max_function() < 0x0000_0007u32 {
        return false;
    }

    let (_, ebx, _, _) = cpuid(0x0000_0007u32, 0);
    ebx & (1u32 << 18) != 0
}

#[derive(Debug)]
pub enum X86RdSeedRngInstantiateError {
    RdSeedInsnUnsupported,
}

pub struct X86RdSeedRng {}

impl X86RdSeedRng {
    pub fn instantiate() -> Result<Self, X86RdSeedRngInstantiateError> {
        if !cpu_has_rdseed() {
            return Err(X86RdSeedRngInstantiateError::RdSeedInsnUnsupported);
        }
        Ok(Self {})
    }
}

impl RngCore for X86RdSeedRng {
    fn generate(
        &mut self,
        output: &mut io_slices::IoSlicesMut,
        _additional_input: Option<&io_slices::IoSlices>,
    ) -> Result<(), RngGenerateError> {
        let mut rdseed_output_buf: [u8; mem::size_of::<u64>()] = [0u8; mem::size_of::<u64>()];
        while !output.is_empty() {
            let r = match rdseed() {
                Ok(r) => r,
                Err(RdSeedError::MaxRetriesExhausted) => {
                    rdseed_output_buf.zeroize();
                    return Err(RngGenerateError::TpmErr(tpm_err_rc!(FAILURE)));
                }
            };
            rdseed_output_buf = r.to_ne_bytes();
            let output0 = output.first().unwrap();
            let output0_len = output0.len().min(rdseed_output_buf.len());
            output0[..output0_len].copy_from_slice(&rdseed_output_buf[..output0_len]);
            output.advance(output0_len);
        }
        rdseed_output_buf.zeroize();
        Ok(())
    }
}
