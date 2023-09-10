extern crate alloc;
use crate::crypto::{io_slices, rng, xor};
use crate::interface;
use crate::utils::{self, cfg_zeroize};
use alloc::vec::Vec;
use cfg_zeroize::Zeroize as _;

#[cfg(feature = "mgf1")]
pub mod mgf1;
pub mod tcg_tpm2_kdf_a;
#[cfg(feature = "ecdh")]
pub mod tcg_tpm2_kdf_e;

pub trait Kdf {
    fn max_output_len(&self) -> Option<usize>;

    fn generate(self, output: &mut io_slices::IoSlicesMut) -> Result<(), interface::TpmErr>;

    fn generate_and_xor(self, output: &mut io_slices::IoSlicesMut)
        -> Result<(), interface::TpmErr>;
}

pub trait VariableChunkOutputKdf {
    fn max_remaining_len(&self) -> Option<usize>;

    fn generate_chunk(
        &mut self,
        output: &mut io_slices::IoSlicesMut,
    ) -> Result<(), interface::TpmErr>;

    fn generate_and_xor_chunk(
        &mut self,
        output: &mut io_slices::IoSlicesMut,
    ) -> Result<(), interface::TpmErr>;
}

impl<VK: VariableChunkOutputKdf> Kdf for VK {
    fn max_output_len(&self) -> Option<usize> {
        self.max_remaining_len()
    }

    fn generate(mut self, output: &mut io_slices::IoSlicesMut) -> Result<(), interface::TpmErr> {
        self.generate_chunk(output)
    }

    fn generate_and_xor(
        mut self,
        output: &mut io_slices::IoSlicesMut,
    ) -> Result<(), interface::TpmErr> {
        self.generate_and_xor_chunk(output)
    }
}

pub trait FixedBlockOutputKdf: Sized {
    fn block_len(&self) -> usize;

    fn max_remaining_len(&self) -> Option<usize>;

    fn generate_block(&mut self, output: &mut [u8]) -> Result<usize, interface::TpmErr>;

    fn generate_chunk_impl(
        &mut self,
        output: &mut io_slices::IoSlicesMut,
        block_buf: &mut [u8],
        mut block_buf_remaining_len: usize,
    ) -> Result<usize, interface::TpmErr> {
        if let Some(max_remaining_len) = self.max_remaining_len() {
            if output.len() > max_remaining_len + block_buf_remaining_len {
                return Err(interface::TpmErr::InternalErr);
            }
        }

        let block_len = self.block_len();
        while !output.is_empty() {
            let output0 = output.first().unwrap();
            let output0_len = output0.len();
            if block_buf_remaining_len != 0 {
                let output0_len = output0_len.min(block_buf_remaining_len);
                let block_buf_src_begin = block_len - block_buf_remaining_len;
                let block_buf_src_end = block_buf_src_begin + output0_len;
                let block_buf_src = &block_buf[block_buf_src_begin..block_buf_src_end];
                output0[..output0_len].copy_from_slice(block_buf_src);
                block_buf_remaining_len -= output0_len;
                output.advance(output0_len);
            } else if output0_len >= block_len {
                let cur_block_len = self.generate_block(&mut output0[..block_len])?;
                debug_assert_eq!(cur_block_len, block_len);
                output.advance(cur_block_len);
            } else {
                debug_assert_eq!(block_buf.len(), block_len);
                let cur_block_len = self.generate_block(block_buf)?;
                debug_assert!(cur_block_len == block_len || cur_block_len >= output.len());
                if cur_block_len != block_len {
                    // The buffered output will get consumed from the tail of the block_buf[]. Move
                    // the result from generate_block() there.
                    block_buf.copy_within(..cur_block_len, block_len - cur_block_len);
                }
                block_buf_remaining_len = cur_block_len;
            }
        }

        // Wipe out the bytes consumed from the block_buf[]. Note that callers are
        // allowed to pass an empty block_buf[] in case they can guarantee for the
        // given configuration of output slices that it wouldn't get used
        // anyway.
        if !block_buf.is_empty() {
            block_buf[..block_len - block_buf_remaining_len].zeroize();
        }

        Ok(block_buf_remaining_len)
    }

    fn generate_and_xor_chunk_impl(
        &mut self,
        output: &mut io_slices::IoSlicesMut,
        block_buf: &mut [u8],
        mut block_buf_remaining_len: usize,
    ) -> Result<usize, interface::TpmErr> {
        if let Some(max_remaining_len) = self.max_remaining_len() {
            if output.len() > max_remaining_len + block_buf_remaining_len {
                return Err(interface::TpmErr::InternalErr);
            }
        }

        let block_len = self.block_len();
        while !output.is_empty() {
            let output0 = output.first().unwrap();
            let output0_len = output0.len();
            if block_buf_remaining_len != 0 {
                let output0_len = output0_len.min(block_buf_remaining_len);
                let block_buf_src_begin = block_len - block_buf_remaining_len;
                let block_buf_src_end = block_buf_src_begin + output0_len;
                let block_buf_src = &block_buf[block_buf_src_begin..block_buf_src_end];
                xor::xor_bytes(&mut output0[..output0_len], block_buf_src);
                block_buf_remaining_len -= output0_len;
                output.advance(output0_len);
            } else {
                debug_assert_eq!(block_buf.len(), block_len);
                let cur_block_len = self.generate_block(block_buf)?;
                debug_assert!(cur_block_len == block_len || cur_block_len >= output.len());
                if cur_block_len != block_len {
                    // The buffered output will get consumed from the tail of the block_buf[]. Move
                    // the result from generate_block() there.
                    block_buf.copy_within(..cur_block_len, block_len - cur_block_len);
                }
                block_buf_remaining_len = cur_block_len;
            }
        }

        // Wipe out the bytes consumed from the block_buf[].
        block_buf[..block_len - block_buf_remaining_len].zeroize();

        Ok(block_buf_remaining_len)
    }
}

pub struct BufferedFixedBlockOutputKdf<BK: FixedBlockOutputKdf> {
    block_kdf: BK,
    block_buf: cfg_zeroize::Zeroizing<Vec<u8>>,
    block_buf_remaining_len: usize,
}

impl<BK: FixedBlockOutputKdf> BufferedFixedBlockOutputKdf<BK> {
    pub fn new(block_kdf: BK) -> Result<Self, interface::TpmErr> {
        let block_len = block_kdf.block_len();
        let block_buf = utils::try_alloc_zeroizing_vec::<u8>(block_len)?;
        Ok(Self {
            block_kdf,
            block_buf,
            block_buf_remaining_len: 0,
        })
    }
}

impl<BK: FixedBlockOutputKdf> VariableChunkOutputKdf for BufferedFixedBlockOutputKdf<BK> {
    fn max_remaining_len(&self) -> Option<usize> {
        self.block_kdf
            .max_remaining_len()
            .map(|max_remaining: usize| max_remaining + self.block_buf_remaining_len)
    }

    fn generate_chunk(
        &mut self,
        output: &mut io_slices::IoSlicesMut,
    ) -> Result<(), interface::TpmErr> {
        self.block_buf_remaining_len = self.block_kdf.generate_chunk_impl(
            output,
            self.block_buf.as_mut_slice(),
            self.block_buf_remaining_len,
        )?;
        Ok(())
    }

    fn generate_and_xor_chunk(
        &mut self,
        output: &mut io_slices::IoSlicesMut,
    ) -> Result<(), interface::TpmErr> {
        self.block_buf_remaining_len = self.block_kdf.generate_and_xor_chunk_impl(
            output,
            self.block_buf.as_mut_slice(),
            self.block_buf_remaining_len,
        )?;
        Ok(())
    }
}

// For code-uniformity of e.g. key derivation + generation primitives,
// provide a trivial RngCore implementation for VariableChunkOutputKdf.
impl<VK: VariableChunkOutputKdf> rng::RngCore for VK {
    fn generate(
        &mut self,
        output: &mut io_slices::IoSlicesMut,
        _additional_input: Option<&io_slices::IoSlices>,
    ) -> Result<(), rng::RngGenerateError> {
        self.generate_chunk(output)
            .map_err(rng::RngGenerateError::TpmErr)
    }
}
