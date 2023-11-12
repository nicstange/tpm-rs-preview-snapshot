// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use crate::crypto::kdf::{self, FixedBlockOutputKdf as _};
use crate::crypto::{hash, io_slices};
use crate::interface;
use crate::utils;
#[cfg(test)]
use cmpa;

// KDFe() as specified in TCG TPM2 Library specification, Part 1
// ("Architecture"), section 11.4.10.3 ("KDFe for ECDH")
pub struct TcgTpm2KdfE<'a> {
    hash_instance: Option<hash::HashInstance>,
    block_len: usize,
    usage: &'a str,
    z: &'a [u8],
    party_u_info: &'a [u8],
    party_v_info: &'a [u8],
    n_total_output_bits: u32,
    n_blocks_generated: u32,
}

impl<'a> TcgTpm2KdfE<'a> {
    pub fn new(
        hash_alg: interface::TpmiAlgHash,
        z: &'a [u8],
        usage: &'a str,
        party_u_info: &'a [u8],
        party_v_info: &'a [u8],
        n_total_output_bits: u32,
    ) -> Result<Self, interface::TpmErr> {
        if usize::try_from(n_total_output_bits).is_err() {
            return Err(tpm_err_internal!());
        }

        let (hash_instance, block_len) = if n_total_output_bits != 0 {
            let hash_instance = hash::HashInstance::new(hash_alg);
            let block_len = hash_instance.digest_len();
            (Some(hash_instance), block_len)
        } else {
            (None, hash::hash_alg_digest_len(hash_alg) as usize)
        };

        Ok(Self {
            hash_instance,
            block_len,
            usage,
            z,
            party_u_info,
            party_v_info,
            n_total_output_bits,
            n_blocks_generated: 0,
        })
    }

    fn total_output_len(&self) -> usize {
        (self.n_total_output_bits as usize + 7) / 8
    }

    fn remaining_output_len(&self) -> usize {
        let total_output_len = self.total_output_len();
        let generated_len = self.n_blocks_generated as usize * self.block_len;
        if total_output_len > generated_len {
            total_output_len - generated_len
        } else {
            0
        }
    }

    fn first_octet_clear_mask(&self) -> u8 {
        // If the number of requested bits is not an even multiple of 8, excess bits in
        // the first produced octet are to be masked off.
        if self.n_blocks_generated != 0 || self.n_total_output_bits % 8 == 0 {
            0u8
        } else {
            !0u8 << (self.n_total_output_bits % 8)
        }
    }
}

impl<'a> kdf::FixedBlockOutputKdf for TcgTpm2KdfE<'a> {
    fn block_len(&self) -> usize {
        self.block_len
    }

    fn max_remaining_len(&self) -> Option<usize> {
        Some(self.remaining_output_len())
    }

    fn generate_block(&mut self, output: &mut [u8]) -> Result<usize, interface::TpmErr> {
        debug_assert_eq!(output.len(), self.block_len);

        let remaining_output_len = self.remaining_output_len();
        let mut hash_instance = match &self.hash_instance {
            Some(hash_instance) => {
                // If producing the last block, the hash_instance
                // can be stolen, otherwise it needs to get cloned.
                if remaining_output_len > self.block_len {
                    hash_instance.clone()
                } else {
                    self.hash_instance.take().unwrap()
                }
            }
            None => {
                // The last block has already been produced.
                return Err(interface::TpmErr::InternalErr);
            }
        };

        let first_octet_clear_mask = self.first_octet_clear_mask();
        self.n_blocks_generated += 1;
        let counter_buf = self.n_blocks_generated.to_be_bytes();
        let usage_null_termintator = [0u8; 1];
        hash_instance.update(io_slices::IoSlices::new(&mut [
            Some(&counter_buf),
            Some(self.z),
            Some(self.usage.as_bytes()),
            Some(&usage_null_termintator),
            Some(self.party_u_info),
            Some(self.party_v_info),
        ]));

        hash_instance.finalize_into(output);
        output[0] &= !first_octet_clear_mask;
        if remaining_output_len < self.block_len {
            output[remaining_output_len..].fill(0);
        }

        Ok(self.block_len.min(remaining_output_len))
    }
}

impl<'a> kdf::Kdf for TcgTpm2KdfE<'a> {
    fn max_output_len(&self) -> Option<usize> {
        <Self as kdf::FixedBlockOutputKdf>::max_remaining_len(self)
    }

    fn generate(mut self, output: &mut io_slices::IoSlicesMut) -> Result<(), interface::TpmErr> {
        if output.len() > self.remaining_output_len() {
            return Err(interface::TpmErr::InternalErr);
        }

        // The block scratch buf will only be needed if any of the output slices'
        // lengths doesn't align with the Hash block length.
        let block_scratch_buf_len = if output.iter().any(|s| s.len() % self.block_len != 0) {
            self.block_len
        } else {
            0
        };
        let mut block_scratch_buf = utils::try_alloc_zeroizing_vec::<u8>(block_scratch_buf_len)?;

        self.generate_chunk_impl(output, block_scratch_buf.as_mut_slice(), 0)?;

        Ok(())
    }

    fn generate_and_xor(
        mut self,
        output: &mut io_slices::IoSlicesMut,
    ) -> Result<(), interface::TpmErr> {
        if output.len() > self.remaining_output_len() {
            return Err(interface::TpmErr::InternalErr);
        }

        let mut block_scratch_buf = utils::try_alloc_zeroizing_vec::<u8>(self.block_len)?;
        self.generate_and_xor_chunk_impl(output, block_scratch_buf.as_mut_slice(), 0)?;

        Ok(())
    }
}

#[test]
fn test_kdf_e() {
    use alloc::vec;
    use kdf::Kdf as _;

    const TEST_Z: [u8; 6] = cmpa::hexstr::bytes_from_hexstr_cnst::<6>("746573745f7a");
    const TEST_USAGE: &str = "test_usage";
    const TEST_PARTY_U_INFO: [u8; 17] =
        cmpa::hexstr::bytes_from_hexstr_cnst::<17>("746573745f70617274795f755f696e666f");
    const TEST_PARTY_V_INFO: [u8; 17] =
        cmpa::hexstr::bytes_from_hexstr_cnst::<17>("746573745f70617274795f765f696e666f");

    struct TestVec {
        hash_alg: interface::TpmiAlgHash,
        n_total_output_bits: u32,
        expected: &'static [u8],
    }

    const TEST_VECS: &[TestVec] = &[
        #[cfg(feature = "sha1")]
        TestVec {
            hash_alg: interface::TpmiAlgHash::Sha1,
            n_total_output_bits: 397,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<50>(
                "1005765e2a0cd4fa8474bca364d1778b4194b465d87b5f7f2ef764fce9646390\
                 c6bc3eb9f5297513cef685ef25efa7900eca",
            ),
        },
        #[cfg(feature = "sha256")]
        TestVec {
            hash_alg: interface::TpmiAlgHash::Sha256,
            n_total_output_bits: 637,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                "0072b21df66ee3b47597981553506ca59d8a87b97ca2ade3f4051b1090578bdd\
                 317320dbf0239f179fb5c6c5a21f2c15df75a0f4019dd5cd99bd96782fa79f66\
                 937b4a4a8cd2c26a4400a36739649961",
            ),
        },
        #[cfg(feature = "sha384")]
        TestVec {
            hash_alg: interface::TpmiAlgHash::Sha384,
            n_total_output_bits: 957,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                "031f5b896a011fb97ad48c57f3d240f5c2b769c124ce507ee021679ba4e17617\
                 fb9a83dd741b5f825aba1217ea7bbfd6005c51f6d055053799539ca437510ea2\
                 55b4155d5d3d5b7d764884b410712b7df0633eb541a9a0efb09ef60b90bd9063\
                 d1ea71af0be96d25887a1a10ddde0dedee9cd76534d6a9a8",
            ),
        },
        #[cfg(feature = "sha512")]
        TestVec {
            hash_alg: interface::TpmiAlgHash::Sha512,
            n_total_output_bits: 1277,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                "1953e61188abb2930673a0dce048e4ed1241e42b8c2503f204a99965da6f204b\
                 a32bc95135cda4f0d66cc51f49138f751b36c014234de8cb5bbac797409a0fe4\
                 0bb717594e8b49c12fd9b59147c0fb5f43fb2eed517ad9d4479aa447c76a5f20\
                 014f0f80c61b075053d176c483f1b5778fef589bba5bcfc23fe87ea78cb859da\
                 3c22a9b79827379a10b4cc706a8e757f372982f033939ba87f79c596f0e6a8cd",
            ),
        },
        #[cfg(feature = "sha3_256")]
        TestVec {
            hash_alg: interface::TpmiAlgHash::Sha3_256,
            n_total_output_bits: 637,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                "190b23427aee3e226d2f58dab161a445ad9281ed0f72dfc680deb4f78cb07c46\
                 0da480e4e3e7b602133373b5bd703fea7b49fb96699aad9e0947116159add5be\
                 51952b7cb4660da1f5817a1cc4c2f058",
            ),
        },
        #[cfg(feature = "sha3_384")]
        TestVec {
            hash_alg: interface::TpmiAlgHash::Sha3_384,
            n_total_output_bits: 957,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                "0e7d97e86e0f8986493f024dfa55da4ce1ee99f9a08fb23ab56251f2f9706cd1\
                 b697cc2e09083df34da77aecba0fe174dda5054cd06e9a3bb334a600974d564e\
                 877c19d96c7a99deda5a7a1a892bc298053529a6b67b50d53a54ac8f5f056787\
                 35baaa1da8875f86223b1081466c5c0f06d4b72c21531853",
            ),
        },
        #[cfg(feature = "sha3_512")]
        TestVec {
            hash_alg: interface::TpmiAlgHash::Sha3_512,
            n_total_output_bits: 1277,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                "0b84e6abdbdc644b3af341d4d08404f2bcad033214ad3955d30e4e09bdc96fc8\
                 3251909bd9b4466b13abe8611136fc7ec37f8b425c91f3de5f60729b2eb16042\
                 73c4a7dd9e745daf9e7a2e401795db1a6b82f0befa6add2b8a4e2b643ed10871\
                 941802e5a9d30be98631841eca693b88cda3187c7420305bc8461cbb067b5120\
                 9558d5aa98f6189aa9d2538c3990754605bafaaf525058b0612f6f9bafd558b3",
            ),
        },
    ];

    for test_vec in TEST_VECS.iter() {
        let kdf = TcgTpm2KdfE::new(
            test_vec.hash_alg,
            &TEST_Z,
            TEST_USAGE,
            &TEST_PARTY_U_INFO,
            &TEST_PARTY_V_INFO,
            test_vec.n_total_output_bits,
        )
        .unwrap();

        let mut output = vec![0u8; test_vec.expected.len()];
        kdf.generate(&mut io_slices::IoSlicesMut::new(&mut [Some(&mut output)]))
            .unwrap();
        assert_eq!(&output, test_vec.expected);
    }
}
