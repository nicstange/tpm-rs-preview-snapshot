// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

// The Hash_DRBG construction from NIST SP 800-90Ar1.

extern crate alloc;
use crate::crypto::{hash, io_slices};
use crate::interface;
use crate::utils::{self, cfg_zeroize};
use alloc::vec::Vec;
use cmpa;
use core::mem;

use super::{ReseedableRngCore, RngCore, RngGenerateError, RngReseedError};

pub struct HashDrbg {
    /// Hash algorithm used for the construction.
    alg: interface::TpmiAlgHash,

    /// Number of requests processed since last (re)seed
    reseed_counter: u64,

    v: cfg_zeroize::Zeroizing<Vec<u8>>,
    c: cfg_zeroize::Zeroizing<Vec<u8>>,
}

impl HashDrbg {
    const MAX_REQUESTS: u64 = 1u64 << 48;
    const MAX_REQUEST_LEN: u32 = 1u32 << 16; // 2^19 bits

    pub fn min_seed_entropy_len(alg: interface::TpmiAlgHash) -> usize {
        // If the preimage resistance security strength is unknown/unspecified,
        // resort to the digest size.
        match hash::hash_alg_preimage_security_strength(alg) {
            Some(strength) => (strength as usize + 7) / 8,
            None => hash::hash_alg_digest_len(alg) as usize,
        }
    }

    pub fn instantiate(
        alg: interface::TpmiAlgHash,
        entropy: &[u8],
        nonce: Option<&[u8]>,
        personalization: Option<&[u8]>,
    ) -> Result<Self, interface::TpmErr> {
        if entropy.len() < Self::min_seed_entropy_len(alg) {
            return Err(interface::TpmErr::InternalErr);
        }

        // NIST SP 800-90Ar1, 10.1.1.2: Hash_DRBG_Instantiate_algorithm.
        let seedlen = Self::seedlen_for_hash_alg(alg)?;
        let mut hash_instance = hash::HashInstance::new(alg);
        let digest_len = hash_instance.digest_len();
        let mut digest_scratch_buf = utils::try_alloc_zeroizing_vec::<u8>(digest_len)?;
        let mut v = utils::try_alloc_zeroizing_vec::<u8>(seedlen)?;
        let mut c = utils::try_alloc_zeroizing_vec::<u8>(seedlen)?;

        // Step 1.)
        let mut seed_material = [Some(entropy), nonce, personalization];
        let seed_material = io_slices::IoSlices::new(&mut seed_material);
        // Step 2-3.);
        Self::hash_df(
            &mut hash_instance,
            seed_material,
            None,
            &mut v,
            &mut digest_scratch_buf,
        )?;
        // Step 4.);
        Self::hash_df(
            &mut hash_instance,
            io_slices::IoSlices::new([Some([0x00u8].as_slice()), Some(&v)].as_mut_slice()),
            None,
            &mut c,
            &mut digest_scratch_buf,
        )?;
        // Step 5.)
        let reseed_counter = 1;

        Ok(Self {
            alg,
            reseed_counter,
            v,
            c,
        })
    }

    pub fn reseed(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&io_slices::IoSlices>,
    ) -> Result<(), RngReseedError> {
        if entropy.len() < Self::min_seed_entropy_len(self.alg) {
            return Err(RngReseedError::TpmErr(interface::TpmErr::InternalErr));
        }

        // NIST SP 800-90Ar1, 10.1.1.3: Hash_DRBG Reseed_algorithm.
        let mut hash_instance = hash::HashInstance::new(self.alg);
        let digest_len = hash_instance.digest_len();
        // The code below hashes into v[] and c[], which are of size
        // seedlen_for_hash_alg() and thus, not aligned to the digest_len.
        let mut digest_scratch_buf =
            utils::try_alloc_zeroizing_vec::<u8>(digest_len).map_err(RngReseedError::TpmErr)?;

        // Spare a reallocation, swap V and C. The old V, now in self.c, is getting
        // hashed into the new state below.
        mem::swap(&mut self.v, &mut self.c);
        // Step 1.)
        let mut seed_material = [Some([0x01u8].as_slice()), Some(&self.c), Some(entropy)];
        let seed_material = io_slices::IoSlices::new(&mut seed_material);
        // Step 2-3.)
        Self::hash_df(
            &mut hash_instance,
            seed_material,
            additional_input,
            &mut self.v,
            &mut digest_scratch_buf,
        )
        .map_err(RngReseedError::TpmErr)?;
        // Step 4.)
        Self::hash_df(
            &mut hash_instance,
            io_slices::IoSlices::new([Some([0x00u8].as_slice()), Some(&self.v)].as_mut_slice()),
            None,
            &mut self.c,
            &mut digest_scratch_buf,
        )
        .map_err(RngReseedError::TpmErr)?;

        // Step 5.)
        self.reseed_counter = 1;

        Ok(())
    }

    pub fn generate(
        &mut self,
        output: &mut io_slices::IoSlicesMut,
        additional_input: Option<&io_slices::IoSlices>,
    ) -> Result<(), RngGenerateError> {
        let mut hash_instance = hash::HashInstance::new(self.alg);
        let digest_len = hash_instance.digest_len();

        let mut digest_scratch_buf =
            utils::try_alloc_zeroizing_vec::<u8>(digest_len).map_err(RngGenerateError::TpmErr)?;
        while !output.is_empty() {
            // NIST SP 800-90Ar1, 10.1.1.4: Hash_DRBG_Generate_algorithm.
            // Step 1.)
            if self.reseed_counter > Self::MAX_REQUESTS {
                return Err(RngGenerateError::ReseedRequired);
            }

            // Step 2.)
            if let Some(additional_input) = &additional_input {
                if !additional_input.is_empty() {
                    // Step 2.1.)
                    hash_instance.update(io_slices::IoSlices::new(&mut [
                        Some(&[0x02u8]),
                        Some(&self.v),
                    ]));
                    for additional_input in additional_input.iter() {
                        hash_instance
                            .update(io_slices::IoSlices::new(&mut [Some(additional_input)]));
                    }
                    hash_instance.finalize_into_reset(&mut digest_scratch_buf);
                    // Step 2.2.)
                    let mut v = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut self.v);
                    let w = cmpa::MpBigEndianUIntByteSlice::from_bytes(&digest_scratch_buf);
                    cmpa::ct_add_mp_mp(&mut v, &w);
                }
            }

            // Step 3.)
            Self::hashgen(
                &mut hash_instance,
                output,
                &mut self.v,
                &mut digest_scratch_buf,
            );

            // Step 4.)
            hash_instance.update(io_slices::IoSlices::new(&mut [
                Some(&[0x03u8]),
                Some(&self.v),
            ]));
            hash_instance.finalize_into_reset(&mut digest_scratch_buf);
            // Step 5.)
            let h = cmpa::MpBigEndianUIntByteSlice::from_bytes(&digest_scratch_buf);
            let mut v = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut self.v);
            cmpa::ct_add_mp_mp(&mut v, &h);
            let c = cmpa::MpBigEndianUIntByteSlice::from_bytes(&self.c);
            cmpa::ct_add_mp_mp(&mut v, &c);
            let reseed_counter = self.reseed_counter.to_be_bytes();
            let reseed_counter = cmpa::MpBigEndianUIntByteSlice::from_bytes(&reseed_counter);
            cmpa::ct_add_mp_mp(&mut v, &reseed_counter);

            // Step 6.)
            self.reseed_counter += 1;
        }

        Ok(())
    }

    fn seedlen_for_hash_alg(alg: interface::TpmiAlgHash) -> Result<usize, interface::TpmErr> {
        // See SP 800-90Ar1, Table 2 on page 38. Strictly speaking, only values for the
        // SHA2 family of hashes are specified (SHA3 isn't even approved for the
        // Hash_DRBG construction), but simply transfer the defined seedlens to
        // SHA3 (or SM3 even) based on matching digest sizes.
        let digest_len = hash::hash_alg_digest_len(alg);
        if digest_len <= 32 {
            Ok(55)
        } else if digest_len <= 64 {
            Ok(110)
        } else {
            Err(interface::TpmErr::InternalErr)
        }
    }

    fn hash_df(
        hash_instance: &mut hash::HashInstance,
        input: io_slices::IoSlices,
        additional_input: Option<&io_slices::IoSlices>,
        mut output: &mut [u8],
        digest_scratch_buf: &mut [u8],
    ) -> Result<(), interface::TpmErr> {
        debug_assert_eq!(digest_scratch_buf.len(), hash_instance.digest_len());
        // The possible values of output.len() are limited to seedlen_for_hash_alg(),
        // the arithmetic below won't overflow.
        debug_assert!(output.len() <= u8::MAX as usize);
        let n_output_bits =
            u32::try_from(output.len()).map_err(|_| interface::TpmErr::InternalErr)?;
        let n_output_bits = n_output_bits
            .checked_mul(8)
            .ok_or(interface::TpmErr::InternalErr)?;
        let digest_len = hash_instance.digest_len();

        // NIST SP 800-90Ar1, 10.1.1.4: Hash_df().
        // Preparation for step 4.2.)
        let mut input_header: [u8; 5] = [0; 5];
        input_header[1..].copy_from_slice(&n_output_bits.to_be_bytes());

        // Step 2.)
        let mut remaining = output.len();
        // Step 3.), will be incremented to one before first use below.
        let mut counter: u8 = 0;
        // Step 4.)
        while remaining > 0 {
            // Step. 3.) + 4.2.)
            counter = counter
                .checked_add(1)
                .ok_or(interface::TpmErr::InternalErr)?;

            // Step 4.1.) with final step 5.) fused into the loop.
            input_header[0] = counter;
            hash_instance.update(io_slices::IoSlices::new(
                [Some(input_header.as_slice())].as_mut_slice(),
            ));
            for input in input.iter() {
                hash_instance.update(io_slices::IoSlices::new([Some(input)].as_mut_slice()));
            }
            if let Some(additional_input) = &additional_input {
                for input in additional_input.iter() {
                    hash_instance.update(io_slices::IoSlices::new([Some(input)].as_mut_slice()));
                }
            }

            if remaining >= digest_len {
                let cur_output_chunk;
                (cur_output_chunk, output) = output.split_at_mut(digest_len);
                hash_instance.finalize_into_reset(cur_output_chunk);
                remaining -= digest_len
            } else {
                hash_instance.finalize_into_reset(digest_scratch_buf);
                output.copy_from_slice(&digest_scratch_buf[..remaining]);
                remaining = 0;
            }
        }

        Ok(())
    }

    fn hashgen(
        hash_instance: &mut hash::HashInstance,
        output: &mut io_slices::IoSlicesMut,
        v: &mut [u8],
        digest_scratch_buf: &mut [u8],
    ) {
        // NIST SP 800-90Ar1, 10.1.1.4: Hashgen().
        // Step 1.), in a sense.
        // In addition, enforce the maximum request length, the caller, Self::generate()
        // will loop and submit multiple "virtual" requests to hashgen() as
        // needed, interspersed with the required updates to the DRBG state.
        let digest_len = digest_scratch_buf.len();
        let max_request_len = Self::MAX_REQUEST_LEN - (Self::MAX_REQUEST_LEN % digest_len as u32);
        let requested_len = output.len();
        let mut remaining_len = usize::try_from(max_request_len)
            .unwrap_or(requested_len)
            .min(requested_len);
        if remaining_len == 0 {
            return;
        }

        // Step 2.)
        // Don't make a copy of v for performance reasons. Remember how often it had
        // been incremented and subtract that amount again when done.
        let mut v_delta = [0u8; mem::size_of::<usize>()];
        let mut v_delta = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(v_delta.as_mut_slice());
        // Step 3.) is implicit.
        // Step 4.)
        loop {
            // Step 4.1.)
            hash_instance.update(io_slices::IoSlices::new(&mut [Some(v)]));

            // Step 4.2.) with final step 5.) fused into the loop.
            let output0 = output.first().unwrap();
            if output0.len() >= digest_len {
                hash_instance.finalize_into_reset(&mut output0[..digest_len]);
                output.advance(digest_len);
                remaining_len -= digest_len;
            } else {
                assert_eq!(digest_scratch_buf.len(), hash_instance.digest_len());
                hash_instance.finalize_into_reset(digest_scratch_buf);
                let mut digest: &[u8] = digest_scratch_buf;
                while !digest.is_empty() && remaining_len > 0 {
                    let output0 = output.first().unwrap();
                    let output0_len = output0.len().min(digest.len());
                    let cur_digest_chunk;
                    (cur_digest_chunk, digest) = digest.split_at(output0_len);
                    output0[..output0_len].copy_from_slice(cur_digest_chunk);
                    output.advance(output0_len);
                    remaining_len -= output0_len;
                }
            }

            // Don't increment V if it's been the last chunk anyway.
            if remaining_len == 0 {
                break;
            }

            // Step 4.3.)
            let mut v = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(v);
            cmpa::ct_add_mp_l(&mut v, 1);
            cmpa::ct_add_mp_l(&mut v_delta, 1);
        }

        // Restore the original value of v. Don't bother subtracting the accumulated
        // v_delta again if it's still zero.
        if cmpa::ct_is_zero_mp(&v_delta).unwrap() == 0 {
            let mut v = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(v);
            cmpa::ct_sub_mp_mp(&mut v, &v_delta);
        }
    }
}

impl RngCore for HashDrbg {
    fn generate(
        &mut self,
        output: &mut io_slices::IoSlicesMut,
        additional_input: Option<&io_slices::IoSlices>,
    ) -> Result<(), RngGenerateError> {
        HashDrbg::generate(self, output, additional_input)
    }
}

impl ReseedableRngCore for HashDrbg {
    fn min_seed_entropy_len(&self) -> usize {
        HashDrbg::min_seed_entropy_len(self.alg)
    }

    fn reseed(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&io_slices::IoSlices>,
    ) -> Result<(), RngReseedError> {
        HashDrbg::reseed(self, entropy, additional_input)
    }
}

#[cfg(test)]
const TEST_HASH_DRBG_NONCE: &[u8] =
    &cmpa::hexstr::bytes_from_hexstr_cnst::<20>("746573745f686173685f647262675f6e6f6e6365");
#[cfg(test)]
const TEST_HASH_DRBG_PERSONALIZATION: &[u8] = &cmpa::hexstr::bytes_from_hexstr_cnst::<30>(
    "746573745f686173685f647262675f706572736f6e616c697a6174696f6e",
);
#[cfg(test)]
const TEST_HASH_DRBG_ADDITIONAL_INPUT: &[u8] = &cmpa::hexstr::bytes_from_hexstr_cnst::<31>(
    "746573745f686173685f647262675f6164646974696f6e616c5f696e707574",
);

#[cfg(test)]
struct HashDrbgTestVec<'a> {
    with_optional_inputs: bool,
    expected_outputs: [&'a [u8]; 2], // Once after instantiate, once after reseed.
}

#[cfg(test)]
fn test_hash_drbg_common(
    hash_alg: interface::TpmiAlgHash,
    entropy: &[u8],
    vecs: &[HashDrbgTestVec],
) {
    use alloc::vec;

    fn generate_and_compare(
        drbg: &mut HashDrbg,
        mut additional_input: Option<[Option<&[u8]>; 5]>,
        expected_output: &[u8],
    ) {
        let output_len = expected_output.len();
        let mut output = vec![0u8; output_len];
        let output_split_at = output_len / 2;
        let (output0, output1) = output.split_at_mut(output_split_at);
        let additional_input = match &mut additional_input {
            Some(additional_input) => {
                Some(io_slices::IoSlices::new(additional_input.as_mut_slice()))
            }
            None => None,
        };
        drbg.generate(
            &mut io_slices::IoSlicesMut::new(&mut [
                None,
                Some(output0),
                Some(&mut [0u8; 0]),
                Some(output1),
                None,
            ]),
            additional_input.as_ref(),
        )
        .unwrap();
        assert_eq!(output, expected_output);
    }

    for v in vecs.iter() {
        let (nonce, personalization, additional_input) = if v.with_optional_inputs {
            (
                Some(TEST_HASH_DRBG_NONCE),
                Some(TEST_HASH_DRBG_PERSONALIZATION),
                Some(TEST_HASH_DRBG_ADDITIONAL_INPUT),
            )
        } else {
            (None, None, None)
        };

        let empty: [u8; 0] = [0u8; 0];
        let additional_input = additional_input.map(|s| {
            let split_at = s.len() / 2;
            let (s0, s1) = s.split_at(split_at);
            [
                Some(empty.as_slice()),
                Some(s0),
                None,
                Some(s1),
                Some(&empty),
            ]
        });

        // Instantiate
        let mut drbg = HashDrbg::instantiate(hash_alg, entropy, nonce, personalization).unwrap();
        // Generate after instantiate.
        generate_and_compare(&mut drbg, additional_input, v.expected_outputs[0]);

        // Reseed.
        {
            let mut additional_input = additional_input.clone();
            let additional_input = match &mut additional_input {
                Some(additional_input) => {
                    Some(io_slices::IoSlices::new(additional_input.as_mut_slice()))
                }
                None => None,
            };
            drbg.reseed(entropy, additional_input.as_ref()).unwrap();
        }
        // And generate after reseed.
        generate_and_compare(&mut drbg, additional_input, v.expected_outputs[1]);
    }
}

#[test]
#[cfg(feature = "sha1")]
fn test_hash_drbg_sha1() {
    let entropy =
        &cmpa::hexstr::bytes_from_hexstr_cnst::<20>("0102030405060708090a0b0c0d0e0f1011121314");
    let vecs: [HashDrbgTestVec; 2] = [
        HashDrbgTestVec {
            with_optional_inputs: false,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<50>(
                    "0aea063927137a952e4f6308977ae7bd\
                     a66b5c6a627866886d81f5db5783aa6e\
                     72c093351d941ba7234ed4b462de71b8\
                     c175",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<9>("a696a411a4c9c2f344"),
            ],
        },
        HashDrbgTestVec {
            with_optional_inputs: true,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<50>(
                    "ba013692c69351aa8b5159371e56cb8a\
                     a7fe4eb58c43d699c75d343870f421d9\
                     41bc6266f0383d1038757f99a0644321\
                     75c0",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<9>("79043a1360b38bf8a2"),
            ],
        },
    ];

    test_hash_drbg_common(interface::TpmiAlgHash::Sha1, entropy, &vecs);
}

#[test]
#[cfg(feature = "sha256")]
fn test_hash_drbg_sha256() {
    let entropy = &cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20",
    );
    let vecs: [HashDrbgTestVec; 2] = [
        HashDrbgTestVec {
            with_optional_inputs: false,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "088f2cce0bef99c5388ac0742cb1b4cd\
                     ac7298deeaf397322e05c9a5b3cd9098\
                     b9708d0ee5e5dafcd6cb1ca92d7bff36\
                     4143f38f595376c92b8b2622719a4a85\
                     47173de88e6d6525b6b9ba1bbe9255c9",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<15>("46bbcc9f8c9a35586eac2400ffb8c7"),
            ],
        },
        HashDrbgTestVec {
            with_optional_inputs: true,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "a333be1ae7814d314e3ed203a377ca10\
                     dac6701ec2c9a1faf3b79dab0856216c\
                     5a880f18c3204ceb1f5e0eadb507231b\
                     8640627fc657f390e354e9de3d58f734\
                     89de9a141dac66b86e821ea8e6aa48e6",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<15>("e1b7638a93bc4e490219c3170dce3a"),
            ],
        },
    ];

    test_hash_drbg_common(interface::TpmiAlgHash::Sha256, entropy, &vecs);
}

#[test]
#[cfg(feature = "sha384")]
fn test_hash_drbg_sha384() {
    let entropy = &cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20\
         2122232425262728292a2b2c2d2e2f30",
    );
    let vecs: [HashDrbgTestVec; 2] = [
        HashDrbgTestVec {
            with_optional_inputs: false,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "271a66720ada0dee30562dc4ff31b204\
                     a4e90df2006fc86d0e65bf00600fecc4\
                     72bc50fc956ae2db6be778385aefa0d4\
                     1769304ad0a4b9256199a54dcde6ed68\
                     b70331da22b2bcddc342087280965c4b\
                     a6fbb8ed7a3d012fbbc41e66c07a91d5\
                     3994ee53d4529fb0b1e6987003f163c9\
                     28efecdda3b05021",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<23>(
                    "bbc6249a83081a679a139672175379d1\
                     6cf5631eaf0d0e",
                ),
            ],
        },
        HashDrbgTestVec {
            with_optional_inputs: true,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "753ae3fa4385496e100bfab4ca4bc4dc\
                     10b8ad9d7ad2e4584b92f6e34677068f\
                     d968a8a441512d386ce12ecef1a5af5f\
                     0f30bf7c9f268c423b23a9e3fa2e3552\
                     e6b9392fb016531ccb80880781529983\
                     58aecf4dde58bc0677e510343847ef99\
                     f9e238757e1b0b08cf319dd72fb2a58b\
                     e6493dac5fe23925",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<23>(
                    "4a9f2c3286e6d08e407928a35a521bec\
                     ba4ccdfef96f66",
                ),
            ],
        },
    ];

    test_hash_drbg_common(interface::TpmiAlgHash::Sha384, entropy, &vecs);
}

#[test]
#[cfg(feature = "sha512")]
fn test_hash_drbg_sha512() {
    let entropy = &cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20\
         2122232425262728292a2b2c2d2e2f30\
         3132333435363738393a3b3c3d3e3f40",
    );
    let vecs: [HashDrbgTestVec; 2] = [
        HashDrbgTestVec {
            with_optional_inputs: false,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "6fd3b8e6c808cc413f7c61b6d768a2cf\
                     ff0249a422ecf0f95457122c0c859f29\
                     9ae9eea351550763cb859a8f3b81b474\
                     652f29e38a0c830dc1157467de685a92\
                     33ac560fcc43ea6ba75b69bc534587ee\
                     954042aa2734b250e8f5c09adfd1d450\
                     46216ab7bf13d5a69490cb0f0585b55a\
                     12f246827a3fdd45dbe4ad27bbdca305\
                     b61938b9da656d4ee6fd073e0ae7f7f5\
                     35055785946abb901c4b87c6aa541def",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<31>(
                    "1ae68ac86b3ed5a9e0a0d18d2350a6de\
                     b9b276dfdd31fcd3f4ccdd24961978",
                ),
            ],
        },
        HashDrbgTestVec {
            with_optional_inputs: true,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "73672b5b088ddb62535252e1826e9dd4\
                     23905963b0c1d385ecd39e67dbf8e751\
                     87c35031d6ce233bb85c39bc7f5c638d\
                     e0ebfd23408e73ffc9cd71454d31136e\
                     b206e48bff1f79d0ee68740fc4cd61db\
                     efdf02da2b39ed83243a385a04d3db6d\
                     64748dd6e1ae46dc3425b3492948b652\
                     29fa161a775f61a3c1f58392fcd60c1a\
                     c16a372349f569d41f0fbb3acc14e691\
                     eb98ae10ecce48be9fb0288165072d73",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<31>(
                    "2eca8324d481d6d68122f415500161d4\
                     e56358814707526f8fde6fcda94c59",
                ),
            ],
        },
    ];

    test_hash_drbg_common(interface::TpmiAlgHash::Sha512, entropy, &vecs);
}

#[test]
#[cfg(feature = "sha3_256")]
fn test_hash_drbg_sha3_256() {
    let entropy = &cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20",
    );
    let vecs: [HashDrbgTestVec; 2] = [
        HashDrbgTestVec {
            with_optional_inputs: false,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "3258c702d6ecd0d210c1fe9abc96565a\
                     f756c3f8f7a57ee0c8907da6af9a203b\
                     76f62b1602f0fae934b72b3717e7f0b2\
                     147e95839ce232f20b847cd108b33dbb\
                     e50ec1b0ce47e30ac38d314e6d11085d",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<15>("bffb239be4bbc99a2b99536b5a1370"),
            ],
        },
        HashDrbgTestVec {
            with_optional_inputs: true,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "ff8d286be6530db33422d8764cb18ddb\
                     50388a0c4054c30e8f58ad17a3cfa3bd\
                     7292885f0d0b7c82c7d272ff825f6d4c\
                     602a6f7b421ca4b72a2c3fb4e0533b15\
                     6bf66f1269ee26022f21c07584f06cea",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<15>("d591b2ebda3ad5c43f8fee489b24d5"),
            ],
        },
    ];

    test_hash_drbg_common(interface::TpmiAlgHash::Sha3_256, entropy, &vecs);
}

#[test]
#[cfg(feature = "sha3_384")]
fn test_hash_drbg_sha3_384() {
    let entropy = &cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20\
         2122232425262728292a2b2c2d2e2f30",
    );
    let vecs: [HashDrbgTestVec; 2] = [
        HashDrbgTestVec {
            with_optional_inputs: false,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "696e8d4a7f691a54c0ef7c9ddd9e4a48\
                     3a51ce8f8736ee0e141d0d4a9229a58f\
                     e285d12f5e945bc5969eab921a7b834b\
                     f2f92226210b2683339e53a649ca6b93\
                     0c01e42618e4edf5ee5a824374b77432\
                     28efb419eefd551d90ae642f88fd9e53\
                     123f3d5d56c3ca1771da20e212c79f78\
                     9e491e01cc425e6e",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<23>(
                    "ad54372cf6c760705a89497a8d16c053\
                     fcd49d129162fe",
                ),
            ],
        },
        HashDrbgTestVec {
            with_optional_inputs: true,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "5120e9f9c1ff9afa552d7488b30676df\
                     4893d279d2eed8564902a9f5c2db4576\
                     c95f73c4441eb55c4c9809763f942a7a\
                     4091a868e0324f181470e186544e3fdc\
                     c73a2d31c7c488ff3f7be4312a6a5141\
                     784e7f9691aa8f07169052960a1abbbf\
                     04f7318448fddcd201cc5c36ebb1f095\
                     57eaabe273eb6ed5",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<23>(
                    "2ab06377bb40cde09cc0b660ed22f10c\
                     9264a3da6ace16",
                ),
            ],
        },
    ];

    test_hash_drbg_common(interface::TpmiAlgHash::Sha3_384, entropy, &vecs);
}

#[test]
#[cfg(feature = "sha3_512")]
fn test_hash_drbg_sha3_512() {
    let entropy = &cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20\
         2122232425262728292a2b2c2d2e2f30\
         3132333435363738393a3b3c3d3e3f40",
    );
    let vecs: [HashDrbgTestVec; 2] = [
        HashDrbgTestVec {
            with_optional_inputs: false,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "8216bba2eff7eb98071001558a4b2778\
                     d2d506492bdabd1c0e8b8c992c4892ec\
                     11fdf5c6527767aba9a6125751e10020\
                     a52b061a94986e766ed6aa281136006c\
                     89d15ad418ec2d934e0ec71df44c0cb3\
                     b947af06ff764e5554656144b8624bc1\
                     3dce3e7f6efcfda12df6510d805bc54f\
                     da4c5ce03391a6f2c951b7566c2d7c2b\
                     361efa08ada32367d0bc9f89f4884b76\
                     d4204420a192d3437d2c52551c2ac9e0",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<31>(
                    "208c106b6b3e3ff59efb41a82d26d61b\
                     725cedd560e20ec164f9ab567f11d6",
                ),
            ],
        },
        HashDrbgTestVec {
            with_optional_inputs: true,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "92395b61629b012b755e8c4c87e8ae80\
                     c2ba7ae4ebac717643d9baec28b848e3\
                     5bace3496da4349632b0c79693a8181d\
                     701d0baa704fbd0e45bbf1398c362612\
                     26fd88d7bd4f81840ba150854c3828c0\
                     972386d7db1ca5ef1fa6854cd3ba7dcc\
                     b37cc2896788df52d342dd234ecdfff9\
                     dc366fd7487a3ccdc9253e76bfa6957e\
                     eafbfb9f446936e3998d4a126926250b\
                     67b85e7ecde016059767c603d7d2a40d",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<31>(
                    "c48cd20f6d2a35cb7ec56ae7bc300596\
                     c9466932037b0f759d4117dce676e2",
                ),
            ],
        },
    ];

    test_hash_drbg_common(interface::TpmiAlgHash::Sha3_512, entropy, &vecs);
}
