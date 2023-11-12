// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use super::FixedBlockOutputKdf;
use crate::crypto::{hash, io_slices, kdf};
use crate::interface;
use crate::utils;
#[cfg(test)]
use cmpa;

// KDFa() as specified in TCG TPM2 Library specification, Part 1
// ("Architecture"), section 11.4.10.2 ("KDFa()")
pub struct TcgTpm2KdfA<'a> {
    hmac_instance: Option<hash::HmacInstance>,
    block_len: usize,
    label: &'a [u8],
    context_u: Option<&'a [u8]>,
    context_v: Option<&'a [u8]>,
    n_total_output_bits: u32,
    n_blocks_generated: u32,
}

impl<'a> TcgTpm2KdfA<'a> {
    pub fn new(
        hash_alg: interface::TpmiAlgHash,
        key: &[u8],
        label: &'a [u8],
        context_u: Option<&'a [u8]>,
        context_v: Option<&'a [u8]>,
        n_total_output_bits: u32,
    ) -> Result<Self, interface::TpmErr> {
        if usize::try_from(n_total_output_bits).is_err() {
            return Err(interface::TpmErr::InternalErr);
        }

        let (hmac_instance, block_len) = if n_total_output_bits != 0 {
            let hmac_instance = hash::HmacInstance::new(hash_alg, key);
            let block_len = hmac_instance.digest_len();
            (Some(hmac_instance), block_len)
        } else {
            (None, hash::hash_alg_digest_len(hash_alg) as usize)
        };

        Ok(Self {
            hmac_instance,
            block_len,
            label,
            context_u,
            context_v,
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

    fn label_zero_sep(&self) -> Option<[u8; 1]> {
        // Iff label[] does not end in a zero byte itself,
        // it gets separated from the subsequent HMAC input by
        // a 0u8.
        if self.label.last().map(|b| *b != 0u8).unwrap_or(false) {
            Some([0u8])
        } else {
            None
        }
    }

    fn first_octet_clear_mask(&self) -> u8 {
        // If the number of requested bits is not an even multiple of 8, excess bits in
        // the first produced octet are to be masked off at the
        if self.n_blocks_generated != 0 || self.n_total_output_bits % 8 == 0 {
            0u8
        } else {
            !0u8 << (self.n_total_output_bits % 8)
        }
    }
}

impl<'a> kdf::FixedBlockOutputKdf for TcgTpm2KdfA<'a> {
    fn block_len(&self) -> usize {
        self.block_len
    }

    fn max_remaining_len(&self) -> Option<usize> {
        Some(self.remaining_output_len())
    }

    fn generate_block(&mut self, output: &mut [u8]) -> Result<usize, interface::TpmErr> {
        debug_assert_eq!(output.len(), self.block_len);

        let remaining_output_len = self.remaining_output_len();
        let mut hmac_instance = match &self.hmac_instance {
            Some(hmac_instance) => {
                // If producing the last block, the hmac_instance
                // can be stolen, otherwise it needs to get cloned.
                if remaining_output_len > self.block_len {
                    hmac_instance.clone()
                } else {
                    self.hmac_instance.take().unwrap()
                }
            }
            None => {
                // The last block has already been produced.
                return Err(interface::TpmErr::InternalErr);
            }
        };

        let first_octet_clear_mask = self.first_octet_clear_mask();
        self.n_blocks_generated += 1;
        let i_buf = self.n_blocks_generated.to_be_bytes();
        let label_zero_sep = self.label_zero_sep();
        let bits_buf = self.n_total_output_bits.to_be_bytes();
        hmac_instance.update(io_slices::IoSlices::new(&mut [
            Some(&i_buf),
            Some(self.label),
            label_zero_sep.as_ref().map(|s| s.as_slice()),
            self.context_u,
            self.context_v,
            Some(bits_buf.as_slice()),
        ]));

        hmac_instance.finalize_into(output);
        output[0] &= !first_octet_clear_mask;
        if remaining_output_len < self.block_len {
            output[remaining_output_len..].fill(0);
        }

        Ok(self.block_len.min(remaining_output_len))
    }
}

impl<'a> kdf::Kdf for TcgTpm2KdfA<'a> {
    fn max_output_len(&self) -> Option<usize> {
        <Self as FixedBlockOutputKdf>::max_remaining_len(self)
    }

    fn generate(mut self, output: &mut io_slices::IoSlicesMut) -> Result<(), interface::TpmErr> {
        if output.len() > self.remaining_output_len() {
            return Err(interface::TpmErr::InternalErr);
        }

        // The block scratch buf will only be needed if any of the output slices'
        // lengths doesn't align with the HMAC block length.
        let block_scratch_buf_len = if output.iter().any(|s| s.len() % self.block_len != 0) {
            self.block_len
        } else {
            0
        };
        let mut block_scratch_buf = utils::try_alloc_zeroizing_vec::<u8>(block_scratch_buf_len)?;

        self.generate_chunk_impl(output, block_scratch_buf.as_mut_slice(), 0)?;

        Ok(())
    }

    fn generate_and_xor(mut self, output: &mut io_slices::IoSlicesMut) -> Result<(), interface::TpmErr> {
        if output.len() > self.remaining_output_len() {
            return Err(interface::TpmErr::InternalErr);
        }

        let mut block_scratch_buf = utils::try_alloc_zeroizing_vec::<u8>(self.block_len)?;
        self.generate_and_xor_chunk_impl(output, block_scratch_buf.as_mut_slice(), 0)?;

        Ok(())
    }
}

#[cfg(test)]
const TEST_KDF_A_LABEL: &[u8] =
    &cmpa::hexstr::bytes_from_hexstr_cnst::<17>("746573745f6b64665f615f6c6162656c00");
#[cfg(test)]
const TEST_KDF_A_CONTEXT_U: &[u8] =
    &cmpa::hexstr::bytes_from_hexstr_cnst::<19>("746573745f6b64665f615f636f6e7465787455");
#[cfg(test)]
const TEST_KDF_A_CONTEXT_V: &[u8] =
    &cmpa::hexstr::bytes_from_hexstr_cnst::<19>("746573745f6b64665f615f636f6e7465787456");

#[cfg(test)]
struct KdfATestVec<'a> {
    output_bits: u32,
    expected_outputs: [&'a [u8]; 4], /* For each combination of w/o or with context_u and
                                      * context_v each. */
}

#[cfg(test)]
fn test_kdf_a_common(hash_alg: interface::TpmiAlgHash, key: &[u8], vecs: &[KdfATestVec]) {
    use alloc::vec;
    use kdf::{Kdf as _, VariableChunkOutputKdf as _};

    for v in vecs.iter() {
        let total_output_len = ((v.output_bits + 7) / 8) as usize;
        for cfg in 0..4 {
            let context_u = if cfg & 2 != 0 {
                Some(TEST_KDF_A_CONTEXT_U)
            } else {
                None
            };
            let context_v = if cfg & 1 != 0 {
                Some(TEST_KDF_A_CONTEXT_V)
            } else {
                None
            };
            for l in 0..1 {
                // Removing the 0x00 byte at the end of label should not have any effect,
                // KDFa() would reinsert it (virtually).
                let label = &TEST_KDF_A_LABEL[..TEST_KDF_A_LABEL.len() - l];

                // Test plain, direct use.
                let kdf =
                    TcgTpm2KdfA::new(hash_alg, key, label, context_u, context_v, v.output_bits)
                        .unwrap();
                let mut output = vec![0u8; total_output_len];
                kdf.generate(&mut io_slices::IoSlicesMut::new(&mut [Some(&mut output)]))
                    .unwrap();
                assert_eq!(output, v.expected_outputs[cfg]);

                // Test the KDF wrapped in a BufferedFixedBlockOutputKdf.
                let kdf =
                    TcgTpm2KdfA::new(hash_alg, key, label, context_u, context_v, v.output_bits)
                        .unwrap();
                let mut buffered_kdf = kdf::BufferedFixedBlockOutputKdf::new(kdf).unwrap();
                let mut total_consumed_len = 0;
                let mut chunk_len = 3;
                while total_consumed_len < total_output_len {
                    chunk_len = chunk_len.min(total_output_len - total_consumed_len);
                    let mut outbuf = vec![0u8; chunk_len];
                    buffered_kdf
                        .generate_chunk(&mut io_slices::IoSlicesMut::new(&mut [Some(&mut outbuf)]))
                        .unwrap();
                    assert_eq!(
                        outbuf,
                        v.expected_outputs[cfg][total_consumed_len..total_consumed_len + chunk_len]
                    );
                    total_consumed_len += chunk_len;
                    chunk_len = 31;
                }
                let mut outbuf = vec![0u8; 1];
                let r = buffered_kdf
                    .generate_chunk(&mut io_slices::IoSlicesMut::new(&mut [Some(&mut outbuf)]));
                assert!(matches!(r, Err(interface::TpmErr::InternalErr)))
            }
        }
    }
}

#[test]
#[cfg(feature = "sha1")]
fn test_kdf_a_sha1() {
    let key =
        &cmpa::hexstr::bytes_from_hexstr_cnst::<20>("0102030405060708090a0b0c0d0e0f1011121314");
    let vecs: [KdfATestVec; 2] = [
        KdfATestVec {
            output_bits: 400,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<50>(
                    "7fbeb21c36a89a225040381bea132937\
                     208e6c5cdb2be5bc33af0ecad68da710\
                     ba364763da0498507f407a56da743662\
                     4ab6",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<50>(
                    "3ffaf0a74b95743caa95a9a092771fcb\
                     c3e06ac993f928df9ef07a62f4592dff\
                     0791a026cfffd537c8a70e8ba6e963d8\
                     6338",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<50>(
                    "3a93e9747073c0cd376998ed3b1e8276\
                     21d4b3a261a45448d3b0fda1481aeaf9\
                     271575f8bb7774cd3324569f17eebea0\
                     2195",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<50>(
                    "3c0c4bb6c0257d3430ad88db0ada33e0\
                     1e3b0449e1f8cc4c936ce12bd197c02d\
                     744a6c438fb1a41042cf5026bbcf85c6\
                     29dc",
                ),
            ],
        },
        KdfATestVec {
            output_bits: 397,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<50>(
                    "0863779fa74a9868138c4a82934ffaff\
                     04e81f9d15689d9a8f9ea33225dad696\
                     7e6e504008b281ace1f4df80922a58de\
                     6ea6",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<50>(
                    "1af59ace3fdff4b2865aa4a5a8894066\
                     21f9c9f239952da90dcafefc39f0816f\
                     070db5f1b08fb0b07eb25409867ae572\
                     c642",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<50>(
                    "0a1ca80dd15f1cd7424e53791b9ad06a\
                     da96429b63d0154464aad211eb82b1c8\
                     cc851cb5bf4305b3a4cccbfcc1e7fa96\
                     8d5f",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<50>(
                    "003141d500a641b0465ea90b4b1a8af0\
                     2e58b13ab18f2b18b92c7e0d6566bd4f\
                     c50489d4e2098407baa73936b4a943d9\
                     77a9",
                ),
            ],
        },
    ];

    test_kdf_a_common(interface::TpmiAlgHash::Sha1, key, &vecs);
}

#[test]
#[cfg(feature = "sha256")]
fn test_kdf_a_sha256() {
    let key = &cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20",
    );
    let vecs: [KdfATestVec; 2] = [
        KdfATestVec {
            output_bits: 640,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "d8a01f0d475078caa9828edcf9ee9cc5\
                     13ff7c72a1e4b5abe91ef572d99b827a\
                     3935edaed51e9575a03eae79d6011b8d\
                     a28fca0f5f86ca7a04ff7345667d3fba\
                     5b357bbfdc8a558b73d8c4736460b389",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "3ed1b2d1fad86697635d680de0ad4302\
                     7614a296c979df2b6c82b473c13c55ab\
                     1a8f522832308973c6b71ed220d08f65\
                     05f89035d32e1454ddd9d22c906a69cd\
                     455902d3221b688143551ecefcae97f4",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "4242ce2dba9f8bb01ed36d93deb50a3a\
                     fa72320f39bf10796815b5a4dd08e592\
                     75d042e709f8b3ddfa06bc91d0ea4f92\
                     b3c03f85e16e1a39fd21ef736d84e035\
                     42d9aa3f6cd029af88e37c8e6fe7c7b1",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "cdea645d147f9ebc8c09ef713f02f7f2\
                     2d558222df0535ab0e339b4245c47e13\
                     dbb99b92990499b1e0b52af3f479c15a\
                     f9002dc10bb9a0643eadba7169fc272b\
                     96e1b956ab3ba80d209da20f90a638ef",
                ),
            ],
        },
        KdfATestVec {
            output_bits: 637,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "05e27ba5a54a048c17398db8acfff6a5\
                     bdee852114fc19f486920967606cb3f2\
                     e451e564078382df83cf060bf63a34a9\
                     8c0011104b26fffe823ffcd39eb52503\
                     92f0f2829a610a5e451c57d237c71e07",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "08bbeb65ccc3e2055b16c615073099e0\
                     1b2b37a0cca1ef7debc04a59b9d2df32\
                     5315dda5aa3446881bb328eec0e95233\
                     9644c8c3615cdfb3e91e9db5573855fc\
                     b0e102a74baf60f0f5eb07b36108d11f",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "19ab8d468fee122d6119ca00eff9010b\
                     99b6a1a1de6370ea1692e7781448c81b\
                     4d3c921c55c7bcfde9afa787af86ce5b\
                     8638e13d2b407f86eddd3a7dfa39124d\
                     f0f1e211fd22564a1c011f2c025c7999",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "1b020bda0129cbe74183f861d81b0844\
                     65cc290ac1b4f491ea6b042d26a01839\
                     69786c49ebd39d155b199aa6496bc762\
                     2ff371ccfe4b32d6adb1958e6d9b43fe\
                     0fcf7fc0be61e7554623b70a3622b903",
                ),
            ],
        },
    ];

    test_kdf_a_common(interface::TpmiAlgHash::Sha256, key, &vecs);
}

#[test]
#[cfg(feature = "sha384")]
fn test_kdf_a_sha384() {
    let key = &cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20\
         2122232425262728292a2b2c2d2e2f30",
    );
    let vecs: [KdfATestVec; 2] = [
        KdfATestVec {
            output_bits: 960,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "5e607a7d6bd9f5662b0e421423d4a469\
                     46de3a7ea15e88db64b979622fe1ee27\
                     1a33dd7d1aaab8537b855b5e2985044d\
                     38e0f703288621d7bb468f4ae2006d64\
                     c922412ef235cb71985d93804e2ed064\
                     fe5fd0451b286c4d67752e9ab9aeefa3\
                     dd42b7767897f8f6da99da48f29739bd\
                     8cafd4522601ff38",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "c441f528950d568fae14b28c511d46b0\
                     060ae175fd89ab63563ba6d0f078e45b\
                     c7d2f62d0c9787104d67e370b2c58046\
                     f2a013780068db1fc3f377cde546e148\
                     9012c20adb9ae71b544be0bc637a192e\
                     cb62137780a812832524792541feeca0\
                     a1a3f2c69336e1cfab14185ddb13f5a1\
                     a62093dd5e447534",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "496a6e2a9c81e6109d936154c6042814\
                     b8bfe08a0a6c45a07148362d333590e1\
                     a1bc84531b4fa8a2dd8868972497ad56\
                     b4511830219a1845d692ca3d6c81360f\
                     57eeac396e29f239f84fc816869721f0\
                     0f0c10be6a964589a7cf5c19a3f768d0\
                     de52b4e44990dcaf03b8827dff687e72\
                     b671c2d6b6ba2a52",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "fa48497ecdb3f16f607afae51be40303\
                     e21288fa04b29659749a2edcf72f3419\
                     ea835282e4568ec97f64fc24aa4d5f39\
                     829fce67bcb6d1ccacadeee10d33c11d\
                     0178d6c8a0e72f2a752b92c015927768\
                     9cd8b7e0fff7ddc726f8acf5cf9d25ab\
                     e1ca690c466ccdf59f2e3b30ddabf089\
                     0e78e778fcf41644",
                ),
            ],
        },
        KdfATestVec {
            output_bits: 957,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "1250b3d5c0b760aace9383ddba725820\
                     0cd76288a49831f9f0c830682c1011d5\
                     0e4eaa5303a32e687866f5258b4abd16\
                     1bb0815b2a7c008b35252159ad9fc60a\
                     1fd6bb5cf62e156eaf0a225d2ee106cf\
                     0ffaf82c905517e6d725f14414bc6762\
                     57b30f72b326ce128da824373fa142e4\
                     e2a795269c358c55",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "05655a7218fb3a48fa5e7d8719ef9c2e\
                     4ba6c212ccb4e2387c36ac29cfdf27b3\
                     212f295245b01d5816aecb1ec528a927\
                     13cf6ddd7beff93cba026c28a6425d93\
                     95de480df5f2db97114fc26f4edc291f\
                     2e95a516f2489d3fe4a73221806dd7b2\
                     81f78ef1550137e1dee244eb726ba4e7\
                     086b0dd52d703860",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "1e4e9ec552956a5d5584c3d5e8681fcd\
                     afc31d71485e65cbcad184d761309de8\
                     267603caa596e1ab8446d9f9f52b73ac\
                     d6e54986ffee7ca823b2256bcce79425\
                     4fb1315af4a595968a989e14668a46b1\
                     b2656fb2616c02cfb74247507a6083ba\
                     416ed94c2e4b01c8ee23175d826f2fca\
                     e8df65bf8e6ead20",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "0f06ac24b96c17305e623d315ffb34bd\
                     0ea4830abeedc14c7ea26d259b32ce9a\
                     8c555750268e182f39dc22a275bd8f3b\
                     69f7cba19db8fe6ea1f2b2f863af0cc2\
                     d2db76db29cf3c26eaaa58065fcee3dd\
                     432353bcff8a87ad9095af33a2d26720\
                     784531fe4de82f78b11a0b91a683597b\
                     07a91c2c6978a7c9",
                ),
            ],
        },
    ];

    test_kdf_a_common(interface::TpmiAlgHash::Sha384, key, &vecs);
}

#[test]
#[cfg(feature = "sha512")]
fn test_kdf_a_sha512() {
    let key = &cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20\
         2122232425262728292a2b2c2d2e2f30\
         3132333435363738393a3b3c3d3e3f40",
    );
    let vecs: [KdfATestVec; 2] = [
        KdfATestVec {
            output_bits: 1280,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "a165982a39ac389b8fbd291e3a8ca404\
                     0d6382e64f266b23fc8423f6ba69a0f1\
                     8931384c5636a407a43090c72aa7fac0\
                     31ef844bf6ec02f4769af393ffe75eee\
                     05b5612dd9c4f1af8f6b5dc09e160518\
                     92f02daf6f923d85666b5cdcd2dd4cb3\
                     803792d51216a68ec6e182753268d02b\
                     9e879bb262b5ce7a41c2a3893cd32e42\
                     4fb8ba5f811f74d1e553cfb8842f0532\
                     7c5692ae7894a0225401f867b4c87e7f",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "319abe52b68ee8e055f824d30327cc75\
                     a11010f2995f917ade4d7a9e6e16d9e1\
                     d389d580f47829912deb8e3ae6bf58c4\
                     fca5eceb8729a5ba893d969e3ca869bd\
                     3fbd3a4a26564c1c67b151f0c79d897a\
                     13c0a34f23c2fbc48a2f06e46d577763\
                     44d798a417c734fefddab57e97a5e91a\
                     24800acd16f095161130c8cbbf9d16e5\
                     624f5bc2eacb1b5f931661b88503893b\
                     31cb990aee25cd2ae5836df6266ef27f",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "8c53e55c3c2011b608409e23f7a91fd5\
                     ef1f6296f59335ef306b2d61bf4fc2e7\
                     e9df3844a782e0eed0c837681283a316\
                     092c32390bf08f7657532c15b99b59e8\
                     6950888f5c54d44abf287a4d4a683324\
                     2b71feba189a1a886633f0ba9d64fe25\
                     85deccbac865a2f557ab0cb2d1207818\
                     6918785cab031649924e54b96a279644\
                     f822467fd914f90c640e01d7b166cfdd\
                     1130e6e2f0ae39890cf3726f4161bf50",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "a50ff1569c6064024b21bd57d13c3e81\
                     a308c1ec4f3e101e6615af475e0e933b\
                     ec173aeab20591af668238696d05c0e7\
                     708bd0a92d3fc8b7103f2fc5a8a95177\
                     5efde071f65f0ccb1b31d37d762b93be\
                     94f6b018ea3f87a57a23548def5bd0df\
                     b4005776c64dfef3c10a3ca27a2348f1\
                     c02011a17c2644e6d063e655d247941b\
                     11d5e8e7ad5cb5b8aa75e7a4dd40920e\
                     7110b5ef597d9578ef30df4af3680096",
                ),
            ],
        },
        KdfATestVec {
            output_bits: 1277,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "0b645dd93226391ae934a9bd5583b5bf\
                     6efcc44b92894f42d27e8738024f3d40\
                     20c9ea92f7d6c9f587d8aa822efef690\
                     33b361f81a78e2021ac8467ea91f8c0b\
                     dabf2e515aae47c3268ebc26dcb002f5\
                     85b1a8196c216eaa41a5a64313aa50e0\
                     d3f7aa7b0db787631d9c2e63935706a9\
                     5495955be4e301fb3491026bdbf02975\
                     e2944602f467790c9a2559ef965787b0\
                     d97811678c8292a16d4e162e0e75513c",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "05daed5b73a1636d8ee56cdf585aaf3e\
                     5041f085a3d31cd4239db0bf5a59f536\
                     b9a06c7cce933a1a009f4c83e0754036\
                     08c48fbdbe10988af04bbefe2f6edda4\
                     e20fa2ea33f9e38a61b16d54682356c0\
                     15c85bf4eee7ba1724399a0dbb02881a\
                     dce8b8b9b4a799836693bd5f206eb47a\
                     c0c58584f1cfb1eb8fbe6e95d00c309b\
                     c942c92e9b88e35d9ff3ca0e3c6a280a\
                     773ee193357aff97bd1d777944eb3b54",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "1d158d8e1909bdd3e3776869914d3141\
                     3b89ecb0d4ef5ea119a8057e957a0f97\
                     ad3c5102c4e34d9660e36ce59dedc670\
                     c7e8235410e6eb382da7a7dc272fbba6\
                     455f96da0b0cbd1c47586c858b5715d1\
                     16261d7b465377adf519fa4b5059a009\
                     39163e890c32ff3e3dcda263934dcd7b\
                     8256a797188e4a1e655c0a3b7b283bc1\
                     3f4aae88d4003808afabaaaea8a497cb\
                     a0d4e38a3d3393cc06af24b00ff2d89b",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "09816eaf31c50aec25328f10aea8254a\
                     242c39caba603723a4b3bb543668a610\
                     f090ec0cda923b7cb05bd3639fd2f9f0\
                     57eb55897834258b3c8d162431036614\
                     5409467be8f51e303bb22f1bbec530b3\
                     c0f9d72b34342eb7ef129ff03a4e15fb\
                     43198b076cb238423d18587e67be7fba\
                     3c0579aa8468c7945562f250e5b63366\
                     8e6816472f5038005d48f11fd1e00cd5\
                     d6c4f028090e871620216d0092000de0",
                ),
            ],
        },
    ];

    test_kdf_a_common(interface::TpmiAlgHash::Sha512, key, &vecs);
}

#[test]
#[cfg(feature = "sha3_256")]
fn test_kdf_a_sha3_256() {
    let key = &cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20",
    );
    let vecs: [KdfATestVec; 2] = [
        KdfATestVec {
            output_bits: 640,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "db893813baa29a616fca847e740238b5\
                     5a8bfd71939a730608b8084963cd195c\
                     5a75175da3efb50b66c95064314bdc99\
                     c179de6c996928b70c80b67fa1aeb890\
                     f8db9ad799aef5eff5ad987dc05fef07",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "db24f816a60cce6c578b8090c7fdace4\
                     77a832777e4e9551c06ebc5935345984\
                     fd5ca28f777fd21f9636b39b06e831f0\
                     e8513015b5eeb3b63b06268cd4d72835\
                     9d15a521b8199e834278f5fee620c481",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "0cbb63b6f145f458ce3e7aa6fc82b110\
                     bc390c71745a1a003577d7f17b9cba61\
                     632f62b482dd72d1f1fb73776aec2578\
                     b7af33f93168ca9fc15b004022c7a0c9\
                     55d5a88d490fc4fe8d7601b0ea1fa915",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "fe18aeaf15926dd22c4766442220b453\
                     d592c71d5028c3fba591a6fd6a8667a8\
                     1e4679540b9f79bc4fc326d244cf3c47\
                     b380823197bf3bcd978ba1a68fbff636\
                     6cf5a2d7d02ba69bebd3075f96fa0317",
                ),
            ],
        },
        KdfATestVec {
            output_bits: 637,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "1364e9224052458c21a66af018f3ab4b\
                     86c73693174d7c5eb571b5ea2868c9b6\
                     f8f85b02e3739061c7b611b6e07c6a25\
                     6a6fa3baf56aadfafbc12b2734561182\
                     3d1a446d2ea4042feaf3f31bb82e03c7",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "1f09799e6c56b9e0252005c69b81f6f9\
                     3d6656a4d0d3084d62b3d2df6bdd5c36\
                     8740b4042aaa9338e3c724ca07bedcf3\
                     18cbbac3d2b73814c050c82e5f6a75f7\
                     781ec3f4fdf2130aacb7342c4a2d56bd",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "0992e6385c26d414d51f5c9a3896aa08\
                     13e6bdfee3ceb9213427f46a2987ac8c\
                     6301ffd55b3b8faa328037c3c2de9538\
                     560d102313ab6ebef3e8826b0dd2a674\
                     c3679d8817d3584e7b8fbf804d0bc5f7",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "0e04e144af638751bf28c808f708e0c6\
                     4545db9ac23f534a671e547c94bfed52\
                     df4fb7489b1c929d32da77803305ae2f\
                     85b305da273ad1dd16d3a574f558b6f2\
                     4bea15b613865f5a1ea85c32854722b4",
                ),
            ],
        },
    ];

    test_kdf_a_common(interface::TpmiAlgHash::Sha3_256, key, &vecs);
}

#[test]
#[cfg(feature = "sha3_384")]
fn test_kdf_a_sha3_384() {
    let key = &cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20\
         2122232425262728292a2b2c2d2e2f30",
    );
    let vecs: [KdfATestVec; 2] = [
        KdfATestVec {
            output_bits: 960,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "e9261e0f3f754cf94d5f824b26233948\
                     827ecbbaf3a292be21fb44604a7ce904\
                     51cae10eec46b7954748b39be14f668d\
                     7618b03dda717c6053901e716f9711cc\
                     66c52dedfcd717a7ea62dfc82264083a\
                     3b6fbc4c55a116ace22e8506bc5ab6ed\
                     82e0bf183eb009de881e3207251e3ee7\
                     31113caadc9f9493",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "ebd425aa1d0a8ce843c6b6d7b08170ff\
                     1851cdb3187a9df22cc96f62827d8ef2\
                     e2c176b99531182acf6aec5d20b6c5a5\
                     1bcea4f0a1f3d772b429a38fc742154d\
                     be7c2c2c6a0936054a76b43e73d5f125\
                     95d9eeb4f71d0d13b9a688d12e9a4a3e\
                     71ec07fd849408299001fd0ff25e6375\
                     188efb15de022fd2",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "45ca53d0df73e3376b9782779cec946f\
                     a8bc016e486c979c076c0b1ee7654070\
                     43659c095aecafa0138b9399bb55e7b7\
                     ce9148c67ff57fe57ce81fad932d04b2\
                     83cf18506e79e16d84dffc6cf57b7ac7\
                     8cb18d924eb9fc5a636fe5570b320d71\
                     bb373bceac65b6541ebe75c6840c8fef\
                     30b29685d7059ebc",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "5ccdd0ed4acbb038c552fa572140f549\
                     11c2595512eef104f79457ffc8edae34\
                     355db8da382031f6d9626f78b4cce46e\
                     2ba2a1ad6e8742ca3309e033456fdb34\
                     7974a775b10dfaaf3900ae48cd30de85\
                     82404b499dbc6ba2fca5c55c7f8bf9cb\
                     989a91b8efa33a1772a1948f850828a9\
                     41104a4a47854805",
                ),
            ],
        },
        KdfATestVec {
            output_bits: 957,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "064ec199849a7e245d06f1d81738fa5c\
                     99c7c7b70be42113834563e680855980\
                     1340e7de9e8928f4b6018392753e1909\
                     8e9731de03b899ff7187808447197c72\
                     c772629aa866de5289d3dfae9f7ed3a7\
                     d926e720b1caaae11457b86f004d247e\
                     b6fde358a1d6bbc17ee00e299262e261\
                     0488e51e2f16d327",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "1c18bfbf1427e1aefb662939cc95e65f\
                     8d19d511b2e22ba7bce37de55bfb5bf9\
                     4092f03759b44c02dc28310914f55fac\
                     c6d639e505c9ebefed7769e3ef984e50\
                     7fe90c505122784630cc87f3b03c0d95\
                     eb2cfa6ac497fc36dece788f695454b8\
                     f0f4f248cbd315235d29add6367528cb\
                     2e3149afec7a151a",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "004d9051b4e6cfc6c321a039b8815dec\
                     0c9d00173713d6bab316d5f44f010183\
                     08838f19d6350fda54e774e17f0f21cf\
                     14f047091524c051284636a46b9dabcc\
                     972fc7e23c5a45a5aecfddbedb9b2a7a\
                     40dcb14c1feced6617861b20bf952118\
                     144a7ea92d311413f738d6477340833e\
                     5266bcda1e472e48",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "09ff61c854ac6cc2d43292ce545ff8fc\
                     6a96444b0cac3872bb3d8e02c59f17e5\
                     3c59de6c8326f701ba759598bad8767c\
                     022a31ff5e9888d4448ec45f0f0911c9\
                     054f90439afb3a0556113805c0f97639\
                     042951c6c57951f0552e4432100eec61\
                     15eda8d76200cccb3d421b0d9efd31b8\
                     9f58ce423214e4bf",
                ),
            ],
        },
    ];

    test_kdf_a_common(interface::TpmiAlgHash::Sha3_384, key, &vecs);
}

#[test]
#[cfg(feature = "sha3_512")]
fn test_kdf_a_sha3_512() {
    let key = &cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20\
         2122232425262728292a2b2c2d2e2f30\
         3132333435363738393a3b3c3d3e3f40",
    );
    let vecs: [KdfATestVec; 2] = [
        KdfATestVec {
            output_bits: 1280,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "2e92ea598e2f2aa624a38ab2e17d5821\
                     51099f057dbaf9798ad1ad7f71ce5732\
                     be83630a719508440f3bbe2c2978cfcf\
                     cbec78541eccafb47c16f7974aa146ee\
                     7ebb8e03c4a193990f4fb66ce03bf287\
                     fcb3d7bab29d6c55762f62c122f8ff73\
                     0d77a046d5d9e9362dacc44e85987b7d\
                     de692f8cc678ce9b70e0752e307c3c84\
                     97c89631c59c334212bced96dd1396ae\
                     fcef5b70394be053b229e959b3ee2a70",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "ef9cd2a862fa14c585c1a21f2fa85fa8\
                     184d6c6fbf46133e6375fae6f6126d62\
                     af0afc76bd33b57671b81707618e8b46\
                     d5c9ba0c6b4c87e9a43d699b3543b414\
                     ae1ef3baf0530c7b9908faaf0fc505b7\
                     ffc1baa13464d0f6b17a8928c89bacf5\
                     56b8d76cf743f386d7f7f7c234987226\
                     8b91218069eb9b0033b5c6850c6bb0af\
                     b8c280b0fb79efad815431cd9bdfa560\
                     86be25d5d3535eea5fbaa7c7b6161e06",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "47b44f53903b687e4c329867547ee68e\
                     19ee074143f9bec9a36b4b5301c82e8b\
                     f264e135ef85dacc9a4219a59fde1d4c\
                     45e2b5d650b364ba674d9a1a70cbf22b\
                     57d307c743f1191468a0bc9002eb5ed7\
                     95a17c1fcecdc424c0274207997997cd\
                     3be05d2862e7c90f75a6d1a5d88656b7\
                     3e44d2b59cca5b727d441ef15cbf4af0\
                     a38db184c988376bb2e3e400b16f71b4\
                     3c2bd39d5d6db7ae846b4a6ac89312a0",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "2c4757a1b050ed4dda9bbd619f7565cb\
                     0e70fa41f1a049cf7d5854d48e3b288f\
                     ba7ffd851f79a8da8cf19c2c8c209995\
                     fe2829c82ade638c43e9afdf91eebad1\
                     7f429b510012cd8b231688284762ed50\
                     6552be988506e5e6236f291f48c7ab4b\
                     d101252cc42a8cbd8dac0d9f37d35a95\
                     21fbb8cf1205ef7b2567d58f59fb6849\
                     5b4abaffccbb638697bd7a9a94dbcb1b\
                     5cc169757f617ef9ae6a4a3df9e7ec91",
                ),
            ],
        },
        KdfATestVec {
            output_bits: 1277,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "135eeee72cfbcd6d8d13c966a772d1a8\
                     3d0e6eb21d597e96fedb03fae8fa7a0f\
                     be11739912a2b2d8bf1a231fe1ecc95d\
                     91322a5591fd3c6bcdd338719405e55b\
                     5330b5882daed24bb682d2ea3780a61e\
                     c5a342548fa785f80cc8e925067cc9a9\
                     2882827e67e14e355645403f86f4b334\
                     df52905e5c1677ccdbb59e8fe127984f\
                     defcad9eebf2bbc836f443676e8220f1\
                     cca4c93d9dda71baeaea00956f1bf056",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "1c1273ab5dda1924bca5f627e09b0ffa\
                     332380bb121bf1f6103ac9d12ed2ee03\
                     5caafe00f2d88bf767aceb49e048942d\
                     aa027bc659900100bb203881fcac69cf\
                     5153f12a3862d1084479b00dda169e91\
                     c31fd2952fee97e7662073ffb38388cb\
                     a57e2d62bde9afb65cce6d8a4bea30b9\
                     a9fefec68ddc8fe765ff88db57ad92c0\
                     e92bcb3eac1ac7460fd5ffed36b298d8\
                     6ec325764987bf799b3ea95b00dd8ce5",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "0acfcfc22a83b7b4b6c034db40d1c053\
                     1fafe265b463988880d84a8e3aed9f1e\
                     17598db2ebd95bdac92a6e1755e3f252\
                     28c58f1dc7ac27cfcf5132211f241cbb\
                     5ddb55927c07d0e917318afe1022dec8\
                     ff7b565135761ce3fe8a457223ef4e0f\
                     4f5cabe9a0a4fc5192ad364cb52fccf6\
                     17d1264035dc53122f5e10f336127ae9\
                     b5bf2e18bdeb5f6cf64197b13d4f7ec7\
                     dafde0fdd7b86065327076ed985cdf22",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "0193ceb751f06888eb37c7ad9af98df3\
                     a21b98b3c60e157e42b42a485d46a2d9\
                     a10bb95a1199da210afe75d73cb6671d\
                     aabf8de557abdef2180121acd0135cbd\
                     6ebd1bc3496f464408d6e22d393a93c0\
                     d37d91950958519c8f8538a5c886af9c\
                     ea72bd69f1dc0557f97e20a6351f9cce\
                     aeb4431e8153d53b249b003f8bd952cc\
                     9e0ccf920fb8bcc491b3e13684948ac1\
                     0561e539185b4a5e51fe0b5fa8109aef",
                ),
            ],
        },
    ];

    test_kdf_a_common(interface::TpmiAlgHash::Sha3_512, key, &vecs);
}
