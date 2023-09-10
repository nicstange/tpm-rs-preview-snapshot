use crate::crypto::{hash, io_slices, kdf};
use crate::interface;

pub struct RFC8017Mgf1 {
    hash_instance: Option<hash::HashInstance>,
    block_len: usize,
    counter: u32,
    counter_last: u32,
}

impl RFC8017Mgf1 {
    pub fn new(
        hash_alg: interface::TpmiAlgHash,
        total_output_len: usize,
        seed: &[u8],
    ) -> Result<Self, interface::TpmErr> {
        let block_len = hash::hash_alg_digest_len(hash_alg) as usize;
        let counter_last = total_output_len.saturating_sub(1) / block_len as usize;
        let counter_last = u32::try_from(counter_last).map_err(|_| tpm_err_rc!(NO_RESULT))?;

        let mut hash_instance = hash::HashInstance::new(hash_alg);
        hash_instance.update(io_slices::IoSlices::new(&mut [Some(seed)]));
        Ok(Self {
            hash_instance: Some(hash_instance),
            block_len,
            counter: 0,
            counter_last,
        })
    }
}

impl kdf::FixedBlockOutputKdf for RFC8017Mgf1 {
    fn block_len(&self) -> usize {
        self.block_len
    }

    fn max_remaining_len(&self) -> Option<usize> {
        let total_len = self.counter_last as usize * self.block_len;
        let total_len = total_len.saturating_add(self.block_len);
        let generated_len = self.counter as usize * self.block_len;
        Some(total_len - generated_len)
    }

    fn generate_block(&mut self, output: &mut [u8]) -> Result<usize, interface::TpmErr> {
        debug_assert_eq!(output.len(), self.block_len);

        let mut hash_instance = match &self.hash_instance {
            Some(hash_instance) => {
                // If producing the last block, the hash_instance can be stolen, otherwise it
                // needs to get cloned.
                if self.counter != self.counter_last {
                    hash_instance.clone()
                } else {
                    self.hash_instance.take().unwrap()
                }
            }
            None => {
                // The last block has already been produced.
                return Err(tpm_err_internal!());
            }
        };

        let counter: [u8; 4] = self.counter.to_be_bytes();
        self.counter = self.counter.wrapping_add(1);
        hash_instance.update(io_slices::IoSlices::new(&mut [Some(&counter)]));
        hash_instance.finalize_into(output);
        Ok(self.block_len)
    }
}

#[cfg(test)]
const TEST_SEED: [u8; 8] = cmpa::hexstr::bytes_from_hexstr_cnst::<8>("6d67663153656564");

#[cfg(test)]
fn test_rfc8017_mgf1_common(hash_alg: interface::TpmiAlgHash, expected: &[u8]) {
    extern crate alloc;
    use crate::crypto::kdf::VariableChunkOutputKdf;
    use alloc::vec;

    use super::BufferedFixedBlockOutputKdf;

    let block_len = hash::hash_alg_digest_len(hash_alg) as usize;
    assert_eq!(expected.len(), 2 * block_len);

    // Request less than the actual output length, the Mgf1 will still generate the
    // full last block.
    let mut kdf = BufferedFixedBlockOutputKdf::new(
        RFC8017Mgf1::new(hash_alg, block_len + 1, &TEST_SEED).unwrap(),
    )
    .unwrap();

    let mut generated = vec![0u8; expected.len()];
    kdf.generate_chunk(&mut io_slices::IoSlicesMut::new(&mut [Some(
        &mut generated,
    )]))
    .unwrap();
    // The internal hash_instance should have been consumed in the course of
    // generating the last block.
    assert!(kdf.block_kdf.hash_instance.is_none());
    assert_eq!(generated, expected);
}

#[test]
#[cfg(feature = "sha1")]
fn test_rfc8017_mgf1_sha1() {
    let expected = cmpa::hexstr::bytes_from_hexstr_cnst::<40>(
        "60cb6f905f77ff3ed4fe3b04e274a80d760b6d5cf6f99847b46055d56f937b97\
         9b9a0db3b5719f0a"
    );
    test_rfc8017_mgf1_common(interface::TpmiAlgHash::Sha1, &expected);
}

#[test]
#[cfg(feature = "sha256")]
fn test_rfc8017_mgf1_sha256() {
    let expected = cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
        "b09c6bfc0594f0a3cca25ca1b23581d89b6cedf8c52a3b40f732951d860f5129\
         5644e56733d6a0879330e82f19393f9df99f6328da1b36fb2ded58dd57fb2c61"
    );
    test_rfc8017_mgf1_common(interface::TpmiAlgHash::Sha256, &expected);
}

#[test]
#[cfg(feature = "sha384")]
fn test_rfc8017_mgf1_sha384() {
    let expected = cmpa::hexstr::bytes_from_hexstr_cnst::<96>(
        "79a293a805bf3e5bcc52779fac93b09142da7ea527de45d296ed8269203058a3\
         95068a005f8719429322dbb6b6a529aad3f0ff683746e4573ead47a264426f93\
         7c3d03ce7f38cdfb44ce7235c93cc915cf4ae77f94da25e916c05d9d83d4e563"
    );
    test_rfc8017_mgf1_common(interface::TpmiAlgHash::Sha384, &expected);
}

#[test]
#[cfg(feature = "sha512")]
fn test_rfc8017_mgf1_sha512() {
    let expected = cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
        "204a033bd0356ac8f8132fab2097ce557a66decbb9351715d41bfeaf8c2efe93\
         588ecb554e10c1be134ce1fddd9c2e7480d4ba258ed8bb763da5d8e8c71a7154\
         20677162f8681cb97c9f086b6009a0f05b252db92504d1ae858823c1d1005f98\
         9cc36c549f7972a9c3400c349d45d4973e89f36addbd060a5fc4956e6805a59b"
    );
    test_rfc8017_mgf1_common(interface::TpmiAlgHash::Sha512, &expected);
}

#[test]
#[cfg(feature = "sha3_256")]
fn test_rfc8017_mgf1_sha3_256() {
    let expected = cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
        "060020d407324ead6beb2ac3052429ebc043bb4b36cdf88655a8566707daf46a\
         a517ecfc5ddcb48b1fca5acd843ce7b61c90be807f726ef030f4e0a163793de1"
    );
    test_rfc8017_mgf1_common(interface::TpmiAlgHash::Sha3_256, &expected);
}

#[test]
#[cfg(feature = "sha3_384")]
fn test_rfc8017_mgf1_sha3_384() {
    let expected = cmpa::hexstr::bytes_from_hexstr_cnst::<96>(
        "b0372bfb7527e09757040152a33115eb409bc3e544450f6706aa1f61df817c02\
         bc5587c02b1d5f7be4a0d0c7e3a432e7cdedd7c3b0b0917d2bbbcf8cda3f893a\
         2eb09a6bfbf185abba5123fdb98469c5fbb2fae4e576f5055f945b208121f75f"
    );
    test_rfc8017_mgf1_common(interface::TpmiAlgHash::Sha3_384, &expected);
}

#[test]
#[cfg(feature = "sha3_512")]
fn test_rfc8017_mgf1_sha3_512() {
    let expected = cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
        "4ca00646487530687e4ce48ddb0b8736abec59275b510413514843eb64834af3\
         855d34b2ca049c8b93b5ea0bc13cff01c26f12e66a0489ad0340c45ba6bd8c14\
         b440591a1d286dd95dcb07ae227931491fbfab10c3bd65768ff3242674a18c5d\
         0d698ec3be6af7355e9191a57f9a1a0abe743cd0a5deb2cb4bd5dd71d167bc16"
    );
    test_rfc8017_mgf1_common(interface::TpmiAlgHash::Sha3_512, &expected);
}
