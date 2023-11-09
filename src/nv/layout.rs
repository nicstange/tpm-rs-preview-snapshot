use crate::crypto::symcipher;
use crate::interface;
use core::{cmp, convert, marker, ops};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AllocBlockCount {
    count: u64,
}

impl convert::From<u64> for AllocBlockCount {
    fn from(value: u64) -> Self {
        Self { count: value }
    }
}

impl convert::From<AllocBlockCount> for u64 {
    fn from(value: AllocBlockCount) -> Self {
        value.count
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PhysicalAllocBlockIndex {
    index: u64,
}

impl convert::From<u64> for PhysicalAllocBlockIndex {
    fn from(value: u64) -> Self {
        Self { index: value }
    }
}

impl convert::From<PhysicalAllocBlockIndex> for u64 {
    fn from(value: PhysicalAllocBlockIndex) -> Self {
        value.index
    }
}

impl ops::Add<AllocBlockCount> for PhysicalAllocBlockIndex {
    type Output = Self;

    fn add(self, rhs: AllocBlockCount) -> Self::Output {
        Self {
            index: self.index.checked_add(rhs.count).unwrap(),
        }
    }
}

impl ops::AddAssign<AllocBlockCount> for PhysicalAllocBlockIndex {
    fn add_assign(&mut self, rhs: AllocBlockCount) {
        self.index = self.index.checked_add(rhs.count).unwrap();
    }
}

impl ops::Sub<Self> for PhysicalAllocBlockIndex {
    type Output = AllocBlockCount;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::Output {
            count: self.index.checked_sub(rhs.index).unwrap(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct LogicalAllocBlockIndex {
    index: u64,
}

impl convert::From<u64> for LogicalAllocBlockIndex {
    fn from(value: u64) -> Self {
        Self { index: value }
    }
}

impl convert::From<LogicalAllocBlockIndex> for u64 {
    fn from(value: LogicalAllocBlockIndex) -> Self {
        value.index
    }
}

impl ops::Add<AllocBlockCount> for LogicalAllocBlockIndex {
    type Output = Self;

    fn add(self, rhs: AllocBlockCount) -> Self::Output {
        Self {
            index: self.index.checked_add(rhs.count).unwrap(),
        }
    }
}

impl ops::AddAssign<AllocBlockCount> for LogicalAllocBlockIndex {
    fn add_assign(&mut self, rhs: AllocBlockCount) {
        self.index = self.index.checked_add(rhs.count).unwrap();
    }
}

impl ops::Sub<Self> for LogicalAllocBlockIndex {
    type Output = AllocBlockCount;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::Output {
            count: self.index.checked_sub(rhs.index).unwrap(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlockRange<I: Copy + cmp::Ord + ops::Add<C, Output = I> + ops::Sub<I, Output = C>, C: Copy> {
    b: I,
    e: I,
    _phantom_c: marker::PhantomData<C>,
}

impl<I: Copy + cmp::Ord + ops::Add<C, Output = I> + ops::Sub<I, Output = C>, C: Copy> BlockRange<I, C> {
    pub fn new(b: I, e: I) -> Self {
        debug_assert!(b < e);
        Self {
            b,
            e,
            _phantom_c: marker::PhantomData,
        }
    }

    pub fn begin(&self) -> I {
        self.b
    }

    pub fn end(&self) -> I {
        self.e
    }

    pub fn block_count(&self) -> C {
        self.e - self.b
    }

    pub fn overlaps_with(&self, other: &Self) -> bool {
        self.end() > other.begin() && self.begin() < other.end()
    }
}

impl<I: Copy + cmp::Ord + ops::Add<C, Output = I> + ops::Sub<I, Output = C>, C: Copy> convert::From<(I, C)>
    for BlockRange<I, C>
{
    fn from(value: (I, C)) -> Self {
        Self {
            b: value.0,
            e: value.0 + value.1,
            _phantom_c: marker::PhantomData,
        }
    }
}

pub type PhysicalAllocBlockRange = BlockRange<PhysicalAllocBlockIndex, AllocBlockCount>;

pub type LogicalAllocBlockRange = BlockRange<LogicalAllocBlockIndex, AllocBlockCount>;

pub struct ImageLayout {
    /// Base-2 logarithm of the Allocation Block size, specified in units of
    /// 128B multiples.
    ///
    /// Allocation Blocks are the basic units of block allocations, all other
    /// sizes are specified in terms of Allocation Blocks.
    pub allocation_block_size_128b_log2: u8,

    /// Base-2 logarithm of the IO Block size, specified in units of
    /// [`Allocation Blocks`](Self::allocation_block_size_128b_log2).
    ///
    /// The "IO Block" is defined to be the defined to equal the minimum unit of
    /// backend IO assumed not to ever clobber unrelated IO Blocks in the
    /// course of writing.
    pub io_block_allocation_blocks_log2: u8,

    /// Base-2 logarithm of the Authentication Tree Node size as specified in
    /// units of [`IO Blocks`](Self::io_block_allocation_blocks_log2).
    ///
    /// Authentication Tree, i.e. Merkle Tree, nodes store digest over child
    /// nodes back to back. Increasing the node size increases the
    /// inner-tree fanout ratio, at the cost of increasing the efforts for
    /// (re-)hashing a single child node for validation or update respectively.
    pub auth_tree_node_io_blocks_log2: u8,

    /// Base-2 logarithm of the range covered by a single Authentication Tree
    /// leaf node digest entry, i.e. a "Authentication Tree Data Block", as
    /// specified in units of [`Allocation
    /// Blocks`](Self::allocation_block_size_128b_log2).
    ///
    /// Note that the allocation bitmap is managed in blocks of that size, so
    /// that an Authentication Tree leaf node digest entry authenticating the
    /// bitmap always would authenticate it exclusively and nothing else.
    /// This is crucial for bootstrapping the authentication in a
    /// CCA-defensive manner, because in the general case an examination of the
    /// allocation bitmap itself would be needed for validating an
    /// Authentication Tree leaf digest entry (for handling unallocated
    /// allocation blocks in the to be authenticated range properly when
    /// calcualting the digest). This constraint breaks the cycle and enables
    /// the bootstrapping code to authenticate the allocation bitmap's contents
    /// **before** decrypting it.
    pub auth_tree_data_block_allocation_blocks_log2: u8,

    /// Base-2 logarithm of the Index B-Tree node size as specified in units of
    /// [`Allocation Blocks`](Self::allocation_block_size_128b_log2).
    ///
    /// Must be >= the IV size + 8 * 8 + (8 - 1) * 20 so that the first node (in
    /// symmetric order) is guaranteed to always store the four special file
    /// entries, as per the minumum B-Tree node fill level.
    pub index_tree_node_allocation_blocks_log2: u8,

    /// The Hash algorithm to use for NV image contents authentication.
    ///
    /// Overall authentication security strength is determined by the security
    /// strength in regard to collision resistance (c.f. NIST SP 800-57,
    /// part 1, rev. 57, table 3) of the hash function as well as by the
    /// HMAC construction specified by means of
    /// [`auth_hmac_hash_alg`](Self::auth_tree_hash_alg).
    /// As a rule of thumb, the [`auth_tree_hash_alg`](Self::auth_tree_hash_alg)
    /// digest size in bits should be no less than twice the targeted
    /// overall security strength.
    pub auth_tree_hash_alg: interface::TpmiAlgHash,

    /// The HMAC hash algorithm to use for NV image contents authentication.
    ///
    /// Overall authentication security strength is determined by the this HMAC
    /// construction (c.f. NIST SP 800-57, part 1, rev. 57, table 3), as
    /// well as by the [`auth_tree_hash_alg`](Self::auth_tree_hash_alg) hash
    /// used for the Authentication Tree digests. As a rule of thumb, the
    /// digest size of the hash used for the HMACs should be no
    /// less than the targeted overall security strength.
    pub auth_hmac_hash_alg: interface::TpmiAlgHash,

    /// Hash algorithm to use for CCA-protection HMACs.
    ///
    /// For defending against Chosen Ciphertext Attacks (CCA) at an early stage
    /// when still bootstrapping the "full" authentication, HMACs are used
    /// in various places, namely for
    /// - the contents of the first (in symmetric order) index B-Tree node,
    /// - the extents and, if needed for the Journal, contents of the Allocation
    ///   Bitmap file,
    /// - the extents of the Authentication Tree file,
    /// - the extents of the Journal file.
    ///
    /// For clarification, it should be stressed that the sole purpose of these
    /// HMACs is to restrict an attacker in his ability to craft arbitrary
    /// ciphertexts and send them to the NV engine for decryption, by
    /// rejecting (with overwhelming probability) those that had not been
    /// created by the NV engine respectively someone with knowledge of the
    /// NV image key somewhen before. They do not, in any way, provide any
    /// sort of image content authentication.
    ///
    /// For the time being, [`cca_hmac_hash_alg`](Self::cca_hmac_hash_alg) is
    /// forced to equal [`auth_hmac_hash_alg`](Self::auth_hmac_hash_alg) for
    /// maximum security. However, as the CCA protection HMACs are stored
    /// inline with the protected data structures and might consume a
    /// significant portion of space, and given that that the CCA model might
    /// not be of actual or limited concern for every real world application
    /// use case, this constraint might get relaxed in the future. Even more
    /// so as domain specific encryption keys are being used for the
    /// CCA-protected entities, the latter of which, by themselves, might be of
    /// limited value if revealed.
    pub preauth_cca_mitigation_hmac_hash_alg: interface::TpmiAlgHash,

    /// Block cipher to use in CFB mode for encryption throughout.
    pub block_cipher_alg: symcipher::SymBlockCipherAlg,
}
