// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use super::{cache, error, extents, index, keys, layout};
use super::{chip, chunked_io_region};
use crate::crypto::{ct_cmp, hash, io_slices};
use crate::interface;
use crate::sync_types;
use crate::utils;
use alloc::{sync, vec};
use core::{convert, future, marker, mem, ops, pin, slice, task};
use ops::DerefMut as _;
use utils::bitmanip::{BitManip as _, UBitManip as _};
use utils::{asynchronous, cfg_zeroize};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct AuthTreeDataAllocBlockIndex {
    index: u64,
}

impl convert::From<u64> for AuthTreeDataAllocBlockIndex {
    fn from(value: u64) -> Self {
        Self { index: value }
    }
}

impl convert::From<AuthTreeDataAllocBlockIndex> for u64 {
    fn from(value: AuthTreeDataAllocBlockIndex) -> Self {
        value.index
    }
}

impl ops::Add<layout::AllocBlockCount> for AuthTreeDataAllocBlockIndex {
    type Output = Self;

    fn add(self, rhs: layout::AllocBlockCount) -> Self::Output {
        Self {
            index: self.index.checked_add(u64::from(rhs)).unwrap(),
        }
    }
}

impl ops::AddAssign<layout::AllocBlockCount> for AuthTreeDataAllocBlockIndex {
    fn add_assign(&mut self, rhs: layout::AllocBlockCount) {
        self.index = self.index.checked_add(u64::from(rhs)).unwrap();
    }
}

impl ops::Sub<Self> for AuthTreeDataAllocBlockIndex {
    type Output = layout::AllocBlockCount;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::Output::from(self.index.checked_sub(rhs.index).unwrap())
    }
}

type AuthTreeDataAllocBlockRange =
    layout::BlockRange<AuthTreeDataAllocBlockIndex, layout::AllocBlockCount>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AuthTreeDataBlockCount {
    count: u64,
}

impl convert::From<u64> for AuthTreeDataBlockCount {
    fn from(value: u64) -> Self {
        Self { count: value }
    }
}

impl convert::From<AuthTreeDataBlockCount> for u64 {
    fn from(value: AuthTreeDataBlockCount) -> Self {
        value.count
    }
}

impl ops::Add<AuthTreeDataBlockCount> for AuthTreeDataBlockCount {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            count: self.count.checked_add(rhs.count).unwrap(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct AuthTreeDataBlockIndex {
    index: u64,
}

impl AuthTreeDataBlockIndex {
    fn new(
        auth_tree_data_allocation_block_index: AuthTreeDataAllocBlockIndex,
        auth_tree_data_block_allocation_blocks_log2: u8,
    ) -> Self {
        Self {
            index: u64::from(auth_tree_data_allocation_block_index)
                >> auth_tree_data_block_allocation_blocks_log2,
        }
    }
}

impl convert::From<u64> for AuthTreeDataBlockIndex {
    fn from(value: u64) -> Self {
        Self { index: value }
    }
}

impl convert::From<AuthTreeDataBlockIndex> for u64 {
    fn from(value: AuthTreeDataBlockIndex) -> Self {
        value.index
    }
}

impl ops::Add<AuthTreeDataBlockCount> for AuthTreeDataBlockIndex {
    type Output = Self;

    fn add(self, rhs: AuthTreeDataBlockCount) -> Self::Output {
        Self {
            index: self.index.checked_add(u64::from(rhs)).unwrap(),
        }
    }
}

impl ops::AddAssign<AuthTreeDataBlockCount> for AuthTreeDataBlockIndex {
    fn add_assign(&mut self, rhs: AuthTreeDataBlockCount) {
        self.index = self.index.checked_add(u64::from(rhs)).unwrap();
    }
}

impl ops::Sub<Self> for AuthTreeDataBlockIndex {
    type Output = AuthTreeDataBlockCount;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::Output::from(self.index.checked_sub(rhs.index).unwrap())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct AuthTreeNodeId {
    /// First Authentication Tree Data block authenticated by the node's
    /// leftmost leaf descandant.
    covered_auth_tree_data_blocks_begin: AuthTreeDataBlockIndex,
    /// Node level, counted zero-based from bottom.
    level: u8,
}

impl AuthTreeNodeId {
    fn new(
        covered_auth_tree_data_block_index: AuthTreeDataBlockIndex,
        level: u8,
        digests_per_node_log2: u8,
    ) -> Self {
        let level_covered_index_mask_bits = ((level + 1) * digests_per_node_log2) as u32;
        let covered_auth_tree_data_blocks_begin = if level_covered_index_mask_bits < u64::BITS {
            u64::from(covered_auth_tree_data_block_index)
                & !u64::trailing_bits_mask(level_covered_index_mask_bits)
        } else {
            0
        };
        Self {
            covered_auth_tree_data_blocks_begin: AuthTreeDataBlockIndex::from(
                covered_auth_tree_data_blocks_begin,
            ),
            level,
        }
    }

    fn last_covered_auth_tree_data_block(
        &self,
        digests_per_node_log2: u8,
    ) -> AuthTreeDataBlockIndex {
        let level_covered_index_mask_bits = ((self.level + 1) * digests_per_node_log2) as u32;
        let last_covered_auth_tree_data_block = if level_covered_index_mask_bits < u64::BITS {
            let level_covered_index_mask = u64::trailing_bits_mask(level_covered_index_mask_bits);
            debug_assert_eq!(
                u64::from(self.covered_auth_tree_data_blocks_begin) & level_covered_index_mask,
                0
            );
            u64::from(self.covered_auth_tree_data_blocks_begin) | level_covered_index_mask
        } else {
            u64::MAX
        };
        AuthTreeDataBlockIndex::from(last_covered_auth_tree_data_block)
    }
}

struct AuthTreeNode {
    data: vec::Vec<u8>,
}

/// Map physical [Allocation
/// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) indices into
/// the Authentication Tree Data domain and vice versa.
///
/// The Authentication Trees don't verify their own storage, therefore the
/// authenticated data is not contiguous on the physical storage, but
/// interspersed with Authentication Tree node storage extents. The
/// [`AuthTreeDataAllocationBlocksMap`](Self) provides a means for translating
/// between physical addresses of [Allocation
/// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) subject to
/// authentication and contiguous Authentication Tree Data domain indices.
struct AuthTreeDataAllocationBlocksMap {
    /// Authentication Tree storage extents represented as
    /// `(physical_end, accumulated_block_count)`, in units of allocation
    /// blocks, ordered by `physical_end`, with `accumulated_block_count`
    /// being equal to the sum of all allocation blocks allocated to the
    /// Authentication Tree node storage up to `physical_end`.
    auth_tree_storage_physical_extents: vec::Vec<(u64, u64)>,
}

impl AuthTreeDataAllocationBlocksMap {
    fn new(logical_auth_tree_extents: &extents::LogicalExtents) -> Result<Self, interface::TpmErr> {
        let mut auth_tree_storage_physical_extents = vec::Vec::new();
        auth_tree_storage_physical_extents
            .try_reserve_exact(logical_auth_tree_extents.len())
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        for logical_extent in logical_auth_tree_extents.iter() {
            let physical_range = logical_extent.physical_range();
            // Temporarily add in unsorted order and with this
            // entry's block count only, the list will be sorted and the latter subsequently
            // accumulated below.
            auth_tree_storage_physical_extents.push((
                u64::from(physical_range.end()),
                u64::from(physical_range.block_count()),
            ));
        }
        auth_tree_storage_physical_extents.sort_unstable_by_key(|e| e.0);

        let mut accumulated_block_count = 0;
        for e in auth_tree_storage_physical_extents.iter_mut() {
            accumulated_block_count += e.1;
            e.1 = accumulated_block_count;
        }

        Ok(Self {
            auth_tree_storage_physical_extents,
        })
    }

    fn map_physical_to_data_allocation_blocks(
        &self,
        physical_range: &layout::PhysicalAllocBlockRange,
    ) -> AuthTreeDataAllocBlockRange {
        // Convert the physical allocation block index to an Authentication Tree data
        // one by subtracting from the former the space occupied by any
        // Authentication Tree Nodes located before it in the image.
        let i = self
            .auth_tree_storage_physical_extents
            .partition_point(|e| e.0 <= u64::from(physical_range.begin()));
        let auth_tree_storage_accumulated_block_count = if i != 0 {
            self.auth_tree_storage_physical_extents[i - 1].1
        } else {
            0
        };
        // The physical allocation block range shall not intersect with any
        // Authentication Tree nodes.
        if i < self.auth_tree_storage_physical_extents.len() {
            let next = self.auth_tree_storage_physical_extents[i];
            let next_begin = next.0 - (next.1 - auth_tree_storage_accumulated_block_count);
            let next_begin = layout::PhysicalAllocBlockIndex::from(next_begin);
            debug_assert!(next_begin >= physical_range.end());
        }
        AuthTreeDataAllocBlockRange::from((
            AuthTreeDataAllocBlockIndex::from(
                u64::from(physical_range.begin()) - auth_tree_storage_accumulated_block_count,
            ),
            physical_range.block_count(),
        ))
    }

    fn iter_data_range_mapping(
        &self,
        data_range: &AuthTreeDataAllocBlockRange,
    ) -> AuthTreeDataAllocationBlocksMapIterator<'_> {
        let map_index = self
            .auth_tree_storage_physical_extents
            .partition_point(|e| e.0 - e.1 <= u64::from(data_range.begin()));
        AuthTreeDataAllocationBlocksMapIterator {
            map: self,
            map_index,
            next_data_allocation_block: data_range.begin(),
            data_allocation_blocks_end: data_range.end(),
        }
    }
}

struct AuthTreeDataAllocationBlocksMapIterator<'a> {
    map: &'a AuthTreeDataAllocationBlocksMap,
    map_index: usize,
    next_data_allocation_block: AuthTreeDataAllocBlockIndex,
    data_allocation_blocks_end: AuthTreeDataAllocBlockIndex,
}

impl<'a> Iterator for AuthTreeDataAllocationBlocksMapIterator<'a> {
    type Item = (AuthTreeDataAllocBlockRange, layout::PhysicalAllocBlockIndex);

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_data_allocation_block == self.data_allocation_blocks_end {
            return None;
        }

        let data_allocation_blocks_begin = u64::from(self.next_data_allocation_block);
        let auth_tree_storage_accumulated_block_count = if self.map_index > 0 {
            let e = self.map.auth_tree_storage_physical_extents[self.map_index - 1];
            debug_assert!(e.0 - e.1 <= data_allocation_blocks_begin);
            e.1
        } else {
            0
        };
        let data_allocation_blocks_end =
            if self.map_index < self.map.auth_tree_storage_physical_extents.len() {
                let e = self.map.auth_tree_storage_physical_extents[self.map_index];
                if e.0 - e.1 < u64::from(self.data_allocation_blocks_end) {
                    self.map_index += 1;
                    e.0 - e.1
                } else {
                    u64::from(self.data_allocation_blocks_end)
                }
            } else {
                u64::from(self.data_allocation_blocks_end)
            };
        self.next_data_allocation_block =
            AuthTreeDataAllocBlockIndex::from(data_allocation_blocks_end);

        let physical_allocation_blocks_begin =
            data_allocation_blocks_begin + auth_tree_storage_accumulated_block_count;

        Some((
            AuthTreeDataAllocBlockRange::new(
                AuthTreeDataAllocBlockIndex::from(data_allocation_blocks_begin),
                self.next_data_allocation_block,
            ),
            layout::PhysicalAllocBlockIndex::from(physical_allocation_blocks_begin),
        ))
    }
}

#[test]
fn test_auth_tree_data_allocation_blocks_map_from_phys() {
    let mut logical_auth_tree_extents = extents::LogicalExtents::new();
    logical_auth_tree_extents
        .extend_by_physical(layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(1),
            layout::AllocBlockCount::from(1),
        )))
        .unwrap();
    logical_auth_tree_extents
        .extend_by_physical(layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(4),
            layout::AllocBlockCount::from(1),
        )))
        .unwrap();
    let map = AuthTreeDataAllocationBlocksMap::new(&logical_auth_tree_extents).unwrap();

    let auth_tree_data_range =
        map.map_physical_to_data_allocation_blocks(&layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(0),
            layout::AllocBlockCount::from(1),
        )));
    assert_eq!(u64::from(auth_tree_data_range.begin()), 0);
    assert_eq!(u64::from(auth_tree_data_range.end()), 1);

    let auth_tree_data_range =
        map.map_physical_to_data_allocation_blocks(&layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(2),
            layout::AllocBlockCount::from(1),
        )));
    assert_eq!(u64::from(auth_tree_data_range.begin()), 1);
    assert_eq!(u64::from(auth_tree_data_range.end()), 2);

    let auth_tree_data_range =
        map.map_physical_to_data_allocation_blocks(&layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(3),
            layout::AllocBlockCount::from(1),
        )));
    assert_eq!(u64::from(auth_tree_data_range.begin()), 2);
    assert_eq!(u64::from(auth_tree_data_range.end()), 3);

    let auth_tree_data_range =
        map.map_physical_to_data_allocation_blocks(&layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(2),
            layout::AllocBlockCount::from(2),
        )));
    assert_eq!(u64::from(auth_tree_data_range.begin()), 1);
    assert_eq!(u64::from(auth_tree_data_range.end()), 3);

    let auth_tree_data_range =
        map.map_physical_to_data_allocation_blocks(&layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(5),
            layout::AllocBlockCount::from(1),
        )));
    assert_eq!(u64::from(auth_tree_data_range.begin()), 3);
    assert_eq!(u64::from(auth_tree_data_range.end()), 4);

    let auth_tree_data_range =
        map.map_physical_to_data_allocation_blocks(&layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(6),
            layout::AllocBlockCount::from(1),
        )));
    assert_eq!(u64::from(auth_tree_data_range.begin()), 4);
    assert_eq!(u64::from(auth_tree_data_range.end()), 5);
}

#[test]
fn test_auth_tree_data_allocation_blocks_map_to_phys() {
    let mut logical_auth_tree_extents = extents::LogicalExtents::new();
    logical_auth_tree_extents
        .extend_by_physical(layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(1),
            layout::AllocBlockCount::from(1),
        )))
        .unwrap();
    logical_auth_tree_extents
        .extend_by_physical(layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(4),
            layout::AllocBlockCount::from(1),
        )))
        .unwrap();
    let map = AuthTreeDataAllocationBlocksMap::new(&logical_auth_tree_extents).unwrap();

    let mut mapped_auth_tree_data_range =
        map.iter_data_range_mapping(&AuthTreeDataAllocBlockRange::from((
            AuthTreeDataAllocBlockIndex::from(0),
            layout::AllocBlockCount::from(1),
        )));
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from((
                AuthTreeDataAllocBlockIndex::from(0),
                layout::AllocBlockCount::from(1),
            )),
            layout::PhysicalAllocBlockIndex::from(0)
        ))
    );
    assert!(mapped_auth_tree_data_range.next().is_none());

    let mut mapped_auth_tree_data_range =
        map.iter_data_range_mapping(&AuthTreeDataAllocBlockRange::from((
            AuthTreeDataAllocBlockIndex::from(0),
            layout::AllocBlockCount::from(2),
        )));
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from((
                AuthTreeDataAllocBlockIndex::from(0),
                layout::AllocBlockCount::from(1),
            )),
            layout::PhysicalAllocBlockIndex::from(0)
        ))
    );
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from((
                AuthTreeDataAllocBlockIndex::from(1),
                layout::AllocBlockCount::from(1),
            )),
            layout::PhysicalAllocBlockIndex::from(2)
        ))
    );
    assert!(mapped_auth_tree_data_range.next().is_none());

    let mut mapped_auth_tree_data_range =
        map.iter_data_range_mapping(&AuthTreeDataAllocBlockRange::from((
            AuthTreeDataAllocBlockIndex::from(1),
            layout::AllocBlockCount::from(2),
        )));
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from((
                AuthTreeDataAllocBlockIndex::from(1),
                layout::AllocBlockCount::from(2),
            )),
            layout::PhysicalAllocBlockIndex::from(2)
        ))
    );
    assert!(mapped_auth_tree_data_range.next().is_none());

    let mut mapped_auth_tree_data_range =
        map.iter_data_range_mapping(&AuthTreeDataAllocBlockRange::from((
            AuthTreeDataAllocBlockIndex::from(1),
            layout::AllocBlockCount::from(4),
        )));
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from((
                AuthTreeDataAllocBlockIndex::from(1),
                layout::AllocBlockCount::from(2),
            )),
            layout::PhysicalAllocBlockIndex::from(2)
        ))
    );
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from((
                AuthTreeDataAllocBlockIndex::from(3),
                layout::AllocBlockCount::from(2),
            )),
            layout::PhysicalAllocBlockIndex::from(5)
        ))
    );
    assert!(mapped_auth_tree_data_range.next().is_none());

    let mut mapped_auth_tree_data_range =
        map.iter_data_range_mapping(&AuthTreeDataAllocBlockRange::from((
            AuthTreeDataAllocBlockIndex::from(3),
            layout::AllocBlockCount::from(1),
        )));
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from((
                AuthTreeDataAllocBlockIndex::from(3),
                layout::AllocBlockCount::from(1),
            )),
            layout::PhysicalAllocBlockIndex::from(5)
        ))
    );
    assert!(mapped_auth_tree_data_range.next().is_none());

    let mut mapped_auth_tree_data_range =
        map.iter_data_range_mapping(&AuthTreeDataAllocBlockRange::from((
            AuthTreeDataAllocBlockIndex::from(4),
            layout::AllocBlockCount::from(1),
        )));
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from((
                AuthTreeDataAllocBlockIndex::from(4),
                layout::AllocBlockCount::from(1),
            )),
            layout::PhysicalAllocBlockIndex::from(6)
        ))
    );
    assert!(mapped_auth_tree_data_range.next().is_none());
}

#[repr(u8)]
enum AuthSubjectDataPrefix {
    AuthTreeRootNode = 1,
    AuthTreeDescendantNode = 2,
    AuthenticatedDataBlockAllocationBlock = 3,
    UnauthenticatedDataBlockAllocationBlock = 4,
}

pub struct AuthTree<ST: sync_types::SyncTypes, C: chip::NVChip> {
    chip: pin::Pin<sync::Arc<C>>,

    auth_tree_extents: extents::LogicalExtents,
    auth_tree_data_allocation_blocks_map: AuthTreeDataAllocationBlocksMap,

    digests_per_node_log2: u8,
    digests_per_node_minus_one_inv_mod_u64: u64,

    auth_tree_levels: u8,
    auth_tree_data_block_count: u64,

    auth_tree_node_cache: sync::Arc<cache::Cache<ST, AuthTreeNodeId, AuthTreeNode>>,

    /// Copied verbatim from [`ImageLayout`](layout::ImageLayout).
    auth_tree_hash_alg: interface::TpmiAlgHash,
    auth_tree_digest_len: u8,

    auth_hmac_hash_alg: interface::TpmiAlgHash,
    auth_hmac_digest: vec::Vec<u8>,
    auth_hmac_key: cfg_zeroize::Zeroizing<vec::Vec<u8>>,

    /// Copied verbatim from [`ImageLayout`](layout::ImageLayout).
    allocation_block_size_128b_log2: u8,
    /// Derived from from [`ImageLayout`](layout::ImageLayout).
    auth_tree_node_allocation_blocks_log2: u8,
    /// Copied verbatim  from [`ImageLayout`](layout::ImageLayout).
    auth_tree_data_block_allocation_blocks_log2: u8,
}

impl<ST: sync_types::SyncTypes, C: chip::NVChip> AuthTree<ST, C> {
    pub fn new(
        chip: pin::Pin<sync::Arc<C>>,
        keys: &keys::Keys<ST>,
        layout: &layout::ImageLayout,
        auth_tree_extents: extents::LogicalExtents,
        auth_hmac_digest: vec::Vec<u8>,
    ) -> Result<asynchronous::AsyncRwLock<ST, Self>, error::NVError> {
        let allocation_block_size_128b_log2 = layout.allocation_block_size_128b_log2;
        let auth_tree_node_allocation_blocks_log2 = layout
            .auth_tree_node_io_blocks_log2
            .checked_add(layout.io_block_allocation_blocks_log2)
            .ok_or(error::NVError::InvalidAuthTreeConfig)?;
        // An Authentication Tree Node's size must fit an usize as well as an
        // u64.
        let auth_tree_node_size_128b_log2 = auth_tree_node_allocation_blocks_log2
            .checked_add(allocation_block_size_128b_log2)
            .ok_or(error::NVError::InvalidAuthTreeConfig)?;
        let auth_tree_node_size_log2 = auth_tree_node_size_128b_log2 as u32 + 7;
        if auth_tree_node_size_log2 >= usize::BITS || auth_tree_node_size_log2 >= u64::BITS {
            return Err(error::NVError::InvalidAuthTreeConfig);
        }

        let auth_tree_data_block_allocation_blocks_log2 =
            layout.auth_tree_data_block_allocation_blocks_log2;
        if auth_tree_data_block_allocation_blocks_log2 >= u64::BITS as u8 {
            return Err(error::NVError::InvalidAuthTreeConfig);
        }

        let auth_tree_hash_alg = layout.auth_tree_hash_alg;
        let auth_tree_digest_len = hash::hash_alg_digest_len(auth_tree_hash_alg);
        let auth_tree_digest_len_log2 = (auth_tree_digest_len as u32)
            .round_up_next_pow2()
            .unwrap()
            .ilog2();
        if auth_tree_node_size_log2 <= auth_tree_digest_len_log2 {
            return Err(error::NVError::InvalidAuthTreeConfig);
        }
        let digests_per_node_log2 = (auth_tree_node_size_log2 - auth_tree_digest_len_log2) as u8;

        // Verify that all the Authentication Tree's extents are aligned to the node
        // size.
        let auth_tree_node_alignment_mask =
            u64::trailing_bits_mask(auth_tree_node_allocation_blocks_log2 as u32);
        for extent in auth_tree_extents.iter() {
            let physical_range = extent.physical_range();
            if u64::from(physical_range.begin()) & auth_tree_node_alignment_mask != 0
                || u64::from(physical_range.end()) & auth_tree_node_alignment_mask != 0
            {
                return Err(error::NVError::UnalignedAuthTreeExtents);
            }
        }
        let auth_tree_nodes_allocation_block_count = auth_tree_extents.allocation_block_count();
        if u64::from(auth_tree_extents.allocation_block_count()) == 0 {
            return Err(error::NVError::InvalidAuthTreeDimensions);
        }

        let auth_tree_data_allocation_blocks_map =
            AuthTreeDataAllocationBlocksMap::new(&auth_tree_extents)?;

        // Deduce the Authentication Tree dimensions from the node count.
        let auth_tree_node_count = u64::from(auth_tree_nodes_allocation_block_count)
            >> auth_tree_node_allocation_blocks_log2;
        let auth_tree_levels =
            auth_tree_node_count_to_auth_tree_levels(auth_tree_node_count, digests_per_node_log2)?;
        let digests_per_node_minus_one_inv_mod_u64 =
            digests_per_node_minus_one_inv_mod_u64(digests_per_node_log2);
        // Verify that the extents of the covered data can be deduced. This validates
        // the tree shape as well (e.g. no dangling interior nodes without any
        // descendants).
        let auth_tree_data_block_count = auth_tree_node_count_to_auth_tree_data_block_count(
            auth_tree_node_count,
            auth_tree_levels,
            digests_per_node_log2,
            digests_per_node_minus_one_inv_mod_u64,
        )?;
        if auth_tree_data_block_allocation_blocks_log2 != 0
            && auth_tree_data_block_count
                >= 1u64 << (u64::BITS as u8 - auth_tree_data_block_allocation_blocks_log2)
        {
            return Err(error::NVError::InvalidAuthTreeDimensions);
        }

        let auth_hmac_hash_alg = layout.auth_hmac_hash_alg;
        let auth_hmac_digest_len = hash::hash_alg_digest_len(auth_hmac_hash_alg);
        if auth_hmac_digest.len() != auth_hmac_digest_len as usize {
            return Err(error::NVError::InvalidDigest);
        }
        let auth_hmac_key = keys.derive_key(keys::KeyId::new(
            index::SpecialInode::AuthTree as u32,
            keys::KeyPurpose::Authentication,
        ))?;

        let cache_slots = 1usize.saturating_add(
            (auth_tree_levels as usize - 1).saturating_mul(1usize << digests_per_node_log2),
        );
        let auth_tree_node_cache = cache::Cache::new(cache_slots)?;

        Ok(asynchronous::AsyncRwLock::new(Self {
            chip,
            auth_tree_extents,
            auth_tree_data_allocation_blocks_map,
            digests_per_node_log2,
            digests_per_node_minus_one_inv_mod_u64,
            auth_tree_levels,
            auth_tree_data_block_count,
            auth_tree_node_cache,
            auth_tree_hash_alg,
            auth_tree_digest_len,
            auth_hmac_hash_alg,
            auth_hmac_digest,
            auth_hmac_key,
            allocation_block_size_128b_log2,
            auth_tree_node_allocation_blocks_log2,
            auth_tree_data_block_allocation_blocks_log2,
        })?)
    }

    fn auth_tree_node_io_region(
        &self,
        node_id: &AuthTreeNodeId,
    ) -> Result<chunked_io_region::ChunkedIoRegion, error::NVError> {
        debug_assert!(node_id.level < self.auth_tree_levels);
        if u64::from(node_id.covered_auth_tree_data_blocks_begin)
            >= u64::from(self.auth_tree_data_block_count)
        {
            return Err(error::NVError::IOBlockOutOfRange);
        }
        let dfs_pre_node_index = auth_tree_data_block_index_to_auth_tree_node_entry(
            node_id.covered_auth_tree_data_blocks_begin,
            node_id.level,
            self.auth_tree_levels,
            self.digests_per_node_log2,
            self.digests_per_node_minus_one_inv_mod_u64,
        )
        .0;
        let logical_begin = layout::LogicalAllocBlockIndex::from(
            dfs_pre_node_index << self.auth_tree_data_block_allocation_blocks_log2,
        );
        let logical_end = logical_begin
            + layout::AllocBlockCount::from(
                1u64 << self.auth_tree_data_block_allocation_blocks_log2,
            );
        let logical_range = layout::LogicalAllocBlockRange::new(logical_begin, logical_end);
        let mut extents_range_iter = self.auth_tree_extents.iter_range(&logical_range);
        let extent = extents_range_iter.next().unwrap();
        debug_assert!(extents_range_iter.next().is_none());
        let physical_range = extent.physical_range();
        Ok(chunked_io_region::ChunkedIoRegion::new(
            u64::from(physical_range.begin()) << self.allocation_block_size_128b_log2,
            u64::from(physical_range.end()) << self.allocation_block_size_128b_log2,
            (self.auth_tree_node_allocation_blocks_log2 + self.allocation_block_size_128b_log2)
                as u32,
        )
        .map_err(|_| tpm_err_internal!())?)
    }

    fn auth_tree_node_size(&self) -> usize {
        1usize
            << (self.auth_tree_node_allocation_blocks_log2
                + self.allocation_block_size_128b_log2
                + 7)
    }

    fn hmac_root_node<'a, DEI: Iterator<Item = &'a [u8]>>(
        &self,
        digest_entries_iterator: DEI,
    ) -> Result<vec::Vec<u8>, error::NVError> {
        let auth_config_version = 0u32.to_be_bytes();
        // It should not be needed AFAICT and is in part redundant to those
        // AuthSubjectDataPrefix prefixes hashed alongside the subjects, but pin
        // down the tree geometry for some extra assurance.
        let auth_config: [u8; 4] = [
            self.allocation_block_size_128b_log2,
            self.auth_tree_node_allocation_blocks_log2,
            self.auth_tree_data_block_allocation_blocks_log2,
            self.auth_tree_levels,
        ];
        let auth_hmac_digest_len = hash::hash_alg_digest_len(self.auth_hmac_hash_alg) as usize;
        debug_assert_eq!(self.auth_hmac_digest.len(), auth_hmac_digest_len);
        let mut root_hmac_digest = utils::try_alloc_vec(auth_hmac_digest_len)?;
        let mut h = hash::HmacInstance::new(self.auth_hmac_hash_alg, &self.auth_hmac_key);
        h.update(io_slices::IoSlices::new(&mut [
            Some(slice::from_ref(
                &(AuthSubjectDataPrefix::AuthTreeRootNode as u8),
            )),
            Some(&auth_config_version),
            Some(&auth_config),
        ]));
        for digest_entry in digest_entries_iterator {
            debug_assert_eq!(digest_entry.len(), self.auth_tree_digest_len as usize);
            h.update(io_slices::IoSlices::new(&mut [Some(digest_entry)]));
        }
        h.finalize_into(&mut root_hmac_digest);
        Ok(root_hmac_digest)
    }

    fn authenticate_root_node(&self, node_data: &[u8]) -> Result<(), error::NVError> {
        let digest_len = self.auth_tree_digest_len as usize;
        debug_assert!(node_data.len() >= digest_len << self.digests_per_node_log2);
        let root_hmac_digest = self.hmac_root_node(
            node_data
                .chunks_exact(digest_len)
                .take(1usize << self.digests_per_node_log2),
        )?;
        if ct_cmp::ct_bytes_eq(&root_hmac_digest, &self.auth_hmac_digest).unwrap() != 0 {
            Ok(())
        } else {
            Err(error::NVError::AuthenticationFailure)
        }
    }

    fn digest_descendant_node<'a, DEI: Iterator<Item = &'a [u8]>>(
        &self,
        digest_entries_iterator: DEI,
    ) -> Result<vec::Vec<u8>, error::NVError> {
        let digest_len = self.auth_tree_digest_len as usize;
        let mut node_digest = utils::try_alloc_vec(digest_len)?;
        let mut h = hash::HashInstance::new(self.auth_tree_hash_alg);
        h.update(io_slices::IoSlices::new(&mut [Some(slice::from_ref(
            &(AuthSubjectDataPrefix::AuthTreeDescendantNode as u8),
        ))]));
        for digest_entry in digest_entries_iterator {
            debug_assert_eq!(digest_entry.len(), digest_len);
            h.update(io_slices::IoSlices::new(&mut [Some(digest_entry)]));
        }
        h.finalize_into(&mut node_digest);
        Ok(node_digest)
    }

    fn authenticate_descendant_node(
        &self,
        node_id: &AuthTreeNodeId,
        node_data: &[u8],
        parent_node: &AuthTreeNode,
    ) -> Result<(), error::NVError> {
        let digest_len = self.auth_tree_digest_len as usize;
        debug_assert!(node_data.len() >= digest_len << self.digests_per_node_log2);
        let node_digest = self.digest_descendant_node(
            node_data
                .chunks_exact(digest_len)
                .take(1usize << self.digests_per_node_log2),
        )?;
        let level_covered_index_mask_bits =
            ((node_id.level + 1) * self.digests_per_node_log2) as u32;
        let entry_in_parent = if level_covered_index_mask_bits < u64::BITS {
            ((u64::from(node_id.covered_auth_tree_data_blocks_begin)
                >> level_covered_index_mask_bits)
                & u64::trailing_bits_mask(self.digests_per_node_log2 as u32)) as usize
        } else {
            0
        };
        let expected_node_digest_begin = entry_in_parent * digest_len;
        let expected_node_digest =
            &parent_node.data[expected_node_digest_begin..expected_node_digest_begin + digest_len];
        if ct_cmp::ct_bytes_eq(&node_digest, expected_node_digest).unwrap() != 0 {
            Ok(())
        } else {
            Err(error::NVError::AuthenticationFailure)
        }
    }

    fn digest_data_block<'a, ABI: Iterator<Item = Option<&'a [u8]>>>(
        &self,
        data_block_allocation_blocks_iter: &mut ABI,
    ) -> Result<vec::Vec<u8>, error::NVError> {
        let digest_len = self.auth_tree_digest_len as usize;
        let mut data_block_digest = utils::try_alloc_vec(digest_len)?;
        let mut h = hash::HashInstance::new(self.auth_tree_hash_alg);
        for allocation_block in data_block_allocation_blocks_iter {
            match allocation_block {
                Some(allocation_block_data) => {
                    debug_assert_eq!(
                        allocation_block_data.len(),
                        1usize << (self.allocation_block_size_128b_log2 + 7)
                    );
                    h.update(io_slices::IoSlices::new(&mut [
                        Some(slice::from_ref(
                            &(AuthSubjectDataPrefix::AuthenticatedDataBlockAllocationBlock as u8),
                        )),
                        Some(allocation_block_data),
                    ]));
                }
                None => {
                    h.update(io_slices::IoSlices::new(&mut [Some(slice::from_ref(
                        &(AuthSubjectDataPrefix::UnauthenticatedDataBlockAllocationBlock as u8),
                    ))]));
                }
            }
        }
        h.finalize_into(&mut data_block_digest);
        Ok(data_block_digest)
    }

    fn authenticate_data_block<'a, ABI: Iterator<Item = Option<&'a [u8]>>>(
        &self,
        auth_tree_data_block_index: AuthTreeDataAllocBlockIndex,
        mut data_block_allocation_blocks_iter: ABI,
        leaf_node: &AuthTreeNode,
    ) -> Result<ABI, error::NVError> {
        let block_digest = self.digest_data_block(&mut data_block_allocation_blocks_iter)?;
        let digest_len = self.auth_tree_digest_len as usize;
        let entry_in_leaf_node = (u64::from(auth_tree_data_block_index)
            & u64::trailing_bits_mask(self.digests_per_node_log2 as u32))
            as usize;
        let expected_block_digest_begin = entry_in_leaf_node * digest_len;
        let expected_block_digest =
            &leaf_node.data[expected_block_digest_begin..expected_block_digest_begin + digest_len];
        if ct_cmp::ct_bytes_eq(&block_digest, expected_block_digest).unwrap() != 0 {
            Ok(data_block_allocation_blocks_iter)
        } else {
            Err(error::NVError::AuthenticationFailure)
        }
    }
}

type AuthTreeReadLock<ST, C> = asynchronous::AsyncRwLockReadGuard<ST, AuthTree<ST, C>>;

type AuthTreeWriteLock<ST, C> = asynchronous::AsyncRwLockWriteGuard<ST, AuthTree<ST, C>>;

#[derive(Clone, Copy)]
struct AuthTreePath {
    node_id: AuthTreeNodeId,
    auth_tree_levels: u8,
    digests_per_node_log2: u8,
}

impl cache::CacheKeys<AuthTreeNodeId> for AuthTreePath {
    type Iterator<'a> = AuthTreePathNodesIterator<'a>;

    fn iter(&self) -> Self::Iterator<'_> {
        AuthTreePathNodesIterator {
            path: self,
            level: self.node_id.level,
        }
    }
}

#[derive(Clone, Copy)]
struct AuthTreePathNodesIterator<'a> {
    path: &'a AuthTreePath,
    level: u8,
}

impl<'a> Iterator for AuthTreePathNodesIterator<'a> {
    type Item = AuthTreeNodeId;

    fn next(&mut self) -> Option<Self::Item> {
        if self.level == self.path.auth_tree_levels {
            return None;
        }
        let level = self.level;
        self.level += 1;

        Some(AuthTreeNodeId::new(
            self.path.node_id.covered_auth_tree_data_blocks_begin,
            level,
            self.path.digests_per_node_log2,
        ))
    }
}

struct AuthTreeNodeNvReadRequest {
    dst_buf: vec::Vec<u8>,
    io_region: chunked_io_region::ChunkedIoRegion,
}

impl ops::Index<&chunked_io_region::ChunkedIoRegionChunkRange> for AuthTreeNodeNvReadRequest {
    type Output = [u8];

    fn index(&self, index: &chunked_io_region::ChunkedIoRegionChunkRange) -> &Self::Output {
        debug_assert_eq!(index.chunk().decompose_to_hierarchic_indices::<0>([]).0, 0);
        &self.dst_buf[index.range_in_chunk().clone()]
    }
}

impl ops::IndexMut<&chunked_io_region::ChunkedIoRegionChunkRange> for AuthTreeNodeNvReadRequest {
    fn index_mut(
        &mut self,
        index: &chunked_io_region::ChunkedIoRegionChunkRange,
    ) -> &mut Self::Output {
        debug_assert_eq!(index.chunk().decompose_to_hierarchic_indices::<0>([]).0, 0);
        &mut self.dst_buf[index.range_in_chunk().clone()]
    }
}

impl chip::NVChipReadRequest for AuthTreeNodeNvReadRequest {
    fn region(&self) -> &chunked_io_region::ChunkedIoRegion {
        &self.io_region
    }
}

enum AuthTreeNodeLoadFuture<
    ST: sync_types::SyncTypes,
    C: chip::NVChip,
    TL: ops::Deref<Target = AuthTree<ST, C>> + marker::Unpin,
> {
    AcquireCacheReservations {
        tree_lock: Option<TL>,
        auth_tree_node_id: AuthTreeNodeId,
        reserve_cache_slots_fut: cache::CacheReserveSlotsFuture<
            ST,
            AuthTreeNodeId,
            AuthTreeNode,
            AuthTreeNodeId,
            AuthTreePath,
        >,
    },
    ReadAndVerifyBranchNodes {
        tree_lock: Option<TL>,
        auth_tree_node_id: AuthTreeNodeId,
        cache_reservations: vec::Vec<cache::CacheSlotReservation<ST, AuthTreeNodeId, AuthTreeNode>>,
        current_level: u8,
        node_read_fut: C::ReadFuture<AuthTreeNodeNvReadRequest>,
    },
    Done,
}

impl<
        ST: sync_types::SyncTypes,
        C: chip::NVChip,
        TL: ops::Deref<Target = AuthTree<ST, C>> + marker::Unpin,
    > AuthTreeNodeLoadFuture<ST, C, TL>
{
    fn new(
        tree_lock: TL,
        auth_tree_node_id: AuthTreeNodeId,
    ) -> Result<Self, (TL, interface::TpmErr)> {
        let path = AuthTreePath {
            node_id: auth_tree_node_id,
            auth_tree_levels: tree_lock.auth_tree_levels,
            digests_per_node_log2: tree_lock.digests_per_node_log2,
        };
        let reserve_cache_slots_fut = match tree_lock.auth_tree_node_cache.reserve_slots(path) {
            Ok(reserve_slots_fut) => reserve_slots_fut,
            Err(e) => return Err((tree_lock, e)),
        };
        Ok(Self::AcquireCacheReservations {
            tree_lock: Some(tree_lock),
            auth_tree_node_id,
            reserve_cache_slots_fut,
        })
    }

    fn submit_read_node(
        tree: &AuthTree<ST, C>,
        auth_tree_node_id: &AuthTreeNodeId,
        current_level: u8,
    ) -> Result<C::ReadFuture<AuthTreeNodeNvReadRequest>, error::NVError> {
        let dst_buf = utils::try_alloc_vec(tree.auth_tree_node_size())?;
        let node_id = AuthTreeNodeId::new(
            auth_tree_node_id.covered_auth_tree_data_blocks_begin,
            current_level,
            tree.digests_per_node_log2,
        );
        let io_region = tree.auth_tree_node_io_region(&node_id)?;
        let request = AuthTreeNodeNvReadRequest { dst_buf, io_region };
        tree.chip.read(request).map_err(|(_, e)| e)
    }
}

impl<
        ST: sync_types::SyncTypes,
        C: chip::NVChip,
        TL: ops::Deref<Target = AuthTree<ST, C>> + marker::Unpin,
    > future::Future for AuthTreeNodeLoadFuture<ST, C, TL>
{
    type Output = (
        TL,
        Result<cache::CacheSlotReservation<ST, AuthTreeNodeId, AuthTreeNode>, error::NVError>,
    );

    fn poll(mut self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        loop {
            match self.deref_mut() {
                Self::AcquireCacheReservations {
                    tree_lock,
                    auth_tree_node_id,
                    reserve_cache_slots_fut,
                } => {
                    let mut cache_reservations = match pin::Pin::new(reserve_cache_slots_fut)
                        .poll(cx)
                    {
                        task::Poll::Ready(Ok((cache_reservations, _))) => cache_reservations,
                        task::Poll::Ready(Err(e)) => {
                            let tree_lock = tree_lock.take().unwrap();
                            *self.deref_mut() = Self::Done;
                            return task::Poll::Ready((tree_lock, Err(error::NVError::from(e))));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    let tree_lock = tree_lock.take().unwrap();
                    let auth_tree_node_id = *auth_tree_node_id;
                    *self = Self::Done;

                    // Got the cache slot reservations for all nodes up to
                    // (including) the root. Check what's already there.
                    let first_cached_index =
                        cache_reservations.iter().position(|r| r.lock().is_some());
                    if let Some(0) = first_cached_index {
                        cache_reservations.truncate(1);
                        let cache_reservation = cache_reservations.pop().unwrap();
                        return task::Poll::Ready((tree_lock, Ok(cache_reservation)));
                    }
                    // Submit a request for reading the topmost
                    // Authentication Tree node not yet in the cache and
                    // transition the future to the next state.
                    let current_level = match first_cached_index {
                        Some(first_cached_index) => {
                            cache_reservations.truncate(first_cached_index + 1);
                            auth_tree_node_id.level + first_cached_index as u8 - 1
                        }
                        None => tree_lock.auth_tree_levels - 1,
                    };
                    let node_read_fut =
                        match Self::submit_read_node(&tree_lock, &auth_tree_node_id, current_level)
                        {
                            Ok(node_read_fut) => node_read_fut,
                            Err(e) => return task::Poll::Ready((tree_lock, Err(e))),
                        };
                    *self = Self::ReadAndVerifyBranchNodes {
                        tree_lock: Some(tree_lock),
                        auth_tree_node_id,
                        cache_reservations,
                        current_level,
                        node_read_fut,
                    };
                }
                Self::ReadAndVerifyBranchNodes {
                    tree_lock: tree_lock_in_self,
                    auth_tree_node_id,
                    cache_reservations,
                    current_level,
                    node_read_fut,
                } => {
                    let node_read_result = match pin::Pin::new(&mut *node_read_fut).poll(cx) {
                        task::Poll::Ready(node_read_result) => node_read_result,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let tree_lock = tree_lock_in_self.take().unwrap();
                    let node_read_request = match node_read_result {
                        (node_read_request, Ok(())) => node_read_request,
                        (_, Err(e)) => {
                            *self = Self::Done;
                            return task::Poll::Ready((tree_lock, Err(e)));
                        }
                    };

                    // Got the current_level node's data from the backing
                    // storage. Verify it using either the already verified
                    // parent or, if the root, by the HMAC.
                    let AuthTreeNodeNvReadRequest {
                        dst_buf: node_data,
                        io_region: _,
                    } = node_read_request;
                    if *current_level != tree_lock.auth_tree_levels - 1 {
                        let node_id = AuthTreeNodeId::new(
                            auth_tree_node_id.covered_auth_tree_data_blocks_begin,
                            *current_level,
                            tree_lock.digests_per_node_log2,
                        );
                        let parent = cache_reservations
                            [(*current_level - auth_tree_node_id.level) as usize + 1]
                            .lock();
                        match tree_lock.authenticate_descendant_node(
                            &node_id,
                            &node_data,
                            parent.as_ref().unwrap(),
                        ) {
                            Ok(()) => (),
                            Err(e) => {
                                drop(parent);
                                *self = Self::Done;
                                return task::Poll::Ready((tree_lock, Err(e)));
                            }
                        }
                    } else {
                        match tree_lock.authenticate_root_node(&node_data) {
                            Ok(()) => (),
                            Err(e) => {
                                *self = Self::Done;
                                return task::Poll::Ready((tree_lock, Err(e)));
                            }
                        }
                    }

                    // Install the now verified node in the cache.
                    let mut locked_cache_entry = cache_reservations
                        [(*current_level - auth_tree_node_id.level) as usize]
                        .lock();
                    if locked_cache_entry.is_none() {
                        *locked_cache_entry = Some(AuthTreeNode { data: node_data });
                    }
                    drop(locked_cache_entry);
                    cache_reservations
                        .truncate((*current_level - auth_tree_node_id.level + 1) as usize);

                    // Either move down to the next node and continue the
                    // verification chain or, once the bottom/requested level
                    // has been reached, return the result.
                    if *current_level == auth_tree_node_id.level {
                        let cache_reservation = cache_reservations.pop().unwrap();
                        *self = Self::Done;
                        return task::Poll::Ready((tree_lock, Ok(cache_reservation)));
                    } else {
                        *current_level -= 1;
                        *node_read_fut = match Self::submit_read_node(
                            &tree_lock,
                            auth_tree_node_id,
                            *current_level,
                        ) {
                            Ok(node_read_fut) => node_read_fut,
                            Err(e) => {
                                *self = Self::Done;
                                return task::Poll::Ready((tree_lock, Err(e)));
                            }
                        };
                        *tree_lock_in_self = Some(tree_lock);
                    }
                }
                Self::Done => unreachable!(),
            }
        }
    }
}

struct AuthTreePendingNodeEntryUpdate {
    node_entry_index: usize,
    updated_digest: vec::Vec<u8>,
}

struct AuthTreePendingNodeUpdates {
    node_id: AuthTreeNodeId,
    updated_entries: vec::Vec<AuthTreePendingNodeEntryUpdate>,
}

struct AuthTreeDataBlockUpdate {
    data_block_index: AuthTreeDataBlockIndex,
    data_block_digest: vec::Vec<u8>,
}

trait AuthTreeDataBlocksUpdatesIterator<ST: sync_types::SyncTypes, C: chip::NVChip> {
    type DigestNextUpdatedAuthTreeDataBlockFuture: future::Future<
            Output = (
                asynchronous::AsyncRwLockWriteGuard<ST, AuthTree<ST, C>>,
                Result<Option<AuthTreeDataBlockUpdate>, error::NVError>,
            ),
        > + marker::Unpin;

    fn next(
        &mut self,
        tree_lock: asynchronous::AsyncRwLockWriteGuard<ST, AuthTree<ST, C>>,
    ) -> Result<
        Self::DigestNextUpdatedAuthTreeDataBlockFuture,
        (
            asynchronous::AsyncRwLockWriteGuard<ST, AuthTree<ST, C>>,
            error::NVError,
        ),
    >;
}

enum AuthTreeUpdateFutureState<
    ST: sync_types::SyncTypes,
    C: chip::NVChip,
    DUI: AuthTreeDataBlocksUpdatesIterator<ST, C> + Unpin,
> {
    DigestNextUpdatedAuthTreeDataBlock {
        next_updated_data_block_fut: DUI::DigestNextUpdatedAuthTreeDataBlockFuture,
    },
    LoadAuthTreeNode {
        load_tree_node_fut:
            AuthTreeNodeLoadFuture<ST, C, asynchronous::AsyncRwLockWriteGuard<ST, AuthTree<ST, C>>>,
        next_updated_data_block: Option<AuthTreeDataBlockUpdate>,
    },
    Done,
}

struct AuthTreeUpdateFuture<
    ST: sync_types::SyncTypes,
    C: chip::NVChip,
    DUI: AuthTreeDataBlocksUpdatesIterator<ST, C> + Unpin,
> {
    data_block_updates_iter: DUI,
    pending_nodes_updates: vec::Vec<AuthTreePendingNodeUpdates>,
    /// Current position in the tree, represented as a sequence of indicies into
    /// [`pending_nodes_updates`](Self::pending_nodes_updates), sorted by
    /// distance from the root.
    cursor: vec::Vec<usize>,
    state: AuthTreeUpdateFutureState<ST, C, DUI>,
}

impl<
        ST: sync_types::SyncTypes,
        C: chip::NVChip,
        DUI: AuthTreeDataBlocksUpdatesIterator<ST, C> + Unpin,
    > AuthTreeUpdateFuture<ST, C, DUI>
{
    fn new(
        tree_lock: asynchronous::AsyncRwLockWriteGuard<ST, AuthTree<ST, C>>,
        mut data_block_updates_iter: DUI,
    ) -> Result<
        Self,
        (
            asynchronous::AsyncRwLockWriteGuard<ST, AuthTree<ST, C>>,
            error::NVError,
        ),
    > {
        let next_updated_data_block_fut = match data_block_updates_iter.next(tree_lock) {
            Ok(next_updated_data_block_fut) => next_updated_data_block_fut,
            Err((tree_lock, e)) => {
                return Err((tree_lock, e.into()));
            }
        };
        Ok(Self {
            data_block_updates_iter,
            pending_nodes_updates: vec::Vec::new(),
            cursor: vec::Vec::new(),
            state: AuthTreeUpdateFutureState::DigestNextUpdatedAuthTreeDataBlock {
                next_updated_data_block_fut,
            },
        })
    }

    fn push_cursor_to_leaf(
        &mut self,
        data_block_index: AuthTreeDataBlockIndex,
        digests_per_node_log2: u8,
        auth_tree_levels: u8,
    ) -> Result<(), interface::TpmErr> {
        let mut level = match self.cursor.last() {
            Some(bottom) => {
                debug_assert!(
                    self.pending_nodes_updates[*bottom]
                        .node_id
                        .last_covered_auth_tree_data_block(digests_per_node_log2)
                        >= data_block_index
                );
                debug_assert!(self.pending_nodes_updates[*bottom].node_id.level > 0);
                self.pending_nodes_updates[*bottom].node_id.level
            }
            None => auth_tree_levels,
        };
        if self.cursor.capacity() < auth_tree_levels as usize {
            self.cursor
                .try_reserve_exact(auth_tree_levels as usize - self.cursor.capacity())
                .map_err(|_| tpm_err_rc!(MEMORY))?;
        }
        self.pending_nodes_updates
            .try_reserve_exact(level as usize)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        while level > 0 {
            level -= 1;
            self.cursor.push(self.pending_nodes_updates.len());
            self.pending_nodes_updates.push(AuthTreePendingNodeUpdates {
                node_id: AuthTreeNodeId::new(data_block_index, level, digests_per_node_log2),
                updated_entries: vec::Vec::new(),
            });
        }

        Ok(())
    }

    fn pending_bottom_node_updates_push(
        &mut self,
        child_covered_auth_tree_data_blocks_begin: AuthTreeDataBlockIndex,
        child_digest: vec::Vec<u8>,
        digests_per_node_log2: u8,
    ) -> Result<(), interface::TpmErr> {
        let bottom = self.cursor.last().unwrap();
        let bottom_node_pending_updates = &mut self.pending_nodes_updates[*bottom];
        debug_assert!(
            bottom_node_pending_updates
                .node_id
                .covered_auth_tree_data_blocks_begin
                <= child_covered_auth_tree_data_blocks_begin
        );
        debug_assert!(
            bottom_node_pending_updates
                .node_id
                .last_covered_auth_tree_data_block(digests_per_node_log2)
                < child_covered_auth_tree_data_blocks_begin
        );
        let level = bottom_node_pending_updates.node_id.level;
        debug_assert!(((level * digests_per_node_log2) as u32) < u64::BITS);
        let entry_index_in_node = ((u64::from(child_covered_auth_tree_data_blocks_begin)
            >> (level * digests_per_node_log2))
            & u64::trailing_bits_mask(digests_per_node_log2 as u32))
            as usize;
        bottom_node_pending_updates
            .updated_entries
            .try_reserve_exact(1)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        bottom_node_pending_updates
            .updated_entries
            .push(AuthTreePendingNodeEntryUpdate {
                node_entry_index: entry_index_in_node,
                updated_digest: child_digest,
            });
        Ok(())
    }
}

impl<
        ST: sync_types::SyncTypes,
        C: chip::NVChip,
        U: AuthTreeDataBlocksUpdatesIterator<ST, C> + Unpin,
    > future::Future for AuthTreeUpdateFuture<ST, C, U>
{
    type Output = (
        asynchronous::AsyncRwLockWriteGuard<ST, AuthTree<ST, C>>,
        Result<(vec::Vec<u8>, vec::Vec<AuthTreePendingNodeUpdates>), error::NVError>,
    );

    fn poll(mut self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        'poll_inner_fut: loop {
            // Poll either of the two possible inner futures, code common to subsequent
            // processing will follow below.
            let state = &mut self.state;
            let (tree_lock, mut next_updated_data_block) = match state {
                AuthTreeUpdateFutureState::DigestNextUpdatedAuthTreeDataBlock {
                    next_updated_data_block_fut,
                } => {
                    let (tree_lock, next_updated_data_block) =
                        match pin::Pin::new(next_updated_data_block_fut).poll(cx) {
                            task::Poll::Ready((tree_lock, Ok(next_updated_data_block))) => {
                                (tree_lock, next_updated_data_block)
                            }
                            task::Poll::Ready((tree_lock, Err(e))) => {
                                self.state = AuthTreeUpdateFutureState::Done;
                                return task::Poll::Ready((tree_lock, Err(e)));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };
                    (tree_lock, next_updated_data_block)
                }
                AuthTreeUpdateFutureState::LoadAuthTreeNode {
                    load_tree_node_fut,
                    next_updated_data_block,
                } => {
                    // The cursor is currently being moved up (because the next_updated_data_block
                    // is past the bottom node's covered range) and the original
                    // contents of the current inner node, which hasn't got all
                    // of its entries updated, got loaded and authenticated. Pop
                    // it and digest it into the associated parent entry, if
                    // any.
                    let (tree_lock, node) = match pin::Pin::new(load_tree_node_fut).poll(cx) {
                        task::Poll::Ready((tree_lock, Ok(node))) => (tree_lock, node),
                        task::Poll::Ready((tree_lock, Err(e))) => {
                            self.state = AuthTreeUpdateFutureState::Done;
                            return task::Poll::Ready((tree_lock, Err(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let next_updated_data_block = next_updated_data_block.take();
                    self.state = AuthTreeUpdateFutureState::Done;
                    let popped = self.cursor.pop().unwrap();
                    let popped_is_root = self.cursor.is_empty();
                    let popped_node_pending_updates = &mut self.pending_nodes_updates[popped];
                    let node = node.lock();
                    let popped_node_updated_digests = AuthTreeNodeUpdatedDigestsIterator::new(
                        Some(&node.as_ref().unwrap().data),
                        &popped_node_pending_updates.updated_entries,
                        tree_lock.auth_tree_digest_len,
                        tree_lock.digests_per_node_log2,
                    );
                    if !popped_is_root {
                        // Popped node is not the root, digest its updated contents into the
                        // associated parent entry.
                        let node_digest =
                            match tree_lock.digest_descendant_node(popped_node_updated_digests) {
                                Ok(node_digest) => node_digest,
                                Err(e) => {
                                    return task::Poll::Ready((tree_lock, Err(e)));
                                }
                            };
                        let popped_node_id = popped_node_pending_updates.node_id;
                        if let Err(e) = self.pending_bottom_node_updates_push(
                            popped_node_id.covered_auth_tree_data_blocks_begin,
                            node_digest,
                            tree_lock.digests_per_node_log2,
                        ) {
                            return task::Poll::Ready((tree_lock, Err(e.into())));
                        }
                    } else {
                        // Popped node is the root, HMAC its updated contents and be done.
                        match tree_lock.hmac_root_node(popped_node_updated_digests) {
                            Ok(root_hmac) => {
                                let pending_nodes_updates =
                                    mem::replace(&mut self.pending_nodes_updates, vec::Vec::new());
                                return task::Poll::Ready((
                                    tree_lock,
                                    Ok((root_hmac, pending_nodes_updates)),
                                ));
                            }
                            Err(e) => {
                                return task::Poll::Ready((tree_lock, Err(e)));
                            }
                        };
                    }
                    (tree_lock, next_updated_data_block)
                }
                AuthTreeUpdateFutureState::Done => unreachable!(),
            };

            // Figure out what to do next, based on next_updated_data_block,
            // the cursor position and the bottom node's covered data range:
            // - if next_updated_data_block is None, all that is left to do is to move the
            //   cursor all the way up to the root, digesting child nodes into their
            //   associated parent entries in the course.
            // - if the next_updated_data_block is located past the cursor's bottom node's
            //   covered data range, the cursor needs to get moved up until
            //   next_updated_data_block is in range again, digesting child nodes into
            //   parent entries on the go,
            // - if the next_updated_data_block is in the cursor's bottom node's covered
            //   range, the cursor will get moved down all the way to level 0, and the
            //   next_updated_data_block's associated digest recorded in the corresponding
            //   leaf slot.
            self.state = AuthTreeUpdateFutureState::Done;
            if self.cursor.is_empty() {
                // Cursor is still empty, it's the first updated
                // data block.
                match &next_updated_data_block {
                    None => {
                        // There is no change at all, copy the existing root hmac and return.
                        let mut root_hmac = vec::Vec::new();
                        if let Err(_) = root_hmac.try_reserve(tree_lock.auth_hmac_digest.len()) {
                            return task::Poll::Ready((tree_lock, Err(tpm_err_rc!(MEMORY).into())));
                        }
                        root_hmac.copy_from_slice(&tree_lock.auth_hmac_digest);
                        return task::Poll::Ready((
                            tree_lock,
                            Ok((
                                root_hmac,
                                mem::replace(&mut self.pending_nodes_updates, vec::Vec::new()),
                            )),
                        ));
                    }
                    Some(next_updated_data_block) => {
                        if let Err(e) = self.push_cursor_to_leaf(
                            next_updated_data_block.data_block_index,
                            tree_lock.digests_per_node_log2,
                            tree_lock.auth_tree_levels,
                        ) {
                            return task::Poll::Ready((tree_lock, Err(e.into())));
                        }
                    }
                }
            }

            loop {
                let bottom = self.cursor.last().unwrap();
                let bottom_node_pending_updates = &self.pending_nodes_updates[*bottom];
                if next_updated_data_block
                    .as_ref()
                    .map(|next_updated_data_block| {
                        next_updated_data_block.data_block_index
                            <= bottom_node_pending_updates
                                .node_id
                                .last_covered_auth_tree_data_block(tree_lock.digests_per_node_log2)
                    })
                    .unwrap_or(false)
                {
                    let next_updated_data_block = next_updated_data_block.take().unwrap();
                    // next_updated_data_block is in the cursor's bottom node's covered range.
                    // Record its digest in the corresponding leaf node, potentially after
                    // moving the cursor all the way down to level 0.
                    if self.cursor.len() != tree_lock.auth_tree_levels as usize {
                        if let Err(e) = self.push_cursor_to_leaf(
                            next_updated_data_block.data_block_index,
                            tree_lock.digests_per_node_log2,
                            tree_lock.auth_tree_levels,
                        ) {
                            return task::Poll::Ready((tree_lock, Err(e.into())));
                        }
                    }
                    if let Err(e) = self.pending_bottom_node_updates_push(
                        next_updated_data_block.data_block_index,
                        next_updated_data_block.data_block_digest,
                        tree_lock.digests_per_node_log2,
                    ) {
                        return task::Poll::Ready((tree_lock, Err(e.into())));
                    }

                    // Obtain the next updated data block location and digest.
                    let next_updated_data_block_fut =
                        match self.data_block_updates_iter.next(tree_lock) {
                            Ok(next_updated_data_block_fut) => next_updated_data_block_fut,
                            Err((tree_lock, e)) => {
                                return task::Poll::Ready((tree_lock, Err(e.into())));
                            }
                        };
                    self.state = AuthTreeUpdateFutureState::DigestNextUpdatedAuthTreeDataBlock {
                        next_updated_data_block_fut,
                    };
                    continue 'poll_inner_fut;
                }

                // At this point, next_updated_data_block is either None or past the cursor's
                // bottom node's covered range. In either case, the cursor needs to get moved
                // up, digesting nodes into their associated parent entries, if any, in the
                // course.
                if bottom_node_pending_updates.updated_entries.len()
                    == 1usize << tree_lock.digests_per_node_log2
                {
                    // All of the node's entries got updated, its original contents won't be
                    // needed for computing the updated digest.
                    let popped = *bottom;
                    self.cursor.pop();
                    let popped_node_pending_updates = &self.pending_nodes_updates[popped];
                    let popped_node_updated_digests = AuthTreeNodeUpdatedDigestsIterator::new(
                        None,
                        &popped_node_pending_updates.updated_entries,
                        tree_lock.auth_tree_digest_len,
                        tree_lock.digests_per_node_log2,
                    );
                    if !self.cursor.is_empty() {
                        // At a descendant node, compute the digest and record it at the associated
                        // parent entry.
                        let node_digest =
                            match tree_lock.digest_descendant_node(popped_node_updated_digests) {
                                Ok(node_digest) => node_digest,
                                Err(e) => {
                                    return task::Poll::Ready((tree_lock, Err(e)));
                                }
                            };
                        let popped_node_id = popped_node_pending_updates.node_id;
                        if let Err(e) = self.pending_bottom_node_updates_push(
                            popped_node_id.covered_auth_tree_data_blocks_begin,
                            node_digest,
                            tree_lock.digests_per_node_log2,
                        ) {
                            return task::Poll::Ready((tree_lock, Err(e.into())));
                        }
                    } else {
                        // At the root, compute the HMAC over the root node and be done.
                        match tree_lock.hmac_root_node(popped_node_updated_digests) {
                            Ok(root_hmac) => {
                                let pending_nodes_updates =
                                    mem::replace(&mut self.pending_nodes_updates, vec::Vec::new());
                                return task::Poll::Ready((
                                    tree_lock,
                                    Ok((root_hmac, pending_nodes_updates)),
                                ));
                            }
                            Err(e) => {
                                return task::Poll::Ready((tree_lock, Err(e)));
                            }
                        };
                    }
                } else {
                    // Only part of the node's entries got updated, its original contents will be
                    // needed for computing the updated digest. Load and authenticate the node's
                    // contents.
                    let load_tree_node_fut = match AuthTreeNodeLoadFuture::new(
                        tree_lock,
                        bottom_node_pending_updates.node_id,
                    ) {
                        Ok(load_tree_node_fut) => load_tree_node_fut,
                        Err((tree_lock, e)) => {
                            return task::Poll::Ready((tree_lock, Err(e.into())));
                        }
                    };
                    self.state = AuthTreeUpdateFutureState::LoadAuthTreeNode {
                        load_tree_node_fut,
                        next_updated_data_block,
                    };
                    continue 'poll_inner_fut;
                }
            }
        }
    }
}

struct AuthTreeNodeUpdatedDigestsIterator<'a> {
    original_node_data: Option<&'a [u8]>,
    updated_entries: &'a [AuthTreePendingNodeEntryUpdate],
    next_node_entry_index: usize,
    next_updated_entries_index: usize,
    digest_len: u8,
    digests_per_node_log2: u8,
}

impl<'a> AuthTreeNodeUpdatedDigestsIterator<'a> {
    fn new(
        original_node_data: Option<&'a [u8]>,
        updated_entries: &'a [AuthTreePendingNodeEntryUpdate],
        digest_len: u8,
        digests_per_node_log2: u8,
    ) -> Self {
        match original_node_data {
            Some(original_node_data) => {
                debug_assert!(
                    original_node_data.len() >= (digest_len as usize) << digests_per_node_log2
                );
            }
            None => {
                debug_assert_eq!(updated_entries.len(), 1usize << digests_per_node_log2);
            }
        }

        Self {
            original_node_data,
            updated_entries,
            next_node_entry_index: 0,
            next_updated_entries_index: 0,
            digest_len,
            digests_per_node_log2,
        }
    }
}

impl<'a> Iterator for AuthTreeNodeUpdatedDigestsIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_node_entry_index == 1usize << self.digests_per_node_log2 {
            return None;
        }

        let node_entry_index = self.next_node_entry_index;
        self.next_node_entry_index += 1;
        if self.next_updated_entries_index < self.updated_entries.len()
            && node_entry_index
                == self.updated_entries[self.next_updated_entries_index].node_entry_index
        {
            let updated_entry_index = self.next_updated_entries_index;
            self.next_updated_entries_index += 1;
            Some(&self.updated_entries[updated_entry_index].updated_digest)
        } else {
            Some(
                self.original_node_data
                    .unwrap()
                    .chunks(self.digest_len as usize)
                    .nth(node_entry_index)
                    .unwrap(),
            )
        }
    }
}

fn auth_subtree_node_count(
    subtree_root_level: u8,
    auth_tree_levels: u8,
    digests_per_node_log2: u8,
    digests_per_node_minus_one_inv_mod_u64: u64,
) -> u64 {
    debug_assert!(auth_tree_levels >= 1);
    debug_assert!(subtree_root_level < auth_tree_levels);
    debug_assert_eq!(
        u64::trailing_bits_mask(digests_per_node_log2 as u32)
            .wrapping_mul(digests_per_node_minus_one_inv_mod_u64),
        1
    );
    // The node count can be easily computed as a geometric sum,
    // which evaluates to
    // (2^((subtree_root_level + 1) * digest_per_node_block_log2) - 1) /
    // (2^digest_per_node_block_log2 - 1).
    // The divisior happens to equal auth_tree_child_node_index_mask, for
    // which the inverse modulo 2^64 is in
    // auth_tree_child_node_index_mask_inv_mod_u64.
    //
    // But be careful: for unrealistically large values of
    // digest_per_node_block_log2, and large values of the
    // image_allocation_blocks (hence levels), the intermediate dividend value in
    // the equation above can overflow an u64 if the node count of the whole tree is
    // to be computed, i.e. if subtree_root_level == auth_tree_levels - 1.
    // It cannot overflow for proper subtrees, i.e. for
    // subtree_root_level < auth_tree_levels - 1 though (see below).
    // Also, the final result for the whole tree will fit an u64, and can get
    // computed recursively from its subtrees by
    // 2^c * S(L - 2) + 1,
    // with c := digest_per_node_block_log2, L:= auth_tree_levels,
    // and S(l) := auth_subtree_node_count(l) for brevity.
    // To see that this fits an u64 (or even the potentially smaller total image
    // authentication block count's bit width for that matter), observe first
    // that
    // S(L - 2) <= (2^(W - 1) - 1) / (2^c - 1), with W == u64::BITS here,
    // because L <= (W + c - 1) / c, c.f.
    // image_allocation_blocks_to_auth_tree_levels(). From that, it follows
    // directly that (2^c - 1) * S(L - 2) <= 2^(W - 1) - 1, or, via doubling,
    // that 2 * (2^c - 1) * S(L - 2) <= 2^W - 2.
    // As 2^c >= 2, we finally obtain
    // 2^c * S(L - 2) <= 2^W - 2 or
    // 2^c * S(L - 2) + 1 <= 2^W - 1 respectively.
    //
    // So, for proper subtrees, i.e. for subtree_root_level <= auth_tree_levels - 2,
    // compute the number of nodes directly, and use a recursive approach
    // for the whole tree, subtree_root_level == auth_tree_levels - 1.
    if auth_tree_levels >= 2 && subtree_root_level == auth_tree_levels - 1 {
        return auth_subtree_node_count(
            auth_tree_levels - 2,
            auth_tree_levels,
            digests_per_node_log2,
            digests_per_node_minus_one_inv_mod_u64,
        ) * (1u64 << digests_per_node_log2)
            + 1;
    }

    debug_assert!(((subtree_root_level + 1) as u32) * (digests_per_node_log2 as u32) <= 64);
    u64::trailing_bits_mask(((subtree_root_level + 1) * digests_per_node_log2) as u32)
        .wrapping_mul(digests_per_node_minus_one_inv_mod_u64)
}

#[test]
fn test_auth_subtree_node_count() {
    for digests_per_node_log2 in 1..65 {
        let digests_per_node_minus_one_inv_mod_u64 =
            digests_per_node_minus_one_inv_mod_u64(digests_per_node_log2);
        let auth_tree_levels = (u64::BITS - 1) as u8 / digests_per_node_log2 + 1;
        let mut expected = 0u64;
        for subtree_root_level in 0..auth_tree_levels {
            if digests_per_node_log2 < 64 {
                let digests_per_node = 1u64 << digests_per_node_log2;
                expected = expected
                    .checked_mul(digests_per_node)
                    .unwrap()
                    .checked_add(1)
                    .unwrap();
            } else {
                expected = 1;
            }
            assert_eq!(
                expected,
                auth_subtree_node_count(
                    subtree_root_level,
                    auth_tree_levels,
                    digests_per_node_log2,
                    digests_per_node_minus_one_inv_mod_u64
                )
            );
        }
    }
}

fn digests_per_node_minus_one_inv_mod_u64(digests_per_node_log2: u8) -> u64 {
    let digests_per_node_minus_one = u64::trailing_bits_mask(digests_per_node_log2 as u32);
    // (2^digests_per_node_log2 - 1) is its own inverse modulo
    // 2^digests_per_node_log2 ...
    debug_assert_eq!(
        digests_per_node_minus_one.wrapping_mul(digests_per_node_minus_one)
            & digests_per_node_minus_one,
        1
    );
    // ... lift it to a inverse modulo 2^64 via Hensel lifting.
    let mut e = digests_per_node_log2 as u32;
    let mut digests_per_node_minus_one_inv = digests_per_node_minus_one;
    while e < u64::BITS {
        digests_per_node_minus_one_inv = (digests_per_node_minus_one_inv << 1).wrapping_sub(
            digests_per_node_minus_one
                .wrapping_mul(digests_per_node_minus_one_inv)
                .wrapping_mul(digests_per_node_minus_one_inv),
        );
        e *= 2;
    }
    debug_assert_eq!(
        digests_per_node_minus_one_inv.wrapping_mul(digests_per_node_minus_one),
        1
    );
    digests_per_node_minus_one_inv
}

#[test]
fn test_digests_per_node_minus_one_inv_mod_u64() {
    for digests_per_node_log2 in 1u8..65 {
        let digests_per_node_minus_one = u64::trailing_bits_mask(digests_per_node_log2 as u32);
        assert_eq!(
            digests_per_node_minus_one.wrapping_mul(digests_per_node_minus_one_inv_mod_u64(
                digests_per_node_log2
            )),
            1
        );
    }
}

fn image_allocation_blocks_to_auth_tree_levels(
    image_allocation_blocks: layout::AllocBlockCount,
    digests_per_node_log2: u8,
    digests_per_node_minus_one_inv_mod_u64: u64,
    auth_tree_node_allocation_blocks_log2: u8,
    auth_tree_data_block_allocation_blocks_log2: u8,
) -> Result<u8, error::NVError> {
    let image_allocation_blocks = u64::from(image_allocation_blocks);
    let digests_per_node = 1u64 << digests_per_node_log2;
    let auth_tree_node_allocation_blocks = 1u64 << auth_tree_node_allocation_blocks_log2;
    let auth_tree_data_block_allocation_blocks =
        1u64 << auth_tree_data_block_allocation_blocks_log2;

    if image_allocation_blocks < auth_tree_node_allocation_blocks {
        return Err(error::NVError::InvalidAuthTreeDimensions);
    }

    // Let t(l) denote the collective size in units of allocation blocks occupied by
    // a full tree of height l as well as of the maximum data range covered by
    // it. Find the least l such that t(l) >= image_allocation_blocks.
    // For that, write t(l) = b * n(l) + d(l), with
    // b    := the authentication tree node size in units of allocation blocks,
    // n(l) := the number of nodes in a full tree of height l,
    // d(l) := the maximum data range covered by a full tree of height l in units of
    // allocation         blocks.
    // The following relations hold:
    // n(l) = (c^l - 1) / (c - 1),
    // d(l) = s * c^l,
    // with c := the number of each node's children and
    // s := the size of an authentication tree data block in units of allocation
    // blocks. It follows that the constraint image_allocation_blocks <= t(l) is
    // equivalent to (c - 1) * image_allocation_blocks <= (c - 1) * t(l) = (b +
    // s * (c - 1)) * c^l - b. and must be solved for minimum l.
    // Rewrite to
    // c^l >= (u * image_allocation_blocks + b) / v,
    // with u := c - 1 and v = b + s * u.
    // Because u < v and b < v, the right hand value does not overflow, but care
    // must be taken that intermediate values, the dividend to be more specific,
    // won't overflow either.  So interleave the computations of the division by
    // v and the computation of the dividend, reducing intermediate values in
    // the course.
    // Handle extreme cases first:
    if auth_tree_node_allocation_blocks > u64::MAX / 2 {
        // There won't be enough space for more than one tree node.
        return Ok(1);
    } else if u64::BITS as u8 <= auth_tree_data_block_allocation_blocks_log2 + digests_per_node_log2
    {
        // A single tree node would be capable of covering all of the maximum possible
        // image_allocation_blocks.
        return Ok(1);
    } else if image_allocation_blocks - auth_tree_node_allocation_blocks
        <= 1u64 << (auth_tree_data_block_allocation_blocks_log2 + digests_per_node_log2)
    {
        // A single tree node would be cabable of cover all of the remaining
        // space in image_allocation_blocks, after accounting for the space the
        // node itself would consume.
        return Ok(1);
    }

    let u = digests_per_node - 1;
    let v = auth_tree_node_allocation_blocks + auth_tree_data_block_allocation_blocks * u;
    debug_assert!(u < v); // u / v = 0, u % v = a
    let mut q = image_allocation_blocks / v;
    debug_assert_ne!(q, 0);
    let mut r = image_allocation_blocks - v * q;
    q *= u;
    r *= u;
    let w = r + auth_tree_node_allocation_blocks;
    let q_w = w / v;
    let r_w = w - q_w * v;
    q += q_w;
    if r_w != 0 {
        q += 1;
    }

    // Base-2 logarithm of q, rounded up.
    let q_log2 = if q != 1 { (q - 1).ilog2() + 1 } else { 0 };
    let auth_tree_levels =
        ((q_log2 + digests_per_node_log2 as u32 - 1) / digests_per_node_log2 as u32) as u8;
    let auth_tree_levels = auth_tree_levels.max(1);

    // Now, t(l) >= image_allocation_blocks for the full tree, but the final tree
    // will be a partial one truncated to make it fit image_allocation_blocks.
    // If that partial tree would have only a single child at the root node,
    // reduce the level by one. This would be the case if a single
    // subtree descendant from the root, t(l - 1), together with a path tree path
    // from top to bottom, l * b, would exceed the image_allocation_blocks.
    if auth_tree_levels > 1 {
        let root_entry_subtree_node_count = auth_subtree_node_count(
            auth_tree_levels - 2,
            auth_tree_levels - 1,
            digests_per_node_log2,
            digests_per_node_minus_one_inv_mod_u64,
        );
        let root_entry_subtree_data_allocation_blocks = 1u64
            << ((auth_tree_levels - 1) * digests_per_node_log2
                + auth_tree_data_block_allocation_blocks_log2);
        let root_entry_subtree_total_allocation_blocks = (root_entry_subtree_node_count
            << auth_tree_node_allocation_blocks_log2)
            + root_entry_subtree_data_allocation_blocks;
        debug_assert!(root_entry_subtree_total_allocation_blocks < image_allocation_blocks);
        if image_allocation_blocks - root_entry_subtree_total_allocation_blocks
            < (auth_tree_levels as u64) << auth_tree_node_allocation_blocks_log2
        {
            return Ok(auth_tree_levels - 1);
        }
    }

    Ok(auth_tree_levels)
}

#[test]
fn test_image_allocation_blocks_to_auth_tree_levels() {
    assert!(matches!(
        image_allocation_blocks_to_auth_tree_levels(layout::AllocBlockCount::from(0), 1, 1, 0, 0),
        Err(error::NVError::InvalidAuthTreeDimensions)
    ));
    for image_allocation_blocks in 1..5 {
        assert_eq!(
            image_allocation_blocks_to_auth_tree_levels(
                layout::AllocBlockCount::from(image_allocation_blocks),
                1,
                1,
                0,
                0
            )
            .unwrap(),
            1
        );
    }
    for image_allocation_blocks in 5..10 {
        assert_eq!(
            image_allocation_blocks_to_auth_tree_levels(
                layout::AllocBlockCount::from(image_allocation_blocks),
                1,
                1,
                0,
                0
            )
            .unwrap(),
            2
        );
    }
    assert_eq!(
        image_allocation_blocks_to_auth_tree_levels(layout::AllocBlockCount::from(10), 1, 1, 0, 0)
            .unwrap(),
        3
    );

    for image_allocation_blocks in [
        1u64 << 8,
        1u64 << 11,
        1u64 << 16,
        1u64 << 17,
        1u64 << 63,
        !0u64,
    ] {
        for auth_tree_node_allocation_blocks_log2 in (0..17).chain([63]) {
            for digests_per_node_log2 in [
                1u8,
                auth_tree_node_allocation_blocks_log2 + 1,
                auth_tree_node_allocation_blocks_log2 + 2,
            ] {
                if digests_per_node_log2 >= u64::BITS as u8 {
                    break;
                }
                let digests_per_node_minus_one_inv_mod_u64 =
                    digests_per_node_minus_one_inv_mod_u64(digests_per_node_log2);
                for auth_tree_data_block_allocation_blocks_log2 in 0..(64 - digests_per_node_log2) {
                    if image_allocation_blocks < (1u64 << auth_tree_node_allocation_blocks_log2) {
                        assert!(matches!(
                            image_allocation_blocks_to_auth_tree_levels(
                                layout::AllocBlockCount::from(image_allocation_blocks),
                                digests_per_node_log2,
                                digests_per_node_minus_one_inv_mod_u64,
                                auth_tree_node_allocation_blocks_log2,
                                auth_tree_data_block_allocation_blocks_log2,
                            ),
                            Err(error::NVError::InvalidAuthTreeDimensions)
                        ));
                        continue;
                    }
                    let auth_tree_levels = image_allocation_blocks_to_auth_tree_levels(
                        layout::AllocBlockCount::from(image_allocation_blocks),
                        digests_per_node_log2,
                        digests_per_node_minus_one_inv_mod_u64,
                        auth_tree_node_allocation_blocks_log2,
                        auth_tree_data_block_allocation_blocks_log2,
                    )
                    .unwrap();
                    assert!(auth_tree_levels != 0);

                    // Verify: The space occupied by a full tree should, together with the range
                    // covered by it, be >= the image size.
                    let auth_tree_node_count = auth_subtree_node_count(
                        auth_tree_levels - 1,
                        auth_tree_levels,
                        digests_per_node_log2,
                        digests_per_node_minus_one_inv_mod_u64,
                    );

                    // A tree with one level less should not be sufficient to cover all
                    // of the available space.
                    if auth_tree_levels > 1 {
                        assert!(
                            (((auth_tree_node_count - 1) >> digests_per_node_log2)
                                << auth_tree_node_allocation_blocks_log2)
                                + (1u64
                                    << ((auth_tree_levels - 1) * digests_per_node_log2
                                        + auth_tree_data_block_allocation_blocks_log2))
                                < image_allocation_blocks
                        );
                    }

                    if auth_tree_levels * digests_per_node_log2
                        + auth_tree_data_block_allocation_blocks_log2
                        >= u64::BITS as u8
                    {
                        // The data range covered exceeds an u64, so it's definitely larger than
                        // image_allocation_blocks.
                        continue;
                    }
                    let auth_tree_data_allocation_blocks = 1u64
                        << (auth_tree_levels * digests_per_node_log2
                            + auth_tree_data_block_allocation_blocks_log2);
                    if u64::MAX - auth_tree_data_allocation_blocks
                        < (auth_tree_node_count << auth_tree_node_allocation_blocks_log2)
                    {
                        // Collective tree nodes size plus covered data range
                        // exceeds an u64, so also definitely greater than
                        // image_allocation_blocks.
                        continue;
                    }
                    let t = (auth_tree_node_count << auth_tree_node_allocation_blocks_log2)
                        + auth_tree_data_allocation_blocks;
                    // There might be some excess space not allowing for an additional complete path
                    // from the root all the way to the bottom in a tree with one more level.
                    let incomplete_path_allocation_blocks =
                        (auth_tree_levels as u64) << auth_tree_node_allocation_blocks_log2;
                    assert!(
                        u64::MAX - t < incomplete_path_allocation_blocks
                            || t + incomplete_path_allocation_blocks >= image_allocation_blocks
                    );
                }
            }
        }
    }
}

fn image_allocation_blocks_to_auth_tree_node_count(
    mut image_allocation_blocks: u64,
    auth_tree_levels: u8,
    digests_per_node_log2: u8,
    digests_per_node_minus_one_inv_mod_u64: u64,
    auth_tree_node_allocation_blocks_log2: u8,
    auth_tree_data_block_allocation_blocks_log2: u8,
) -> u64 {
    // Truncate a (virtual) full authentication tree of height auth_tree_levels such
    // that it and the data covered by it will fit image_allocation_blocks.
    // Proceed from top to bottom: at each node account for the full desendant
    // subtrees emerging from it and descend into the partial one, if any.
    let auth_tree_node_allocation_blocks = 1u64 << auth_tree_node_allocation_blocks_log2;
    if image_allocation_blocks < auth_tree_node_allocation_blocks {
        return 0;
    }

    // Number of nodes in a full subtree emerging from a node at the current level.
    let mut entry_subtree_node_count = if auth_tree_levels >= 2 {
        auth_subtree_node_count(
            auth_tree_levels - 2,
            auth_tree_levels - 1,
            digests_per_node_log2,
            digests_per_node_minus_one_inv_mod_u64,
        )
    } else {
        0
    };
    // Data range covered by a full subtree emerging from a node at the current
    // level.
    let mut entry_subtree_data_allocation_blocks = 1u64
        << ((auth_tree_levels - 1) * digests_per_node_log2
            + auth_tree_data_block_allocation_blocks_log2);

    let mut auth_tree_node_count = 0;
    let mut level = auth_tree_levels;
    while level > 0 {
        level -= 1;

        let entry_subtree_total_allocation_blocks = (entry_subtree_node_count
            << auth_tree_node_allocation_blocks_log2)
            + entry_subtree_data_allocation_blocks;

        // Account for the current root node itself.
        image_allocation_blocks -= auth_tree_node_allocation_blocks;
        auth_tree_node_count += 1;
        // Full subtrees descendant of the current root node.
        let full_subtree_count = image_allocation_blocks / entry_subtree_total_allocation_blocks;
        image_allocation_blocks -= full_subtree_count * entry_subtree_total_allocation_blocks;
        auth_tree_node_count += full_subtree_count * entry_subtree_node_count;

        if image_allocation_blocks < (level as u64) << auth_tree_node_allocation_blocks_log2 {
            // Not enough space left for even a single tree path down to the bottom.
            break;
        }

        if level != 0 {
            // Update for the next iteration.
            entry_subtree_node_count = (entry_subtree_node_count - 1) >> digests_per_node_log2;
            entry_subtree_data_allocation_blocks >>= digests_per_node_log2;
        }
    }

    debug_assert!(
        level != 0
            || image_allocation_blocks < (1u64 << auth_tree_data_block_allocation_blocks_log2)
    );

    auth_tree_node_count
}

fn auth_tree_node_count_to_auth_tree_levels(
    auth_tree_node_count: u64,
    digests_per_node_log2: u8,
) -> Result<u8, error::NVError> {
    if auth_tree_node_count == 0 {
        return Err(error::NVError::InvalidAuthTreeDimensions);
    }
    debug_assert!(0 < digests_per_node_log2 && digests_per_node_log2 <= u64::BITS as u8);
    let t = if digests_per_node_log2 != u64::BITS as u8 {
        auth_tree_node_count - ((auth_tree_node_count - 1) >> digests_per_node_log2)
    } else {
        auth_tree_node_count
    };
    debug_assert_ne!(t, 0);
    let t = t
        .round_up_next_pow2()
        .ok_or(error::NVError::InvalidAuthTreeDimensions)?;
    let levels_minus_one = (t.ilog2() as u8 + digests_per_node_log2 - 1) / digests_per_node_log2;
    if levels_minus_one * digests_per_node_log2 >= u64::BITS as u8 {
        // One level less would be sufficient to cover the whole
        // range representable in an u64 already.
        return Err(error::NVError::InvalidAuthTreeDimensions);
    }
    Ok(levels_minus_one + 1)
}

#[test]
fn test_auth_tree_node_count_to_auth_tree_levels() {
    for digests_per_node_log2 in 1u8..65 {
        for auth_tree_levels in
            1..(u64::BITS as u8 + digests_per_node_log2 - 1) / digests_per_node_log2 + 1
        {
            let auth_tree_node_count = auth_subtree_node_count(
                auth_tree_levels - 1,
                auth_tree_levels,
                digests_per_node_log2,
                digests_per_node_minus_one_inv_mod_u64(digests_per_node_log2),
            );
            assert_eq!(
                auth_tree_levels,
                auth_tree_node_count_to_auth_tree_levels(
                    auth_tree_node_count,
                    digests_per_node_log2
                )
                .unwrap()
            );
            if auth_tree_node_count != 1 {
                assert_eq!(
                    auth_tree_levels,
                    auth_tree_node_count_to_auth_tree_levels(
                        auth_tree_node_count - 1,
                        digests_per_node_log2
                    )
                    .unwrap()
                );
            }
            if auth_tree_levels * digests_per_node_log2 < 64 {
                assert_eq!(
                    auth_tree_levels + 1,
                    auth_tree_node_count_to_auth_tree_levels(
                        auth_tree_node_count + 1,
                        digests_per_node_log2
                    )
                    .unwrap()
                );
            } else if auth_tree_node_count != u64::MAX {
                assert!(matches!(
                    auth_tree_node_count_to_auth_tree_levels(
                        auth_tree_node_count + 1,
                        digests_per_node_log2
                    ),
                    Err(error::NVError::InvalidAuthTreeDimensions)
                ));
            }
        }
    }
}

fn auth_tree_node_count_to_auth_tree_data_block_count(
    mut auth_tree_node_count: u64,
    auth_tree_levels: u8,
    digests_per_node_log2: u8,
    digests_per_node_minus_one_inv_mod_u64: u64,
) -> Result<u64, error::NVError> {
    if auth_tree_node_count == 0 {
        return Err(error::NVError::InvalidAuthTreeDimensions);
    }
    debug_assert!(0 < digests_per_node_log2 && digests_per_node_log2 <= u64::BITS as u8);
    debug_assert_eq!(
        auth_tree_levels,
        auth_tree_node_count_to_auth_tree_levels(auth_tree_node_count, digests_per_node_log2)
            .unwrap()
    );

    if auth_tree_levels == 1 {
        debug_assert_eq!(auth_tree_node_count, 1);
        return Ok(1u64 << digests_per_node_log2);
    }

    // Traverse the tree from top to bottom, at each level account for the
    // Authentication Tree data block range covered by the full subtrees rooted
    // at the current node's entries and descend into the partial one, if any.
    let mut auth_tree_data_block_count = 0u64;
    let mut level = auth_tree_levels;
    let mut entry_subtree_node_count = auth_subtree_node_count(
        auth_tree_levels - 1,
        auth_tree_levels,
        digests_per_node_log2,
        digests_per_node_minus_one_inv_mod_u64,
    );
    while level > 1 && auth_tree_node_count != 0 {
        if auth_tree_node_count < level as u64 {
            // No complete path from the current node down to the bottom
            // left, meaning the current node's existence makes no sense.
            return Err(error::NVError::InvalidAuthTreeDimensions);
        }
        level -= 1;
        // Remove the current node.
        auth_tree_node_count -= 1;
        // Recursively calculate the new subtree node count for one level less.
        entry_subtree_node_count = (entry_subtree_node_count - 1) >> digests_per_node_log2;
        // Remove all full subtrees rooted at entries from the current node.
        let full_entries_in_node = auth_tree_node_count / entry_subtree_node_count;
        auth_tree_node_count -= full_entries_in_node * entry_subtree_node_count;
        // And account for the Authentication Tree Data Block ranges covered by those.
        if level != 0 && level == auth_tree_levels - 1 {
            // The root node's entries could collectively cover a wider range
            // than would be representable in an u64.
            if full_entries_in_node >= 1u64 << (u64::BITS as u8 - level * digests_per_node_log2) {
                return Err(error::NVError::InvalidAuthTreeDimensions);
            }
        }
        auth_tree_data_block_count = auth_tree_data_block_count
            .checked_add(full_entries_in_node << (level * digests_per_node_log2))
            .ok_or(error::NVError::InvalidAuthTreeDimensions)?;
    }
    debug_assert_eq!(auth_tree_node_count, 0);
    Ok(auth_tree_data_block_count)
}

#[test]
fn test_auth_tree_node_count_to_auth_tree_data_block_count() {
    for digests_per_node_log2 in 1..17 {
        let digests_per_node_minus_one_inv_mod_u64 =
            digests_per_node_minus_one_inv_mod_u64(digests_per_node_log2);
        assert_eq!(
            auth_tree_node_count_to_auth_tree_data_block_count(
                1,
                1,
                digests_per_node_log2,
                digests_per_node_minus_one_inv_mod_u64
            )
            .unwrap(),
            1u64 << digests_per_node_log2
        );

        for auth_tree_levels in
            2..((u64::BITS as u8 + digests_per_node_log2 - 1) / digests_per_node_log2) + 1
        {
            let root_entry_subtree_node_count = auth_subtree_node_count(
                auth_tree_levels - 2,
                auth_tree_levels,
                digests_per_node_log2,
                digests_per_node_minus_one_inv_mod_u64,
            );
            for full_entries_in_root in 1..(1u64 << digests_per_node_log2) {
                // Incomplete paths from top to bottom in partial root entry.
                if auth_tree_levels > 2 {
                    for p in 1..auth_tree_levels - 1 {
                        assert!(matches!(
                            auth_tree_node_count_to_auth_tree_data_block_count(
                                full_entries_in_root * root_entry_subtree_node_count + 1 + p as u64,
                                auth_tree_levels,
                                digests_per_node_log2,
                                digests_per_node_minus_one_inv_mod_u64
                            ),
                            Err(error::NVError::InvalidAuthTreeDimensions)
                        ));
                    }
                }

                // Full subtrees + a single path down from the root all the way to the bottom.
                assert_eq!(
                    auth_tree_node_count_to_auth_tree_data_block_count(
                        full_entries_in_root * root_entry_subtree_node_count
                            + auth_tree_levels as u64,
                        auth_tree_levels,
                        digests_per_node_log2,
                        digests_per_node_minus_one_inv_mod_u64
                    )
                    .unwrap(),
                    (full_entries_in_root << ((auth_tree_levels - 1) * digests_per_node_log2))
                        + (1u64 << digests_per_node_log2)
                );

                // Only full subtrees emerging from the root.
                if u64::MAX
                    - (full_entries_in_root << ((auth_tree_levels - 1) * digests_per_node_log2))
                    < 1u64 << ((auth_tree_levels - 1) * digests_per_node_log2)
                {
                    // The data range covered by one more full tree entry would exceed an u64.
                    break;
                }
                assert_eq!(
                    auth_tree_node_count_to_auth_tree_data_block_count(
                        1 + (full_entries_in_root + 1) * root_entry_subtree_node_count,
                        auth_tree_levels,
                        digests_per_node_log2,
                        digests_per_node_minus_one_inv_mod_u64
                    )
                    .unwrap(),
                    (full_entries_in_root + 1) << ((auth_tree_levels - 1) * digests_per_node_log2)
                );
            }
        }
    }
}

fn auth_tree_data_block_index_to_auth_tree_node_entry(
    auth_tree_data_block_index: AuthTreeDataBlockIndex,
    auth_tree_node_level: u8,
    auth_tree_levels: u8,
    digests_per_node_log2: u8,
    digests_per_node_minus_one_inv_mod_u64: u64,
) -> (u64, usize) {
    debug_assert!(auth_tree_levels > 0);
    debug_assert!(auth_tree_node_level < auth_tree_levels);

    let child_entry_index_mask = u64::trailing_bits_mask(digests_per_node_log2 as u32);
    let mut index =
        u64::from(auth_tree_data_block_index) >> (auth_tree_node_level * digests_per_node_log2);
    let entry_in_node_index = (index & child_entry_index_mask) as usize;
    if auth_tree_node_level + 1 == auth_tree_levels {
        return (0, entry_in_node_index);
    }

    // Calculate the DFS PRE index of the Authentication Tree node at the requested
    // level on the path to the given data block: traverse the tree from bottom
    // to top, at each (parent) node account for the full subtrees rooted at the
    // preceeding sibling entries each as well as for the parent node itself and
    // move further up.
    // The Authentication Tree's total node count will always fit an u64, c.f.
    // the reasoning in auth_subtree_node_count(). Thus, the computation of
    // node_dfs_pre_index, which is strictly less than that, won't overflow either.
    let mut node_dfs_pre_index = 0;
    // The size of each subtree rooted right below the current parent node level.
    let mut entry_subtree_node_count = auth_subtree_node_count(
        auth_tree_node_level,
        auth_tree_levels,
        digests_per_node_log2,
        digests_per_node_minus_one_inv_mod_u64,
    );
    for _parent_level in auth_tree_node_level + 1..auth_tree_levels {
        index >>= digests_per_node_log2;
        let entry_in_parent_node = index & child_entry_index_mask;

        // Skip all the preceeding siblings' subtree nodes.
        node_dfs_pre_index += entry_subtree_node_count * entry_in_parent_node;
        // And account for the current parent node itself.
        node_dfs_pre_index += 1;

        // Calculate the next round's subtree node count recursively.
        // In the very last round, this can overflow but won't get used.
        entry_subtree_node_count =
            (entry_subtree_node_count << digests_per_node_log2).wrapping_add(1);
    }
    (node_dfs_pre_index, entry_in_node_index)
}
