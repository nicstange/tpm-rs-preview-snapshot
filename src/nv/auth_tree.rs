extern crate alloc;
use super::{cache, error, extents, index, keys, layout};
use super::{chip, chunked_io_region};
use crate::crypto::{ct_cmp, hash, io_slices};
use crate::interface;
use crate::nv::auth_tree;
use crate::sync_types;
use crate::utils;
use alloc::{sync, vec};
use core::{future, marker, ops, pin, slice, task};
use ops::DerefMut as _;
use utils::bitmanip::{BitManip as _, UBitManip as _};
use utils::{asynchronous, cfg_zeroize};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct AuthTreeNodeCacheId {
    covered_auth_tree_data_blocks_begin: u64,
    level: u8,
}

impl AuthTreeNodeCacheId {
    fn new(covered_auth_tree_data_blocks_begin: u64, level: u8, digests_per_node_log2: u8) -> Self {
        Self {
            covered_auth_tree_data_blocks_begin: covered_auth_tree_data_blocks_begin
                & !u64::trailing_bits_mask((level * digests_per_node_log2) as u32),
            level,
        }
    }
}

struct AuthTreeNode {
    data: vec::Vec<u8>,
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

    digests_per_node_log2: u8,
    digests_per_node_minus_one_inv_mod_u64: u64,

    auth_tree_levels: u8,
    auth_tree_data_block_count: u64,

    auth_tree_node_cache: sync::Arc<cache::Cache<ST, AuthTreeNodeCacheId, AuthTreeNode>>,

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
        node_id: &AuthTreeNodeCacheId,
    ) -> Result<chunked_io_region::ChunkedIoRegion, error::NVError> {
        debug_assert!(node_id.level < self.auth_tree_levels);
        debug_assert_eq!(
            node_id.covered_auth_tree_data_blocks_begin
                & u64::trailing_bits_mask((node_id.level * self.digests_per_node_log2) as u32),
            0
        );
        if node_id.covered_auth_tree_data_blocks_begin >= self.auth_tree_data_block_count {
            return Err(error::NVError::IOBlockOutOfRange);
        }
        let dfs_pre_node_index = phys_auth_tree_data_block_index_to_auth_tree_node_entry(
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

    fn hmac_root_node(&self, node_data: &[u8]) -> Result<vec::Vec<u8>, error::NVError> {
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
            Some(node_data),
        ]));
        h.finalize_into(&mut root_hmac_digest);
        Ok(root_hmac_digest)
    }

    fn authenticate_root_node(&self, node_data: &[u8]) -> Result<(), error::NVError> {
        let root_hmac_digest = self.hmac_root_node(node_data)?;
        if ct_cmp::ct_bytes_eq(&root_hmac_digest, &self.auth_hmac_digest).unwrap() != 0 {
            Ok(())
        } else {
            Err(error::NVError::AuthenticationFailure)
        }
    }

    fn digest_descendant_node(&self, node_data: &[u8]) -> Result<vec::Vec<u8>, error::NVError> {
        debug_assert_eq!(node_data.len(), self.auth_tree_node_size());
        let digest_len = self.auth_tree_digest_len as usize;
        let mut node_digest = utils::try_alloc_vec(digest_len)?;
        let mut h = hash::HashInstance::new(self.auth_tree_hash_alg);
        h.update(io_slices::IoSlices::new(&mut [
            Some(slice::from_ref(
                &(AuthSubjectDataPrefix::AuthTreeDescendantNode as u8),
            )),
            Some(node_data),
        ]));
        h.finalize_into(&mut node_digest);
        Ok(node_digest)
    }

    fn authenticate_descendant_node(
        &self,
        node_id: &AuthTreeNodeCacheId,
        node_data: &[u8],
        parent_node: &AuthTreeNode,
    ) -> Result<(), error::NVError> {
        let node_digest = self.digest_descendant_node(node_data)?;
        let digest_len = self.auth_tree_digest_len as usize;
        let entry_in_parent = ((node_id.covered_auth_tree_data_blocks_begin
            >> (node_id.level * self.digests_per_node_log2))
            & u64::trailing_bits_mask(self.digests_per_node_log2 as u32))
            as usize;
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
        data_block_begin: layout::PhysicalAllocBlockIndex,
        mut data_block_allocation_blocks_iter: ABI,
        parent_node: &AuthTreeNode,
    ) -> Result<ABI, error::NVError> {
        let block_digest = self.digest_data_block(&mut data_block_allocation_blocks_iter)?;
        let digest_len = self.auth_tree_digest_len as usize;
        let entry_in_parent =
            ((u64::from(data_block_begin) >> self.auth_tree_data_block_allocation_blocks_log2)
                & u64::trailing_bits_mask(self.digests_per_node_log2 as u32)) as usize;
        let expected_block_digest_begin = entry_in_parent * digest_len;
        let expected_block_digest = &parent_node.data
            [expected_block_digest_begin..expected_block_digest_begin + digest_len];
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
    node_id: AuthTreeNodeCacheId,
    auth_tree_levels: u8,
    digests_per_node_log2: u8,
}

#[derive(Clone, Copy)]
struct AuthTreePathNodesIterator<'a> {
    path: &'a AuthTreePath,
    level: u8,
}

impl<'a> Iterator for AuthTreePathNodesIterator<'a> {
    type Item = AuthTreeNodeCacheId;

    fn next(&mut self) -> Option<Self::Item> {
        if self.level == self.path.auth_tree_levels {
            return None;
        }
        let level = self.level;
        self.level += 1;

        let covered_auth_tree_data_blocks_begin =
            self.path.node_id.covered_auth_tree_data_blocks_begin
                & !u64::trailing_bits_mask((level * self.path.digests_per_node_log2) as u32);
        Some(AuthTreeNodeCacheId {
            covered_auth_tree_data_blocks_begin,
            level,
        })
    }
}

impl cache::CacheKeys<AuthTreeNodeCacheId> for AuthTreePath {
    type Iterator<'a> = AuthTreePathNodesIterator<'a>;

    fn iter(&self) -> Self::Iterator<'_> {
        AuthTreePathNodesIterator {
            path: self,
            level: self.node_id.level,
        }
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
        auth_tree_node_id: AuthTreeNodeCacheId,
        reserve_cache_slots_fut: cache::CacheReserveSlotsFuture<
            ST,
            AuthTreeNodeCacheId,
            AuthTreeNode,
            AuthTreeNodeCacheId,
            AuthTreePath,
        >,
    },
    ReadAndVerifyBranchNodes {
        tree_lock: Option<TL>,
        auth_tree_node_id: AuthTreeNodeCacheId,
        cache_reservations:
            vec::Vec<cache::CacheSlotReservation<ST, AuthTreeNodeCacheId, AuthTreeNode>>,
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
        auth_tree_node_id: AuthTreeNodeCacheId,
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
        auth_tree_node_id: &AuthTreeNodeCacheId,
        current_level: u8,
    ) -> Result<C::ReadFuture<AuthTreeNodeNvReadRequest>, error::NVError> {
        let dst_buf = utils::try_alloc_vec(tree.auth_tree_node_size())?;
        let node_id = AuthTreeNodeCacheId::new(
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
        Result<cache::CacheSlotReservation<ST, AuthTreeNodeCacheId, AuthTreeNode>, error::NVError>,
    );

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
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

                    // Got the cache slot reservations for all nodes up to (including) the
                    // root. Check what's already there.
                    let first_cached_index =
                        cache_reservations.iter().position(|r| r.lock().is_some());
                    if let Some(0) = first_cached_index {
                        cache_reservations.truncate(1);
                        let cache_reservation = cache_reservations.pop().unwrap();
                        return task::Poll::Ready((tree_lock, Ok(cache_reservation)));
                    }
                    // Submit a request for reading the topmost Authentication Tree node not yet in
                    // the cache and transition the future to the next state.
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

                    // Got the current_level node's data from the backing storage. Verify it using
                    // either the already verified parent or, if the root, by
                    // the HMAC.
                    let AuthTreeNodeNvReadRequest {
                        dst_buf: node_data,
                        io_region: _,
                    } = node_read_request;
                    if *current_level != tree_lock.auth_tree_levels - 1 {
                        let node_id = AuthTreeNodeCacheId::new(
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

                    // Either move down to the next node and continue the verification chain or,
                    // once the bottom/requested level has been reached, return
                    // the result.
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

pub trait AuthTreeDataBlockUpdate {
    type AllocationBlockIterator<'a>: Iterator<Item = Option<&'a [u8]>>
    where
        Self: 'a;

    fn data_block_allocation_blocks_iter(&self) -> Self::AllocationBlockIterator<'_>;
}

pub trait AuthTreeDataBlocksUpdates {
    type AuthTreeDataBlockUpdate: AuthTreeDataBlockUpdate;

    type PrepareAuthTreeDataBlockUpdate: future::Future<
            Output = Result<
                (
                    layout::PhysicalAllocBlockIndex,
                    Self::AuthTreeDataBlockUpdate,
                ),
                error::NVError,
            >,
        > + marker::Unpin;

    fn next_data_block_update(
        &mut self,
    ) -> Result<
        Option<(
            layout::PhysicalAllocBlockIndex,
            Self::PrepareAuthTreeDataBlockUpdate,
        )>,
        error::NVError,
    >;
}

// pub enum AuthTreeUpdateFuture<ST: sync_types::SyncTypes, C: chip::NVChip> {}

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

// fn auth_tree_node_count_to_image_allocation_blocks(
//     auth_tree_node_count: u64,
//     auth_tree_levels: u8,
//     digests_per_node_log2: u8,
//     digests_per_node_minus_one_inv_mod_u64: u64,
//     auth_tree_data_block_allocation_blocks_log2: u8,
// ) -> Result<u64, error::NVError> { debug_assert_eq!( auth_tree_levels,
//   auth_tree_node_count_to_auth_tree_levels(auth_tree_node_count,
//   digests_per_node_log2) .unwrap() ); let auth_tree_data_block_count =
//   auth_tree_node_count_to_auth_tree_data_block_count( auth_tree_node_count,
//   auth_tree_levels, digests_per_node_log2,
//   digests_per_node_minus_one_inv_mod_u64, )?;

//     if auth_tree_data_block_allocation_blocks_log2 != 0
//         && auth_tree_data_block_count
//             >= 1u64 << (u64::BITS as u8 -
// auth_tree_data_block_allocation_blocks_log2)     {
//         return Err(error::NVError::InvalidAuthTreeDimensions);
//     }
//     Ok(auth_tree_data_block_count <<
// auth_tree_data_block_allocation_blocks_log2) }

fn phys_auth_tree_data_block_index_to_auth_tree_node_entry(
    auth_tree_data_block_index: u64,
    auth_tree_node_level: u8,
    auth_tree_levels: u8,
    digests_per_node_log2: u8,
    digests_per_node_minus_one_inv_mod_u64: u64,
) -> (u64, usize) {
    debug_assert!(auth_tree_levels > 0);
    debug_assert!(auth_tree_node_level < auth_tree_levels);

    let child_entry_index_mask = u64::trailing_bits_mask(digests_per_node_log2 as u32);
    let mut index = auth_tree_data_block_index >> (auth_tree_node_level * digests_per_node_log2);
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

fn phys_allocation_block_index_to_auth_tree_node_entry(
    phys_allocation_block_index: layout::PhysicalAllocBlockIndex,
    auth_tree_node_level: u8,
    auth_tree_levels: u8,
    digests_per_node_log2: u8,
    digests_per_node_minus_one_inv_mod_u64: u64,
    auth_tree_data_block_allocation_blocks_log2: u8,
) -> (u64, usize) {
    let phys_allocation_block_index = u64::from(phys_allocation_block_index);
    let auth_tree_data_block_index =
        phys_allocation_block_index >> auth_tree_data_block_allocation_blocks_log2;
    phys_auth_tree_data_block_index_to_auth_tree_node_entry(
        auth_tree_data_block_index,
        auth_tree_node_level,
        auth_tree_levels,
        digests_per_node_log2,
        digests_per_node_minus_one_inv_mod_u64,
    )
}
