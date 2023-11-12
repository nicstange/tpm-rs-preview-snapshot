// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Definition of the [`NVChip`] trait.

extern crate alloc;
use super::{chunked_io_region, error};
use alloc::sync;
use chunked_io_region::{ChunkedIoRegion, ChunkedIoRegionChunkRange};
use core::{future, ops, pin, marker};
use error::NVError;

/// Common interface to NV memory backend implementations.
pub trait NVChip {
    /// The minium IO unit guaranteed not to affect neighbouring blocks,
    /// referred to in this documentation as "Chip IO Block" size. To be
    /// returned as the base-2 logarithm of that minimum Chip IO Block size as
    /// given in units of 128 Byte multiples.
    fn chip_io_block_size_128b_log2(&self) -> u32;

    /// The current size of the backing NV memory in units of [Chip IO
    /// Blocks](Self::chip_io_block_size_128b_log2).
    fn chip_io_blocks(&self) -> u64;

    /// Optimum number of [Chip IO
    /// Blocks](Self::chip_io_block_size_128b_log2) to process at
    /// once, returned as a base-2 logarithm. For example, a memory-backed
    /// implementation might guarantee that writes to individual 128 Byte
    /// allocation units won't affect neighbouring data, but prefer IO to
    /// processed in units of 4K pages for performance reasons.
    fn preferred_chip_io_blocks_bulk_log2(&self) -> u32;

    type ResizeFuture: future::Future<Output = Result<(), NVError>>;

    /// Attempt to resize, i.e. grow or shrink, the backing NV memory.
    /// If unsupported, an error of [`NVError::OperationNotSupported`] shall get
    /// returned.
    ///
    /// # Arguments:
    ///
    /// * chip_io_blocks_count` - The new size, in units of [Chip IO
    ///   Blocks](Self::chip_io_block_size_128b_log2).
    fn resize(
        self: &pin::Pin<sync::Arc<Self>>,
        chip_io_blocks_count: u64,
    ) -> Result<Self::ResizeFuture, NVError>;

    type ReadFuture<R: NVChipReadRequest>: future::Future<Output = (R, Result<(), NVError>)> + marker::Unpin;

    /// Read data from the NV memory chip.
    ///
    /// # Arguments:
    ///
    /// * `request` - The [`NVChipReadRequest`] describing where to read from as
    ///   well as providing access to the destination buffers receiving the
    ///   result. The associated range is guaranteed to be
    ///   [aligned](ChunkedIoRegion::is_aligned) to [Chip IO
    ///   Blocks](Self::chip_io_block_size_128b_log2).
    fn read<R: NVChipReadRequest>(
        self: &pin::Pin<sync::Arc<Self>>,
        request: R,
    ) -> Result<Self::ReadFuture<R>, (R, NVError)>;

    type WriteFuture<R: NVChipWriteRequest>: future::Future<Output = (R, Result<(), NVError>)> + marker::Unpin;

    /// Write data to the NV memory chip.
    ///
    /// # Arguments:
    ///
    /// * `request` - The [`NVChipWriteRequest`] describing where to write to as
    ///   well as providing access to the source buffers to take the data from.
    ///   The associated range is guaranteed to be
    ///   [aligned](ChunkedIoRegion::is_aligned) to [Chip IO
    ///   Blocks](Self::chip_io_block_size_128b_log2).
    fn write<R: NVChipWriteRequest>(
        self: &pin::Pin<sync::Arc<Self>>,
        request: R,
    ) -> Result<Self::WriteFuture<R>, (R, NVError)>;

    type WriteSyncFuture: future::Future<Output = Result<(), NVError>>;

    /// Sync all pending writes to the backing NV memory.
    fn write_sync(self: &pin::Pin<sync::Arc<Self>>) -> Result<Self::WriteSyncFuture, NVError>;

    type TrimFuture: future::Future<Output = Result<(), NVError>>;

    /// Discard a given range of NV memory.
    ///
    /// This is a hint issued by the NV core code informing the NV memory device
    /// that the specified range is considered being unused from now and will
    /// never be read again without a prior write. Implementations may return
    /// [`NVError::OperationNotSupported`].
    ///
    /// # Arguments:
    ///
    /// * - `chip_io_block_index` - Index of the first [Chip IO
    ///   Block](Self::chip_io_block_size_128b_log2) to discard.
    /// * - `chip_io_blocks_count` - The number of [Chip IO
    ///   Blocks](Self::chip_io_block_size_128b_log2) to discard.
    fn trim(
        self: &pin::Pin<sync::Arc<Self>>,
        chip_io_block_index: u64,
        chip_io_blocks_count: usize,
    ) -> Result<Self::TrimFuture, NVError>;
}

/// Trait defining the common interface to [`NVChip`] write requests to be
/// submitted to [`write()`](NVChip::write).
///
/// The `NVChipWriteRequest` interface is intended to provide a means to obtain
/// all required information about the write destination location as well as
/// access to the source data buffers in a generic way. Note that the
/// [`NVChipWriteRequest`] instance is always getting returned again one way or
/// the other out of [`write()`](NVChip::write) or the associated
/// [`WriteFuture`](NVChip::WriteFuture) respectively, enabling temporary
/// ownership transfers of any required ressources, like e.g. the source
/// buffers, for the duration of the write request.
///
/// The write request source data may be split across equally sized buffers,
/// so-called "chunks", whose layout is described alongside the physical write
/// destination location by means of the [`ChunkedIoRegion`] returned by
/// [`region()`](Self::region). The region is required to be
/// [aligned](ChunkedIoRegion::is_aligned) to the [Chip IO
/// Block](NVChip::chip_io_block_size_128b_log2) size.
///
/// Access to the chunked source buffers is provided by making the
/// [`NVChipWriteRequest`] instance indexable with [`ChunkedIoRegionChunkRange`]
/// "indices" emitted by the aforementioned
/// [`ChunkedIoRegion`]'s iterators.
pub trait NVChipWriteRequest
where
    for<'a> Self: ops::Index<&'a ChunkedIoRegionChunkRange, Output = [u8]>,
{
    /// Return a [`ChunkedIoRegion`] describing the buffer layout as well as the
    /// physical destination of the write request.
    /// [`ChunkedIoRegionChunkRange`]s obtained from its iterators will be
    /// used to index `Self`, thereby getting access to the individual
    /// source buffers.
    fn region(&self) -> &ChunkedIoRegion;
}

/// Trait defining the common interface to [`NVChip`] read requests to be
/// submitted to [`read()`](NVChip::read).
///
/// The `NVChipReadRequest` interface is intended to provide a means to obtain
/// all required information about the read source location as well as access to
/// the destination data buffers in a generic way. Note that the
/// [`NVChipReadRequest`] instance is always getting returned again one way or
/// the other out of [`read()`](NVChip::read) or the associated
/// [`ReadFuture`](NVChip::ReadFuture) respectively, enabling temporary
/// ownership transfers of any required ressources, like e.g. the source
/// buffers, for the duration of the read request.
///
/// The read request destination memory may be split across equally sized
/// buffers, so-called "chunks", whose layout is described alongside the
/// physical read source location by means of the [`ChunkedIoRegion`] returned
/// by [`region()`](Self::region). The region is required to be
/// [aligned](ChunkedIoRegion::is_aligned) to the [Chip IO
/// Block](NVChip::chip_io_block_size_128b_log2) size.
///
/// Access to the chunked destination buffers is provided by making the
/// [`NVChipReadRequest`] instance indexable with [`ChunkedIoRegionChunkRange`]
/// "indices" emitted by the aforementioned
/// [`ChunkedIoRegion`]'s iterators.
pub trait NVChipReadRequest
where
    for<'a> Self: ops::Index<&'a ChunkedIoRegionChunkRange, Output = [u8]>
        + ops::IndexMut<&'a ChunkedIoRegionChunkRange>,
{
    /// Return a [`ChunkedIoRegion`] describing the buffer layout as well as the
    /// physical source of the read request.
    /// [`ChunkedIoRegionChunkRange`]s obtained from its iterators will be
    /// used to index `Self`, thereby getting access to the individual
    /// destination buffers.
    fn region(&self) -> &ChunkedIoRegion;
}
