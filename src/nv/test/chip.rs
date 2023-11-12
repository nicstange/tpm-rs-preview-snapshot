// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use crate::nv;
use crate::nv::chunked_io_region;
use crate::sync_types::Lock as _;
use crate::sync_types::SyncTypes;
use crate::utils::asynchronous::test::executor::TestNopSyncTypes;
use alloc::{sync, vec};
use core::{future, mem, ops, pin, task};
use nv::chip;
use nv::error::NVError;
use ops::{Deref as _, DerefMut as _};

pub struct TestNVChip {
    chip_io_blocks: <TestNopSyncTypes as SyncTypes>::Lock<vec::Vec<Option<vec::Vec<u8>>>>,
    chip_io_block_size_128b_log2: u32,
    preferred_chip_io_blocks_bulk_log2: u32,
}

impl TestNVChip {
    pub fn new(
        chip_io_block_size_128b_log2: u32,
        chip_io_blocks_count: u64,
        preferred_chip_io_blocks_bulk_log2: u32,
    ) -> sync::Arc<Self> {
        let mut chip_io_blocks = vec::Vec::new();
        let chip_io_blocks_count = usize::try_from(chip_io_blocks_count).unwrap();
        chip_io_blocks.resize(chip_io_blocks_count, None);
        sync::Arc::new(Self {
            chip_io_blocks: <TestNopSyncTypes as SyncTypes>::Lock::from(chip_io_blocks),
            chip_io_block_size_128b_log2,
            preferred_chip_io_blocks_bulk_log2,
        })
    }

    fn _read_chunked_io_region(
        &self,
        request: &mut dyn chip::NVChipReadRequest,
        io_region: chunked_io_region::ChunkedIoRegion,
        chip_io_blocks_bulk_log2: u32,
    ) -> Result<(), NVError> {
        let chip_io_blocks = self.chip_io_blocks.lock();
        for (physical_bulk_index, bulk_chunks) in io_region
            .aligned_blocks_iter(chip_io_blocks_bulk_log2 + self.chip_io_block_size_128b_log2)
            .unwrap()
        {
            let bulk_first_chip_io_block_index =
                match physical_bulk_index.checked_shl(chip_io_blocks_bulk_log2) {
                    Some(chip_io_block_index) => chip_io_block_index,
                    None => return Err(NVError::IOBlockOutOfRange),
                };
            let bulk_first_chip_io_block_index =
                match usize::try_from(bulk_first_chip_io_block_index) {
                    Ok(chip_io_block_index) => chip_io_block_index,
                    Err(_) => return Err(NVError::IOBlockOutOfRange),
                };

            for (offset_in_bulk_128b, bulk_chunk_range) in bulk_chunks {
                let offset_in_bulk_128b = usize::try_from(offset_in_bulk_128b).unwrap();
                let chip_io_block_index_in_bulk =
                    offset_in_bulk_128b >> self.chip_io_block_size_128b_log2;
                let mut chip_io_block_index =
                    match bulk_first_chip_io_block_index.checked_add(chip_io_block_index_in_bulk) {
                        Some(chip_io_block_index) => chip_io_block_index,
                        None => return Err(NVError::IOBlockOutOfRange),
                    };

                let chip_io_block_size_128b = 1usize << self.chip_io_block_size_128b_log2;
                let chip_io_block_size = chip_io_block_size_128b << 7;
                let offset_in_chip_io_block_128b =
                    offset_in_bulk_128b & (chip_io_block_size_128b - 1);
                let mut offset_in_chip_io_block = offset_in_chip_io_block_128b << 7;
                let dst_bulk_chunk_slice = request.index_mut(&bulk_chunk_range);
                debug_assert!(
                    dst_bulk_chunk_slice.len() <= chip_io_block_size << chip_io_blocks_bulk_log2
                );
                debug_assert!(
                    dst_bulk_chunk_slice.len() < chip_io_block_size
                        || (dst_bulk_chunk_slice.len() % chip_io_block_size == 0
                            && offset_in_chip_io_block == 0)
                );
                let mut bytes_copied = 0;
                while bytes_copied < dst_bulk_chunk_slice.len() {
                    if chip_io_block_index >= chip_io_blocks.len() {
                        return Err(NVError::IOBlockOutOfRange);
                    }
                    let chip_io_block = match chip_io_blocks[chip_io_block_index].as_ref() {
                        Some(chip_io_block) => chip_io_block,
                        None => return Err(NVError::IOBlockNotMapped),
                    };

                    let bytes_remaining = dst_bulk_chunk_slice.len() - bytes_copied;
                    let bytes_to_copy =
                        bytes_remaining.min(chip_io_block_size - offset_in_chip_io_block);

                    dst_bulk_chunk_slice[bytes_copied..bytes_copied + bytes_to_copy]
                        .copy_from_slice(
                            &chip_io_block
                                [offset_in_chip_io_block..offset_in_chip_io_block + bytes_to_copy],
                        );
                    chip_io_block_index += 1;
                    offset_in_chip_io_block = 0;
                    bytes_copied += bytes_to_copy;
                }
            }
        }
        Ok(())
    }

    fn process_read_request(
        &self,
        request: &mut dyn chip::NVChipReadRequest,
    ) -> Result<(), NVError> {
        let io_range = request.region();
        let (unaligned_head, aligned_tail) = io_range
            .align_to(self.preferred_chip_io_blocks_bulk_log2 + self.chip_io_block_size_128b_log2);
        self._read_chunked_io_region(request, unaligned_head, 0)?;
        if let Some((aligned, unaligned_tail)) = aligned_tail {
            self._read_chunked_io_region(
                request,
                aligned,
                self.preferred_chip_io_blocks_bulk_log2,
            )?;
            self._read_chunked_io_region(request, unaligned_tail, 0)?;
        }
        Ok(())
    }

    fn _write_chunked_io_region(
        &self,
        request: &dyn chip::NVChipWriteRequest,
        io_region: chunked_io_region::ChunkedIoRegion,
        chip_io_blocks_bulk_log2: u32,
    ) -> Result<(), NVError> {
        let mut chip_io_blocks = self.chip_io_blocks.lock();
        for (physical_bulk_index, bulk_chunks) in io_region
            .aligned_blocks_iter(chip_io_blocks_bulk_log2 + self.chip_io_block_size_128b_log2)
            .unwrap()
        {
            let bulk_first_chip_io_block_index =
                match physical_bulk_index.checked_shl(chip_io_blocks_bulk_log2) {
                    Some(chip_io_block_index) => chip_io_block_index,
                    None => return Err(NVError::IOBlockOutOfRange),
                };
            let bulk_first_chip_io_block_index =
                match usize::try_from(bulk_first_chip_io_block_index) {
                    Ok(chip_io_block_index) => chip_io_block_index,
                    Err(_) => return Err(NVError::IOBlockOutOfRange),
                };

            for (offset_in_bulk_128b, bulk_chunk_range) in bulk_chunks {
                let offset_in_bulk_128b = usize::try_from(offset_in_bulk_128b).unwrap();
                let chip_io_block_index_in_bulk =
                    offset_in_bulk_128b >> self.chip_io_block_size_128b_log2;
                let mut chip_io_block_index =
                    match bulk_first_chip_io_block_index.checked_add(chip_io_block_index_in_bulk) {
                        Some(chip_io_block_index) => chip_io_block_index,
                        None => return Err(NVError::IOBlockOutOfRange),
                    };

                let chip_io_block_size_128b = 1usize << self.chip_io_block_size_128b_log2;
                let chip_io_block_size = chip_io_block_size_128b << 7;
                let offset_in_chip_io_block_128b =
                    offset_in_bulk_128b & (chip_io_block_size_128b - 1);
                let mut offset_in_chip_io_block = offset_in_chip_io_block_128b << 7;
                let src_bulk_chunk_slice = request.index(&bulk_chunk_range);
                debug_assert!(
                    src_bulk_chunk_slice.len() <= chip_io_block_size << chip_io_blocks_bulk_log2
                );
                debug_assert!(
                    src_bulk_chunk_slice.len() < chip_io_block_size
                        || (src_bulk_chunk_slice.len() % chip_io_block_size == 0
                            && offset_in_chip_io_block == 0)
                );
                let mut bytes_copied = 0;
                while bytes_copied < src_bulk_chunk_slice.len() {
                    if chip_io_block_index >= chip_io_blocks.len() {
                        return Err(NVError::IOBlockOutOfRange);
                    }

                    if chip_io_blocks[chip_io_block_index].is_none() {
                        let mut block_buf = vec::Vec::new();
                        block_buf.resize(chip_io_block_size, 0);
                        chip_io_blocks[chip_io_block_index] = Some(block_buf);
                    }
                    let chip_io_block = chip_io_blocks[chip_io_block_index].as_mut().unwrap();

                    let bytes_remaining = src_bulk_chunk_slice.len() - bytes_copied;
                    let bytes_to_copy =
                        bytes_remaining.min(chip_io_block_size - offset_in_chip_io_block);

                    chip_io_block[offset_in_chip_io_block..offset_in_chip_io_block + bytes_to_copy]
                        .copy_from_slice(
                            &src_bulk_chunk_slice[bytes_copied..bytes_copied + bytes_to_copy],
                        );
                    chip_io_block_index += 1;
                    offset_in_chip_io_block = 0;
                    bytes_copied += bytes_to_copy;
                }
            }
        }
        Ok(())
    }

    fn process_write_request(&self, request: &dyn chip::NVChipWriteRequest) -> Result<(), NVError> {
        let io_range = request.region();
        let (unaligned_head, aligned_tail) = io_range
            .align_to(self.preferred_chip_io_blocks_bulk_log2 + self.chip_io_block_size_128b_log2);
        self._write_chunked_io_region(request, unaligned_head, 0)?;
        if let Some((aligned, unaligned_tail)) = aligned_tail {
            self._write_chunked_io_region(
                request,
                aligned,
                self.preferred_chip_io_blocks_bulk_log2,
            )?;
            self._write_chunked_io_region(request, unaligned_tail, 0)?;
        }
        Ok(())
    }
}

impl chip::NVChip for TestNVChip {
    fn chip_io_block_size_128b_log2(&self) -> u32 {
        self.chip_io_block_size_128b_log2
    }

    fn chip_io_blocks(&self) -> u64 {
        u64::try_from(self.chip_io_blocks.lock().len()).unwrap()
    }

    fn preferred_chip_io_blocks_bulk_log2(&self) -> u32 {
        self.preferred_chip_io_blocks_bulk_log2
    }

    type ResizeFuture = TestNVChipResizeFuture;
    fn resize(
        self: &pin::Pin<sync::Arc<Self>>,
        chip_io_blocks_count: u64,
    ) -> Result<Self::ResizeFuture, NVError> {
        Ok(TestNVChipResizeFuture::Init {
            c: self.clone(),
            chip_io_blocks_count,
        })
    }

    type ReadFuture<R: chip::NVChipReadRequest> = TestNVChipReadFuture<R>;
    fn read<R: chip::NVChipReadRequest>(
        self: &pin::Pin<sync::Arc<Self>>,
        request: R,
    ) -> Result<Self::ReadFuture<R>, (R, NVError)> {
        Ok(TestNVChipReadFuture::Init {
            c: self.clone(),
            request,
        })
    }

    type WriteFuture<R: chip::NVChipWriteRequest> = TestNVChipWriteFuture<R>;
    fn write<R: chip::NVChipWriteRequest>(
        self: &pin::Pin<sync::Arc<Self>>,
        request: R,
    ) -> Result<Self::WriteFuture<R>, (R, NVError)> {
        Ok(TestNVChipWriteFuture::Init {
            c: self.clone(),
            request,
        })
    }

    type WriteSyncFuture = TestNVChipWriteSyncFuture;
    fn write_sync(self: &pin::Pin<sync::Arc<Self>>) -> Result<Self::WriteSyncFuture, NVError> {
        Ok(TestNVChipWriteSyncFuture::Init)
    }

    type TrimFuture = TestNVChipTrimFuture;
    fn trim(
        self: &pin::Pin<sync::Arc<Self>>,
        chip_io_block_index: u64,
        chip_io_blocks_count: usize,
    ) -> Result<Self::TrimFuture, NVError> {
        Ok(TestNVChipTrimFuture::Init {
            c: self.clone(),
            chip_io_block_index,
            chip_io_blocks_count,
        })
    }
}

pub enum TestNVChipResizeFuture {
    Init {
        c: pin::Pin<sync::Arc<TestNVChip>>,
        chip_io_blocks_count: u64,
    },
    PolledOnce {
        c: pin::Pin<sync::Arc<TestNVChip>>,
        chip_io_blocks_count: u64,
    },
    Done,
}

impl Unpin for TestNVChipResizeFuture {}

impl future::Future for TestNVChipResizeFuture {
    type Output = Result<(), NVError>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        match self.deref_mut() {
            Self::Init {
                c,
                chip_io_blocks_count,
            } => {
                *self = Self::PolledOnce {
                    c: c.clone(),
                    chip_io_blocks_count: *chip_io_blocks_count,
                };
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Self::PolledOnce {
                c,
                chip_io_blocks_count,
            } => {
                let mut chip_io_blocks = c.chip_io_blocks.lock();
                let chip_io_blocks_count = usize::try_from(*chip_io_blocks_count).unwrap();
                chip_io_blocks.resize(chip_io_blocks_count, None);
                drop(chip_io_blocks);
                *self = Self::Done;
                task::Poll::Ready(Ok(()))
            }
            Self::Done => {
                unreachable!("Attempt to poll completed future.")
            }
        }
    }
}

pub enum TestNVChipReadFuture<R: chip::NVChipReadRequest> {
    Init {
        c: pin::Pin<sync::Arc<TestNVChip>>,
        request: R,
    },
    PolledOnce {
        c: pin::Pin<sync::Arc<TestNVChip>>,
        request: R,
    },
    Done,
}

impl<R: chip::NVChipReadRequest> Unpin for TestNVChipReadFuture<R> {}

impl<R: chip::NVChipReadRequest> future::Future for TestNVChipReadFuture<R> {
    type Output = (R, Result<(), NVError>);

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = mem::replace(self.deref_mut(), Self::Done);
        match this {
            Self::Init { c, request } => {
                *self = Self::PolledOnce { c, request };
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Self::PolledOnce { c, mut request } => {
                let result = c.process_read_request(&mut request);
                task::Poll::Ready((request, result))
            }
            Self::Done => {
                unreachable!("Attempt to poll completed future.")
            }
        }
    }
}

pub enum TestNVChipWriteFuture<R: chip::NVChipWriteRequest> {
    Init {
        c: pin::Pin<sync::Arc<TestNVChip>>,
        request: R,
    },
    PolledOnce {
        c: pin::Pin<sync::Arc<TestNVChip>>,
        request: R,
    },
    Done,
}

impl<R: chip::NVChipWriteRequest> Unpin for TestNVChipWriteFuture<R> {}

impl<R: chip::NVChipWriteRequest> future::Future for TestNVChipWriteFuture<R> {
    type Output = (R, Result<(), NVError>);

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = mem::replace(self.deref_mut(), Self::Done);
        match this {
            Self::Init { c, request } => {
                *self = Self::PolledOnce { c, request };
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Self::PolledOnce { c, request } => {
                let result = c.process_write_request(&request);
                task::Poll::Ready((request, result))
            }
            Self::Done => {
                unreachable!("Attempt to poll completed future.")
            }
        }
    }
}

pub enum TestNVChipWriteSyncFuture {
    Init,
    PolledOnce,
    Done,
}

impl Unpin for TestNVChipWriteSyncFuture {}

impl future::Future for TestNVChipWriteSyncFuture {
    type Output = Result<(), NVError>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        match self.deref() {
            Self::Init => {
                *self = Self::PolledOnce;
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Self::PolledOnce => {
                *self = Self::Done;
                task::Poll::Ready(Ok(()))
            }
            Self::Done => {
                unreachable!("Attempt to poll completed future.")
            }
        }
    }
}

pub enum TestNVChipTrimFuture {
    Init {
        c: pin::Pin<sync::Arc<TestNVChip>>,
        chip_io_block_index: u64,
        chip_io_blocks_count: usize,
    },
    PolledOnce {
        c: pin::Pin<sync::Arc<TestNVChip>>,
        chip_io_block_index: u64,
        chip_io_blocks_count: usize,
    },
    Done,
}

impl Unpin for TestNVChipTrimFuture {}

impl future::Future for TestNVChipTrimFuture {
    type Output = Result<(), NVError>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        match self.deref_mut() {
            Self::Init {
                c,
                chip_io_block_index,
                chip_io_blocks_count,
            } => {
                *self = Self::PolledOnce {
                    c: c.clone(),
                    chip_io_block_index: *chip_io_block_index,
                    chip_io_blocks_count: *chip_io_blocks_count,
                };
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Self::PolledOnce {
                c,
                chip_io_block_index,
                chip_io_blocks_count,
            } => {
                let chip_io_block_index = usize::try_from(*chip_io_block_index).unwrap();
                let end_block_index = chip_io_block_index
                    .checked_add(*chip_io_blocks_count)
                    .unwrap();
                let mut chip_io_blocks = c.chip_io_blocks.lock();
                if chip_io_blocks.len() < end_block_index {
                    return task::Poll::Ready(Err(NVError::IOBlockOutOfRange));
                }
                for block in chip_io_blocks
                    .iter_mut()
                    .skip(chip_io_block_index)
                    .take(*chip_io_blocks_count)
                {
                    *block = None;
                }
                drop(chip_io_blocks);
                *self = Self::Done;
                task::Poll::Ready(Ok(()))
            }
            Self::Done => {
                unreachable!("Attempt to poll completed future.")
            }
        }
    }
}

#[test]
fn test_nv_chip_rw() {
    #[derive(PartialEq, Eq, Debug)]
    struct TestRwRequest {
        region: chunked_io_region::ChunkedIoRegion,
        level0_child_count_log2: u32,
        level1_child_count_log2: u32,
        buffers: vec::Vec<vec::Vec<vec::Vec<vec::Vec<u8>>>>,
    }

    impl TestRwRequest {
        fn new(
            chunk_size_128b_log2: u32,
            level0_child_count_log2: u32,
            level1_child_count_log2: u32,
            level2_child_count: usize,
            physical_begin_chunk: u64,
        ) -> Self {
            let physical_begin_128b = physical_begin_chunk << chunk_size_128b_log2;
            let region_size_128b = level2_child_count
                << (chunk_size_128b_log2 + level0_child_count_log2 + level1_child_count_log2);
            let physical_end_128b = physical_begin_128b + region_size_128b as u64;
            let region = chunked_io_region::ChunkedIoRegion::new(
                physical_begin_128b,
                physical_end_128b,
                chunk_size_128b_log2,
            )
            .unwrap();
            let mut buffers = vec::Vec::new();
            for _l2 in 0..level2_child_count {
                let mut level1_childs = vec::Vec::new();
                for _l1 in 0..(1usize << level1_child_count_log2) {
                    let mut level0_childs = vec::Vec::new();
                    for _l0 in 0..(1usize << level0_child_count_log2) {
                        let chunk = vec![0; 1usize << (chunk_size_128b_log2 + 7)];
                        level0_childs.push(chunk);
                    }
                    level1_childs.push(level0_childs);
                }
                buffers.push(level1_childs);
            }

            Self {
                region,
                level0_child_count_log2,
                level1_child_count_log2,
                buffers,
            }
        }

        fn fill_buffers_with<F: FnMut() -> u32>(&mut self, fill_fn: &mut F) {
            for l2 in 0..self.buffers.len() {
                for l1 in 0..(1usize << self.level1_child_count_log2) {
                    for l0 in 0..(1usize << self.level0_child_count_log2) {
                        let chunk = &mut self.buffers[l2][l1][l0];
                        for v in chunk.chunks_mut(4) {
                            let fill_value = fill_fn();
                            v.copy_from_slice(&fill_value.to_le_bytes());
                        }
                    }
                }
            }
        }
    }

    impl ops::Index<&chunked_io_region::ChunkedIoRegionChunkRange> for TestRwRequest {
        type Output = [u8];
        fn index(&self, index: &chunked_io_region::ChunkedIoRegionChunkRange) -> &Self::Output {
            let chunk = index.chunk();
            let (l2, [l1, l0]) = chunk.decompose_to_hierarchic_indices([
                self.level1_child_count_log2,
                self.level0_child_count_log2,
            ]);
            &self.buffers[l2][l1][l0][index.range_in_chunk().clone()]
        }
    }

    impl ops::IndexMut<&chunked_io_region::ChunkedIoRegionChunkRange> for TestRwRequest {
        fn index_mut(
            &mut self,
            index: &chunked_io_region::ChunkedIoRegionChunkRange,
        ) -> &mut Self::Output {
            let chunk = index.chunk();
            let (l2, [l1, l0]) = chunk.decompose_to_hierarchic_indices([
                self.level1_child_count_log2,
                self.level0_child_count_log2,
            ]);
            &mut self.buffers[l2][l1][l0][index.range_in_chunk().clone()]
        }
    }

    impl chip::NVChipReadRequest for TestRwRequest {
        fn region(&self) -> &chunked_io_region::ChunkedIoRegion {
            &self.region
        }
    }

    impl chip::NVChipWriteRequest for TestRwRequest {
        fn region(&self) -> &chunked_io_region::ChunkedIoRegion {
            &self.region
        }
    }

    fn test_one(
        chip_io_block_size_128b_log2: u32,
        preferred_chip_io_blocks_bulk_log2: u32,
        request_chunk_size_128b_log2: u32,
        request_level0_child_count_log2: u32,
        request_level1_child_count_log2: u32,
        request_level2_child_count: usize,
    ) {
        use crate::utils::asynchronous::test::executor;
        use chip::NVChip as _;

        let request_physical_begin_chunk = 1
            << (chip_io_block_size_128b_log2
                - request_chunk_size_128b_log2.min(chip_io_block_size_128b_log2));
        let request_size_128b = (request_level2_child_count as u64)
            << (request_chunk_size_128b_log2
                + request_level0_child_count_log2
                + request_level1_child_count_log2);
        let physical_end_128b =
            (request_physical_begin_chunk << request_chunk_size_128b_log2) + request_size_128b;
        let chip_io_block_size_128b = 1 << chip_io_block_size_128b_log2;
        let chip_io_blocks_count =
            (physical_end_128b + (chip_io_block_size_128b - 1)) >> chip_io_block_size_128b_log2;
        let chip = pin::Pin::new(TestNVChip::new(
            chip_io_block_size_128b_log2,
            chip_io_blocks_count,
            preferred_chip_io_blocks_bulk_log2,
        ));

        let mut write_request = TestRwRequest::new(
            request_chunk_size_128b_log2,
            request_level0_child_count_log2,
            request_level1_child_count_log2,
            request_level2_child_count,
            request_physical_begin_chunk,
        );
        let mut fill_value: u32 = 0;
        write_request.fill_buffers_with(&mut || {
            fill_value += 1;
            fill_value
        });

        let e = executor::TestAsyncExecutor::new();
        let write_task = e.spawn(chip.write(write_request).unwrap());
        e.run_to_completion();
        let (write_request, result) = write_task.take().unwrap();
        result.unwrap();

        let read_request = TestRwRequest::new(
            request_chunk_size_128b_log2,
            request_level0_child_count_log2,
            request_level1_child_count_log2,
            request_level2_child_count,
            request_physical_begin_chunk,
        );
        let read_task = e.spawn(chip.read(read_request).unwrap());
        e.run_to_completion();
        let (read_request, result) = read_task.take().unwrap();
        result.unwrap();

        assert_eq!(read_request, write_request);
    }

    test_one(0, 0, 0, 0, 0, 1);
    test_one(0, 0, 1, 0, 0, 1);

    test_one(0, 0, 0, 1, 1, 3);
    test_one(0, 0, 1, 1, 1, 3);
    test_one(0, 1, 0, 1, 1, 3);
    test_one(0, 1, 1, 1, 1, 3);
    test_one(0, 1, 2, 1, 1, 3);
    test_one(0, 2, 1, 1, 1, 3);

    test_one(0, 0, 0, 0, 1, 2 * 3);
    test_one(0, 0, 1, 0, 1, 2 * 3);
    test_one(0, 1, 0, 0, 1, 2 * 3);
    test_one(0, 1, 1, 0, 1, 2 * 3);
    test_one(0, 1, 2, 0, 1, 2 * 3);
    test_one(0, 2, 1, 0, 1, 2 * 3);

    test_one(0, 0, 0, 1, 0, 2 * 3);
    test_one(0, 0, 1, 1, 0, 2 * 3);
    test_one(0, 1, 0, 1, 0, 2 * 3);
    test_one(0, 1, 1, 1, 0, 2 * 3);
    test_one(0, 1, 2, 1, 0, 2 * 3);
    test_one(0, 2, 1, 1, 0, 2 * 3);

    test_one(0, 0, 0, 0, 0, 2 * 2 * 3);
    test_one(0, 0, 1, 0, 0, 2 * 2 * 3);
    test_one(0, 1, 0, 0, 0, 2 * 2 * 3);
    test_one(0, 1, 1, 0, 0, 2 * 2 * 3);
    test_one(0, 1, 2, 0, 0, 2 * 2 * 3);
    test_one(0, 2, 1, 0, 0, 2 * 2 * 3);

    test_one(0, 0, 0, 2, 0, 3);
    test_one(0, 0, 1, 2, 0, 3);
    test_one(0, 1, 0, 2, 0, 3);
    test_one(0, 1, 1, 2, 0, 3);
    test_one(0, 1, 2, 2, 0, 3);
    test_one(0, 2, 1, 2, 0, 3);

    test_one(0, 0, 0, 0, 2, 3);
    test_one(0, 0, 1, 0, 2, 3);
    test_one(0, 1, 0, 0, 2, 3);
    test_one(0, 1, 1, 0, 2, 3);
    test_one(0, 1, 2, 0, 2, 3);
    test_one(0, 2, 1, 0, 2, 3);


    test_one(1, 0, 0, 0, 0, 2);
    test_one(1, 0, 0, 1, 1, 3);
    test_one(1, 1, 0, 1, 1, 3);
    test_one(1, 2, 0, 1, 1, 3);
}
