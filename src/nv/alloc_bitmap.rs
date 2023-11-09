extern crate alloc;
use super::extents;
use super::layout;
use super::layout::PhysicalAllocBlockRange;
use crate::interface;
use crate::utils;
use alloc::vec;
use core::{array, cmp};
use utils::bitmanip::BitManip as _;
use utils::bitmanip::UBitManip as _;

type BitmapWord = u64;
const BITMAP_WORD_BITS_LOG2: u32 = BitmapWord::BITS.ilog2();

struct BitmapWordBlocksLsbsMaskTable {
    word_blocks_lsb_masks_table: [BitmapWord; BITMAP_WORD_BITS_LOG2 as usize - 2],
}

impl BitmapWordBlocksLsbsMaskTable {
    const fn new() -> Self {
        Self {
            word_blocks_lsb_masks_table: Self::init_word_blocks_lsb_masks_table(),
        }
    }

    const fn lookup_blocks_lsbs_mask(&self, block_allocation_blocks_log2: u32) -> BitmapWord {
        if block_allocation_blocks_log2 == 0 {
            !0
        } else if block_allocation_blocks_log2 == BITMAP_WORD_BITS_LOG2 - 1 {
            1
        } else {
            self.word_blocks_lsb_masks_table[block_allocation_blocks_log2 as usize - 1]
        }
    }

    const fn init_word_blocks_lsb_masks_table() -> [BitmapWord; BITMAP_WORD_BITS_LOG2 as usize - 2]
    {
        let mut blocks_lsbs_masks_table = [0; BITMAP_WORD_BITS_LOG2 as usize - 2];
        let mut blocks_lsbs_mask = 1 as BitmapWord;
        let mut block_allocation_blocks_log2 = BITMAP_WORD_BITS_LOG2;
        while block_allocation_blocks_log2 > 1 {
            block_allocation_blocks_log2 -= 1;
            let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
            blocks_lsbs_mask = blocks_lsbs_mask | (blocks_lsbs_mask << block_allocation_blocks);
            blocks_lsbs_masks_table[block_allocation_blocks_log2 as usize - 1] = blocks_lsbs_mask;
        }
        blocks_lsbs_masks_table
    }

    const fn compute_blocks_lsbs_mask(block_allocation_blocks_log2: u32) -> BitmapWord {
        if block_allocation_blocks_log2 == BITMAP_WORD_BITS_LOG2 {
            1
        } else {
            let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
            let block_allocation_blocks_mask = ((1 as BitmapWord) << block_allocation_blocks) - 1;
            !(0 as BitmapWord) / block_allocation_blocks_mask
        }
    }
}

pub struct AllocBitmap {
    bitmap: vec::Vec<BitmapWord>,
}

impl AllocBitmap {
    pub fn find_free_block<const AN: usize, const FN: usize>(
        &self,
        block_allocation_blocks_log2: u32,
        pending_allocs: &SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &SparseAllocBitmapUnion<'_, FN>,
    ) -> Option<layout::PhysicalAllocBlockIndex> {
        let block_allocations_blocks = 1u32 << block_allocation_blocks_log2;
        debug_assert!(block_allocations_blocks <= BitmapWord::BITS);
        if block_allocations_blocks == BitmapWord::BITS {
            return self.find_free_fullword_block(pending_allocs, pending_frees);
        }

        let word_blocks_lsbs_mask_table = BitmapWordBlocksLsbsMaskTable::new();
        let word_blocks_lsbs_mask =
            word_blocks_lsbs_mask_table.lookup_blocks_lsbs_mask(block_allocation_blocks_log2);
        let bitmaps_words_iter =
            AllocBitmapWordIterator::new(self, pending_allocs, pending_frees, 0);
        struct FoundCandidate {
            contiguous_index: u64,
            bitmap_word: BitmapWord,
            split_block_allocation_blocks_log2: u32, // Minimize.
        }
        let mut best: Option<FoundCandidate> = None;
        for (contiguous_index, bitmap_word) in bitmaps_words_iter {
            // Don't bother examining any further if all allocation blocks tracked by this
            // word are allocated already anyway.
            if bitmap_word == !0 {
                continue;
            }

            if bitmap_word == 0 {
                if best.is_none() {
                    best = Some(FoundCandidate {
                        contiguous_index,
                        bitmap_word,
                        split_block_allocation_blocks_log2: BITMAP_WORD_BITS_LOG2,
                    });
                }
                continue;
            }

            let free_blocks_lsbs = Self::bitmap_word_free_blocks_lsbs(
                bitmap_word,
                block_allocation_blocks_log2,
                word_blocks_lsbs_mask,
            );
            if free_blocks_lsbs == 0 {
                continue;
            }

            // It is possible to allocate the block from the range tracked by the current
            // word. See if it is the best candidate: determine the minimum
            // power-of-two sized block the allocation would split, if any, and
            // minimize that.
            let split_block_allocation_blocks_log2 =
                Self::bitmap_word_block_alloc_split_block_size_log2(
                    free_blocks_lsbs,
                    best.as_ref().map(
                        |FoundCandidate {
                             split_block_allocation_blocks_log2,
                             ..
                         }| {
                            debug_assert!(
                                *split_block_allocation_blocks_log2 > block_allocation_blocks_log2
                            );
                            *split_block_allocation_blocks_log2
                        },
                    ),
                    block_allocation_blocks_log2,
                    word_blocks_lsbs_mask,
                    &word_blocks_lsbs_mask_table,
                );

            if split_block_allocation_blocks_log2 == block_allocation_blocks_log2 {
                // It's a perfect fit.
                return Some(layout::PhysicalAllocBlockIndex::from(
                    contiguous_index * BitmapWord::BITS as u64
                        + Self::bitmap_word_block_alloc_select_block(
                            free_blocks_lsbs,
                            block_allocation_blocks_log2,
                            word_blocks_lsbs_mask,
                            &word_blocks_lsbs_mask_table,
                        ) as u64,
                ));
            } else if best.as_ref().map(|FoundCandidate {
                        split_block_allocation_blocks_log2: best_split_block_allocations_block_log2,
                        ..
                }| *best_split_block_allocations_block_log2 > split_block_allocation_blocks_log2).unwrap_or(true)  {
                    best = Some(FoundCandidate {
                        contiguous_index,
                        bitmap_word,
                        split_block_allocation_blocks_log2,
                    });
            }
        }

        if let Some(FoundCandidate {
            contiguous_index,
            bitmap_word,
            split_block_allocation_blocks_log2,
        }) = best
        {
            let word_split_blocks_lsbs_mask = word_blocks_lsbs_mask_table
                .lookup_blocks_lsbs_mask(split_block_allocation_blocks_log2);
            let mut free_split_blocks_lsbs = Self::bitmap_word_free_blocks_lsbs(
                bitmap_word,
                split_block_allocation_blocks_log2,
                word_split_blocks_lsbs_mask,
            );
            if split_block_allocation_blocks_log2 < BITMAP_WORD_BITS_LOG2 - 1 {
                let double_split_block_allocations_block_log2 =
                    split_block_allocation_blocks_log2 + 1;
                let word_double_split_blocks_lsbs_mask = word_blocks_lsbs_mask_table
                    .lookup_blocks_lsbs_mask(double_split_block_allocations_block_log2);
                free_split_blocks_lsbs = Self::bitmap_word_filter_blocks_with_free_buddy_lsbs(
                    free_split_blocks_lsbs,
                    free_split_blocks_lsbs,
                    split_block_allocation_blocks_log2,
                    word_double_split_blocks_lsbs_mask,
                );
            }
            debug_assert_ne!(free_split_blocks_lsbs, 0);
            Some(layout::PhysicalAllocBlockIndex::from(
                contiguous_index * BitmapWord::BITS as u64
                    + Self::bitmap_word_block_alloc_select_block(
                        free_split_blocks_lsbs,
                        split_block_allocation_blocks_log2,
                        word_split_blocks_lsbs_mask,
                        &word_blocks_lsbs_mask_table,
                    ) as u64,
            ))
        } else {
            None
        }
    }

    pub fn find_free_extents<const AN: usize, const FN: usize>(
        &self,
        request_allocation_blocks: layout::AllocBlockCount,
        pending_allocs: &SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &SparseAllocBitmapUnion<'_, FN>,
    ) -> Result<Option<extents::PhysicalExtents>, interface::TpmErr> {
        let mut extents = extents::PhysicalExtents::new();
        let request_allocation_blocks = u64::from(request_allocation_blocks);
        if request_allocation_blocks == 0 {
            return Ok(Some(extents));
        }

        // First handle small allocation requests for anything covered by a single
        // bitmap word separately.
        if request_allocation_blocks <= BitmapWord::BITS as u64 {
            return match self.find_free_subword_chunk(
                request_allocation_blocks as u32,
                pending_allocs,
                pending_frees,
            ) {
                Some(free_subword_chunk_begin) => {
                    extents.extend(&PhysicalAllocBlockRange::from((
                        free_subword_chunk_begin,
                        layout::AllocBlockCount::from(request_allocation_blocks),
                    )))?;
                    Ok(Some(extents))
                }
                None => Ok(None),
            };
        }

        // The allocation request spans more than the range covered by a single bitmap
        // word. For a smallish request < 2 * BitmapWord::BITS in allocation block
        // count, try to still obtain a single contigous allocation, as this
        // will allow for direct references, rather than indirect ones involving
        // extents lists.
        if request_allocation_blocks < 2 * BitmapWord::BITS as u64 {
            if let Some(free_sub_doubleword_chunk_begin) = self.find_free_sub_doubleword_chunk(
                request_allocation_blocks as u32,
                pending_allocs,
                pending_frees,
            ) {
                extents.extend(&PhysicalAllocBlockRange::from((
                    free_sub_doubleword_chunk_begin,
                    layout::AllocBlockCount::from(request_allocation_blocks),
                )))?;
                return Ok(Some(extents));
            }
        }

        // Proceed with the general allocation procedure for any request for more than
        // what is covered by a single bitmap word in size.
        let request_subword_rem_allocation_blocks =
            request_allocation_blocks % BitmapWord::BITS as u64;
        let request_fullword_blocks = request_allocation_blocks / BitmapWord::BITS as u64;

        let free_subword_rem_chunk_begin = if request_subword_rem_allocation_blocks != 0 {
            match self.find_free_subword_chunk(
                request_subword_rem_allocation_blocks as u32,
                pending_allocs,
                pending_frees,
            ) {
                Some(free_subword_chunk_begin) => Some(free_subword_chunk_begin),
                None => return Ok(None),
            }
        } else {
            None
        };

        let mut extents = match self.find_free_fullword_blocks(
            request_fullword_blocks,
            pending_allocs,
            pending_frees,
            free_subword_rem_chunk_begin,
        )? {
            Some(free_fullword_blocks_extents) => free_fullword_blocks_extents,
            None => return Ok(None),
        };

        if let Some(free_subword_rem_chunk_begin) = free_subword_rem_chunk_begin {
            extents.extend(&layout::PhysicalAllocBlockRange::from((
                free_subword_rem_chunk_begin,
                layout::AllocBlockCount::from(request_subword_rem_allocation_blocks),
            )))?;
        }

        Ok(Some(extents))
    }

    fn find_free_fullword_block<const AN: usize, const FN: usize>(
        &self,
        pending_allocs: &SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &SparseAllocBitmapUnion<'_, FN>,
    ) -> Option<layout::PhysicalAllocBlockIndex> {
        let bitmaps_words_iter =
            AllocBitmapWordIterator::new(self, pending_allocs, pending_frees, 0);
        for (contiguous_index, bitmap_word) in bitmaps_words_iter {
            if bitmap_word == 0 {
                return Some(layout::PhysicalAllocBlockIndex::from(
                    contiguous_index * (BitmapWord::BITS as u64),
                ));
            }
        }
        None
    }

    fn find_free_subword_chunk<const AN: usize, const FN: usize>(
        &self,
        chunk_allocation_blocks: u32,
        pending_allocs: &SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &SparseAllocBitmapUnion<'_, FN>,
    ) -> Option<layout::PhysicalAllocBlockIndex> {
        debug_assert_ne!(chunk_allocation_blocks, 0);
        let containing_block_allocation_blocks =
            chunk_allocation_blocks.round_up_next_pow2().unwrap();
        let containing_block_allocation_blocks_log2 = containing_block_allocation_blocks.ilog2();

        if containing_block_allocation_blocks == chunk_allocation_blocks {
            return self.find_free_block(
                containing_block_allocation_blocks_log2,
                pending_allocs,
                pending_frees,
            );
        }
        debug_assert!(chunk_allocation_blocks >= 3);

        let word_blocks_lsbs_mask_table = BitmapWordBlocksLsbsMaskTable::new();
        let word_containing_blocks_lsbs_mask = word_blocks_lsbs_mask_table
            .lookup_blocks_lsbs_mask(containing_block_allocation_blocks_log2);

        let bitmaps_words_iter =
            AllocBitmapWordIterator::new(self, pending_allocs, pending_frees, 0);
        enum FoundCandidate {
            FreeContainingBlock {
                contiguous_index: u64,
                bitmap_word: u64,
                split_block_allocation_blocks_log2: u32, // Minimize.
            },
            ChunkInPartialContainingBlock {
                contiguous_index: u64,
                chunk_begin: u32,
                excess_aligned_blocks_set: u32, // Maximize.
            },
        }
        // To be minimized first, start out with the worst case value.
        let mut best_excess_allocation_blocks =
            containing_block_allocation_blocks - chunk_allocation_blocks;
        // The best_excess_allocation_blocks value found so far distributed uniformly
        // across all block fields in a bitmap word.
        let mut containing_blocks_max_excess_len =
            word_containing_blocks_lsbs_mask * best_excess_allocation_blocks as BitmapWord;
        // Similarly, the requested chunk_allocation_blocks distributed uniformly across
        // all block fields in a bitmap word.
        let containing_blocks_min_maxstr_len =
            word_containing_blocks_lsbs_mask * chunk_allocation_blocks as BitmapWord;
        let mut best: Option<FoundCandidate> = None;
        for (contiguous_index, bitmap_word) in bitmaps_words_iter {
            // Don't bother examining any further if all allocation blocks tracked by this
            // word are allocated already anyway.
            if bitmap_word == !0 {
                continue;
            }

            if bitmap_word == 0 {
                if best.is_none() {
                    best = Some(FoundCandidate::FreeContainingBlock {
                        contiguous_index,
                        bitmap_word,
                        // If containing_block_allocation_blocks_log2 == BITMAP_WORD_BITS_LOG2, the
                        // correct value would in fact be zero, but it won't be of any relevance in
                        // this particular case anyway.
                        split_block_allocation_blocks_log2: BITMAP_WORD_BITS_LOG2,
                    });
                }
                continue;
            }

            let (max_containing_block_maxstr_len, containing_blocks_maxstr_lens) =
                Self::bitmap_word_blocks_maxstr_lens(
                    !bitmap_word,
                    containing_block_allocation_blocks_log2,
                    word_containing_blocks_lsbs_mask,
                );
            if max_containing_block_maxstr_len < chunk_allocation_blocks {
                continue;
            }

            // This does wrap for those blocks that don't have a string of consecutive free
            // blocks of sufficient length left. However, the single (unsigned)
            // comparison below would effectively test (the individual block
            // fields) for
            //      containing_blocks_min_maxstr_len
            //   <= containing_blocks_maxstr_lens
            //   <= containing_blocks_min_maxstr_len + containing_blocks_max_excess_len,
            // c.f. Hacker's Delight, 2nd edition, 4-1 ("Checking Bounds of Integers"),
            // which is what is needed.
            let containing_blocks_excess_lens = Self::bitmap_word_blocks_fields_sub(
                containing_blocks_maxstr_lens,
                containing_blocks_min_maxstr_len,
                containing_block_allocation_blocks_log2,
                word_containing_blocks_lsbs_mask,
            );
            let mut containing_blocks_candidates_lsbs = Self::bitmap_word_blocks_fields_geq_lsbs(
                containing_blocks_max_excess_len,
                containing_blocks_excess_lens,
                containing_block_allocation_blocks_log2,
                word_containing_blocks_lsbs_mask,
            );
            if containing_blocks_candidates_lsbs == 0 {
                continue;
            }

            if max_containing_block_maxstr_len == containing_block_allocation_blocks {
                let free_containing_blocks_lsbs = Self::bitmap_word_free_blocks_lsbs(
                    bitmap_word,
                    containing_block_allocation_blocks_log2,
                    word_containing_blocks_lsbs_mask,
                );
                // The fully free blocks are a subset of all candidates.
                debug_assert_eq!(
                    containing_blocks_candidates_lsbs & free_containing_blocks_lsbs,
                    free_containing_blocks_lsbs
                );
                if free_containing_blocks_lsbs == containing_blocks_candidates_lsbs {
                    // All candidates are fully free blocks.
                    // The case that the full range covered by the bitmap_word is free has been
                    // handled separately above already.
                    debug_assert!(containing_block_allocation_blocks_log2 < BITMAP_WORD_BITS_LOG2);
                    let best_split_block_allocations_block_log2 = match best {
                        Some(FoundCandidate::FreeContainingBlock {
                            split_block_allocation_blocks_log2,
                            ..
                        }) => Some(split_block_allocation_blocks_log2),
                        Some(FoundCandidate::ChunkInPartialContainingBlock { .. }) => {
                            // At this point, the best (minimum) excess value found so far is known
                            // to not be smaller than that of a fully
                            // free containing block.
                            unreachable!();
                        }
                        None => None,
                    };

                    let split_block_allocation_blocks_log2 =
                        Self::bitmap_word_block_alloc_split_block_size_log2(
                            free_containing_blocks_lsbs,
                            best_split_block_allocations_block_log2,
                            containing_block_allocation_blocks_log2,
                            word_containing_blocks_lsbs_mask,
                            &word_blocks_lsbs_mask_table,
                        );
                    if best_split_block_allocations_block_log2
                        .map(|best_split_block_allocations_block_log2| {
                            split_block_allocation_blocks_log2
                                < best_split_block_allocations_block_log2
                        })
                        .unwrap_or(true)
                    {
                        best = Some(FoundCandidate::FreeContainingBlock {
                            contiguous_index,
                            bitmap_word,
                            split_block_allocation_blocks_log2,
                        });
                        // No need to update the best_excess_allocation_blocks, it is still at
                        // its worst case value.
                        debug_assert_eq!(
                            best_excess_allocation_blocks,
                            containing_block_allocation_blocks - chunk_allocation_blocks
                        );
                    }
                    continue;
                } else {
                    // There is at least one partially allocated containing block and it will be
                    // better than the fully free ones. Mask off the latter as
                    // they won't win the race anyway.
                    containing_blocks_candidates_lsbs ^= free_containing_blocks_lsbs;
                    debug_assert_ne!(containing_blocks_candidates_lsbs, 0);
                }
            }

            // At this point, all containing candidate blocks are known to
            // already have some other allocations in them.
            let word_block_field_mask =
                BitmapWord::trailing_bits_mask(containing_block_allocation_blocks);

            // The containing_block_allocation_blocks has been chosen such that it's less
            // than twice the chunk_allocation_blocks. It follows that there is
            // at most one maxstr of consecutive unallocated allocation blocks
            // whose length exceeds chunk_allocation_blocks in each containing
            // block. Thus, when searching for the ends of such a maxstr (known to exist),
            // it suffices to find the tail of a 1-str of length at least
            // containing_block_allocation_blocks / 2. Note that as we do know
            // the length of each block's maxstr already, the respective maxstrs'
            // start can be computed from the end right away.
            let mut containing_blocks_maxstr_end_bits = !bitmap_word;
            let mut s = 1;
            while s < containing_block_allocation_blocks / 2 {
                // Retain those bits which are at the end (from least to most significant order)
                // of a string of consecutive ones at least 2 * s in length.
                containing_blocks_maxstr_end_bits =
                    containing_blocks_maxstr_end_bits & (containing_blocks_maxstr_end_bits << s);
                s *= 2;
            }
            let mut containing_block_begin = 0;
            while containing_blocks_candidates_lsbs != 0 {
                containing_block_begin += containing_blocks_candidates_lsbs.trailing_zeros();
                containing_blocks_candidates_lsbs >>= containing_block_allocation_blocks;

                let containing_block_candidate_maxstr_len = (containing_blocks_maxstr_lens
                    >> containing_block_begin)
                    & word_block_field_mask;
                debug_assert!(
                    containing_block_candidate_maxstr_len
                        < containing_block_allocation_blocks as BitmapWord
                );
                let containing_block_candidate_maxstr_len =
                    containing_block_candidate_maxstr_len as u32;
                debug_assert!(containing_block_candidate_maxstr_len >= chunk_allocation_blocks);
                let excess_allocation_blocks =
                    containing_block_candidate_maxstr_len - chunk_allocation_blocks;
                if excess_allocation_blocks > best_excess_allocation_blocks {
                    // A previous block from this very same word has been a better fit already.
                    continue;
                }
                let containing_block_candidate_maxstr_end_bit = (containing_blocks_maxstr_end_bits
                    >> containing_block_begin)
                    & word_block_field_mask;
                debug_assert_ne!(containing_block_candidate_maxstr_end_bit, 0);
                let containing_block_candidate_maxstr_end =
                    containing_block_candidate_maxstr_end_bit.ilog2() + 1;
                debug_assert!(
                    containing_block_candidate_maxstr_end >= containing_block_candidate_maxstr_len
                );
                let containing_block_candidate_maxstr_begin =
                    containing_block_candidate_maxstr_end - containing_block_candidate_maxstr_len;
                if excess_allocation_blocks == 0 {
                    // It's a perfect fit, no need to look any further.
                    return Some(layout::PhysicalAllocBlockIndex::from(
                        contiguous_index * BitmapWord::BITS as u64
                            + containing_block_begin as u64
                            + containing_block_candidate_maxstr_begin as u64,
                    ));
                }

                // Determine the maximum possible alignment for the leftover excess space, the
                // more it is aligned, with the meaning to be specified in what
                // follows, the better. Logically, the excess space can be
                // viewed as a collection of differently sized blocks, one for
                // each bit set in excess_allocation_blocks, with a size
                // corresponding to that bit position. Example: for excess_allocation_blocks =
                // 0x15, the excess space would consist of three blocks: one of
                // size 1, another one of size 2^2 = 4 and a third one of size
                // 2^4 = 16. Now, depending on where the string of free blocks
                // starts and on the alignment of the chunk_allocation_blocks, it
                // might or might not be possible to place the allocation within the string of
                // free blocks to keep the remaining excess blocks aligned. In
                // general, the larger the maximum excess space block which is
                // aligned, the better the configuration.
                //
                // Now, there are two possibilities to place the new allocation relative to the
                // excess space: either in front or after it. Note that in
                // principle, there is more degree of freedom, as the allocation could
                // be placed somewhere "in the middle" of the excess space, but none of these
                // additional options would improve the best possible overall
                // excess blocks alignment.
                //
                // For each of the possible excess starting points, either at
                // containing_block_candidate_maxstr_begin or at
                // containing_block_candidate_maxstr_begin + chunk_allocation_blocks, determine
                // the point of maximum alignment within the excess range (which
                // happens to be aligned to the maximum excess block) and split
                // the excess space into two parts.  All the blocks now found in
                // the two individual parts can be considered aligned: in the
                // first part the sequence of blocks would be ordered from from smallest to
                // largest, and in the second part after the point of maximum
                // alignment from largest down to smallest.
                let max_excess_block = u32::next_power_of_two(excess_allocation_blocks + 1) >> 1;
                // First option: the allocation is placed after the excess space.
                // This computes the amount of excess space after the point point of maximum
                // alignment within the excess space, c.f. Hacker's Delight, 2nd edition, 3-3
                // ("Detecting a Power-of-2 Boundary Crossing").
                let excess_aligned_blocks_set_after_1 = (containing_block_candidate_maxstr_begin
                    | max_excess_block.wrapping_neg())
                .wrapping_add(excess_allocation_blocks);
                let excess_aligned_blocks_set_after_0 =
                    excess_allocation_blocks - excess_aligned_blocks_set_after_1;
                let excess_aligned_blocks_set_after =
                    excess_aligned_blocks_set_after_0 | excess_aligned_blocks_set_after_1;
                // Second option: the allocation is placed before the excess space.
                let excess_aligned_blocks_set_before_1 = ((containing_block_candidate_maxstr_begin
                    + chunk_allocation_blocks)
                    | max_excess_block.wrapping_neg())
                .wrapping_add(excess_allocation_blocks);
                let excess_aligned_blocks_set_before_0 =
                    excess_allocation_blocks - excess_aligned_blocks_set_before_1;
                let excess_aligned_blocks_set_before =
                    excess_aligned_blocks_set_before_0 | excess_aligned_blocks_set_before_1;
                let (chunk_begin, excess_aligned_blocks_set) =
                    if excess_aligned_blocks_set_after > excess_aligned_blocks_set_before {
                        (
                            containing_block_candidate_maxstr_begin + excess_allocation_blocks,
                            excess_aligned_blocks_set_after,
                        )
                    } else {
                        (
                            containing_block_candidate_maxstr_begin,
                            excess_aligned_blocks_set_before,
                        )
                    };
                let chunk_begin = chunk_begin + containing_block_begin;
                if excess_allocation_blocks < best_excess_allocation_blocks {
                    best = Some(FoundCandidate::ChunkInPartialContainingBlock {
                        contiguous_index,
                        chunk_begin,
                        excess_aligned_blocks_set,
                    });
                    best_excess_allocation_blocks = excess_allocation_blocks;
                    // Update the containing_blocks_max_excess_len block fields accordingly:
                    // uniformly set all fields to the new effective upper bound for the subsequent
                    // search.
                    containing_blocks_max_excess_len = word_containing_blocks_lsbs_mask
                        * best_excess_allocation_blocks as BitmapWord;
                } else {
                    debug_assert_eq!(best_excess_allocation_blocks, excess_allocation_blocks);
                    let best_excess_aligned_blocks_set = match best.as_ref().unwrap() {
                        FoundCandidate::ChunkInPartialContainingBlock {
                            excess_aligned_blocks_set,
                            ..
                        } => *excess_aligned_blocks_set,
                        FoundCandidate::FreeContainingBlock { .. } => unreachable!(),
                    };
                    if excess_aligned_blocks_set > best_excess_aligned_blocks_set {
                        best = Some(FoundCandidate::ChunkInPartialContainingBlock {
                            contiguous_index,
                            chunk_begin,
                            excess_aligned_blocks_set,
                        });
                    }
                }
            }
        }

        match best {
            Some(FoundCandidate::ChunkInPartialContainingBlock {
                contiguous_index,
                chunk_begin,
                excess_aligned_blocks_set: _,
            }) => Some(layout::PhysicalAllocBlockIndex::from(
                contiguous_index * BitmapWord::BITS as u64 + chunk_begin as u64,
            )),
            Some(FoundCandidate::FreeContainingBlock {
                contiguous_index,
                bitmap_word,
                split_block_allocation_blocks_log2,
            }) => {
                let word_split_blocks_lsbs_mask = word_blocks_lsbs_mask_table
                    .lookup_blocks_lsbs_mask(split_block_allocation_blocks_log2);
                let mut free_split_blocks_lsbs = Self::bitmap_word_free_blocks_lsbs(
                    bitmap_word,
                    split_block_allocation_blocks_log2,
                    word_split_blocks_lsbs_mask,
                );
                if split_block_allocation_blocks_log2 < BITMAP_WORD_BITS_LOG2 - 1 {
                    let double_split_block_allocations_block_log2 =
                        split_block_allocation_blocks_log2 + 1;
                    let word_double_split_blocks_lsbs_mask = word_blocks_lsbs_mask_table
                        .lookup_blocks_lsbs_mask(double_split_block_allocations_block_log2);
                    free_split_blocks_lsbs = Self::bitmap_word_filter_blocks_with_free_buddy_lsbs(
                        free_split_blocks_lsbs,
                        free_split_blocks_lsbs,
                        split_block_allocation_blocks_log2,
                        word_double_split_blocks_lsbs_mask,
                    );
                }
                debug_assert_ne!(free_split_blocks_lsbs, 0);
                Some(layout::PhysicalAllocBlockIndex::from(
                    contiguous_index * BitmapWord::BITS as u64
                        + Self::bitmap_word_block_alloc_select_block(
                            free_split_blocks_lsbs,
                            split_block_allocation_blocks_log2,
                            word_split_blocks_lsbs_mask,
                            &word_blocks_lsbs_mask_table,
                        ) as u64,
                ))
            }
            None => None,
        }
    }

    fn find_free_sub_doubleword_chunk<const AN: usize, const FN: usize>(
        &self,
        chunk_allocation_blocks: u32,
        pending_allocs: &SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &SparseAllocBitmapUnion<'_, FN>,
    ) -> Option<layout::PhysicalAllocBlockIndex> {
        debug_assert!(chunk_allocation_blocks > BitmapWord::BITS);
        debug_assert!(chunk_allocation_blocks < 2 * BitmapWord::BITS);

        let subword_rem_allocation_blocks = chunk_allocation_blocks - BitmapWord::BITS;
        let subword_rem_free_head_word_mask =
            BitmapWord::trailing_bits_mask(subword_rem_allocation_blocks);
        let subword_rem_free_tail_word_mask =
            subword_rem_free_head_word_mask << (BitmapWord::BITS - subword_rem_allocation_blocks);

        let mut previous_bitmap_word: Option<BitmapWord> = None;
        let bitmaps_words_iter =
            AllocBitmapWordIterator::new(self, pending_allocs, pending_frees, 0);
        struct FoundCandidate {
            contiguous_index: u64,
            first_bitmap_word: u64,
            excess_allocation_blocks: u32, // Minimize.
        }
        let mut best: Option<FoundCandidate> = None;
        for (contiguous_index, bitmap_word) in bitmaps_words_iter {
            // Don't bother examining any further if all allocation blocks tracked by this
            // word are allocated already anyway.
            if bitmap_word == !0 {
                previous_bitmap_word = None;
                continue;
            }

            if bitmap_word == 0 {
                match previous_bitmap_word {
                    Some(0) => {
                        if best.is_none() {
                            best = Some(FoundCandidate {
                                contiguous_index: contiguous_index - 1,
                                first_bitmap_word: 0,
                                excess_allocation_blocks: BitmapWord::BITS
                                    - subword_rem_allocation_blocks,
                            });
                        }
                    }
                    Some(previous_bitmap_word) => {
                        debug_assert_eq!(previous_bitmap_word & subword_rem_free_tail_word_mask, 0);
                        let excess_allocation_blocks =
                            previous_bitmap_word.leading_zeros() - subword_rem_allocation_blocks;
                        if best
                            .as_ref()
                            .map(|best| best.excess_allocation_blocks > excess_allocation_blocks)
                            .unwrap_or(true)
                        {
                            best = Some(FoundCandidate {
                                contiguous_index: contiguous_index - 1,
                                first_bitmap_word: previous_bitmap_word,
                                excess_allocation_blocks,
                            });
                            if excess_allocation_blocks == 0 {
                                // It's a perfect fit, no need to look any further.
                                break;
                            }
                        }
                    }
                    None => (),
                }
                previous_bitmap_word = Some(0);
                continue;
            } else if bitmap_word & subword_rem_free_head_word_mask == 0 {
                match previous_bitmap_word {
                    Some(0) => {
                        let excess_allocation_blocks =
                            bitmap_word.trailing_zeros() - subword_rem_allocation_blocks;
                        if best
                            .as_ref()
                            .map(|best| best.excess_allocation_blocks > excess_allocation_blocks)
                            .unwrap_or(true)
                        {
                            best = Some(FoundCandidate {
                                contiguous_index: contiguous_index - 1,
                                first_bitmap_word: 0,
                                excess_allocation_blocks,
                            });
                            if excess_allocation_blocks == 0 {
                                // It's a perfect fit, no need to look any further.
                                break;
                            }
                        }
                    }
                    Some(_) | None => (),
                }
            }

            if bitmap_word & subword_rem_free_tail_word_mask == 0 {
                previous_bitmap_word = Some(bitmap_word);
            } else {
                previous_bitmap_word = None;
            }
        }

        match best {
            Some(FoundCandidate {
                contiguous_index,
                first_bitmap_word,
                ..
            }) => {
                let chunk_begin_in_fullword_block = if first_bitmap_word == 0 {
                    0
                } else {
                    BitmapWord::BITS - subword_rem_allocation_blocks
                };

                Some(layout::PhysicalAllocBlockIndex::from(
                    contiguous_index * BitmapWord::BITS as u64
                        + chunk_begin_in_fullword_block as u64,
                ))
            }
            None => None,
        }
    }

    fn find_free_fullword_blocks<const AN: usize, const FN: usize>(
        &self,
        request_fullword_blocks: u64,
        pending_allocs: &SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &SparseAllocBitmapUnion<'_, FN>,
        pending_subword_chunk_allocation: Option<layout::PhysicalAllocBlockIndex>,
    ) -> Result<Option<extents::PhysicalExtents>, interface::TpmErr> {
        let mut extents = extents::PhysicalExtents::new();
        if request_fullword_blocks == 0 {
            return Ok(Some(extents));
        }

        // In the first scan, optimistically try to limit the number of extents by
        // (adaptively) rejecting too short runs of contiguous free fullword
        // blocks. Many schemes are possible, for example one could fix the
        // upper limit on the number of extents and require that each
        // run is at least the total allocation request size divided by that number in
        // length. However, that would put unreasonably strict constraints on possible
        // chunk length distributions: if the scan happened to find one
        // significantly longer run by chance, then one or more smaller ones
        // could still be accepted while staying within the bounds of the
        // total extent number limit. On the other if the rejection scheme was to accept
        // anything for all but the last extent, no matter how short, then
        // chances are that no suitable free run of sufficient length covering
        // the remaining allocation request size can be found in
        // the last iteration.
        //
        // Thus, a more adaptive approach is chosen here. First of all, the total number
        // of extents is limited to the log2 (rounded up) of the allocation
        // request size. Over the course of the allocation, a budget of
        // remaining extents is maintained.  At any point in time, the
        // minimum acceptable free fullword block run length is determined such that the
        // overall remaining allocation request goal would still be achievable
        // with a worst case configuration of exponentially growing chunks. To
        // be more specific, those exponentially growing chunk length in the
        // assumed worst case scenario would correspond (roughly) to the
        // set bits in the remaining allocation request size each. In particular the
        // maximum imposed lower bound would be less or equal to roughly half
        // the remaining allocation request size.
        let mut budget = request_fullword_blocks.ilog2() + 1;
        let mut min_accepted_free_run_fullword_blocks = 1u64;

        fn update_min_accepted_free_run_fullword_blocks(
            budget: u32,
            remaining_fullword_blocks: u64,
        ) -> u64 {
            if remaining_fullword_blocks == 0 {
                return 1;
            }
            debug_assert_ne!(budget, 0);

            // First step: allocate the remaining "budget tickets" to the individual
            // positions in remaining_fullword_blocks.
            // - First allocate to all set bits in remaining_fullword_blocks, from most to
            //   least significant bits.
            // - Then fill up the unset unset bits in remaining_fullword_blocks, from most
            //   to least significant, until the budget is exhausted.
            // Note that the only thing that matters is the least signifcant bit position
            // with a "budget ticket" allocated to it, c.f. the second step below. So handle
            // three different cases, of increasing computational cost:
            // 1. The distance between the most and the least significant bits in
            //    remaining_fullword_blocks is less than the budget: in this case all set
            //    bits as well as the unset ones interspersed inbetween will receive a
            //    "budget ticket". The least significant bit receiving a "budget ticket"
            //    allocation will be located at or to the right of the least significant bit
            //    in remaining_fullword_blocks and can be computed directly.
            // 2. The number of set bits in remaining_fullword_blocks is less or equal to
            //    the budget: in this case, all set bits will have a "budget ticket"
            //    allocated to them, but not all their separating unset bits. The least
            //    significant bit receiving a "budget ticket" allocation will be indentical
            //    to the least significant set bit in remaining_fullword_blocks.
            // 3. In the remaining case, there are fewer budget tickets than set bits in
            //    remaining_fullword_blocks. Allocate them from most to least significant
            //    bits.
            let remaining_fullword_blocks_lsb =
                remaining_fullword_blocks & remaining_fullword_blocks.wrapping_neg();
            let remaining_fullword_blocks_lsb_log2 = remaining_fullword_blocks_lsb.ilog2();
            let budget_allocation_mask = if remaining_fullword_blocks_lsb_log2 + budget > u64::BITS
                || remaining_fullword_blocks_lsb << budget > remaining_fullword_blocks
            {
                // Case 1.)
                1u64 << (remaining_fullword_blocks.ilog2() - (budget - 1))
            } else if budget >= remaining_fullword_blocks.count_ones() {
                // Case 2.)
                remaining_fullword_blocks_lsb
            } else {
                // Case 3.)
                // Create a left aligned contiguous chunk of budget set bits and
                // scatter that over the set bits in remaining_fullword_blocks, starting
                // from the left.
                let budget_pool = !(u64::trailing_bits_mask(u64::BITS - budget));
                budget_pool
                    .expand_from_left(remaining_fullword_blocks | (remaining_fullword_blocks - 1))
            };

            // Second step: determine the minimum acceptable fullword block run length from
            // the least significant bit that received a "budget ticket"
            // allocation to it. Require that the minimum fullword block run
            // will have sufficient length to accomodate for at least the modulo
            // of the remaining allocation request length by twice that least significant
            // bit. That is, if a fullword block run length of exactly that minimum length
            // would have been accepted, all the bits at and to the right of
            // this least significant bit position in
            // remaining_fullword_blocks would become clear thereafter.
            // Set all bits at and to the right of the least significant bit, clear anything
            // above:
            let budget_allocation_tail_mask = budget_allocation_mask ^ (budget_allocation_mask - 1);
            let min_accepted_free_run_fullword_blocks =
                remaining_fullword_blocks & budget_allocation_tail_mask;
            // As an additional constraint to avoid an excessive number of small extents for
            // certain values of remaining_fullword_blocks with a longer tail of
            // zeroes, require that the minumum is at least equal to the least
            // significant bit with a "budget ticket" allocated to it. Isolate
            // the LSB:
            let budget_allocation_mask_lsb =
                budget_allocation_mask & budget_allocation_mask.wrapping_neg();
            min_accepted_free_run_fullword_blocks
                .max(budget_allocation_mask_lsb)
                .min(remaining_fullword_blocks)
        }

        // This request for an integral multiple of fullword blocks might have been
        // issued on behalf of another request for a size with unaligned
        // remainder, whose containing fullword block needs to get dismissed in
        // the search.
        let pending_subword_chunk_allocation_contiguous_index =
            pending_subword_chunk_allocation.map(|p| u64::from(p) >> BITMAP_WORD_BITS_LOG2);
        let mut found_fullword_blocks = 0u64;
        let mut total_free_fullword_blocks = 0u64;
        // Cached shortest extent found (and used) so far: pair of index and length in
        // units of fullword blocks.
        let mut shortest_extent: Option<(usize, u64)> = None;
        let mut bitmaps_words_iter =
            AllocBitmapWordIterator::new(self, pending_allocs, pending_frees, 0);
        while let Some((cur_free_run_begin_contiguous_index, _)) =
            bitmaps_words_iter.find(|(_, bitmap_word)| *bitmap_word == 0)
        {
            if pending_subword_chunk_allocation_contiguous_index
                .map(|p| p == cur_free_run_begin_contiguous_index)
                .unwrap_or(false)
            {
                continue;
            }

            let cur_free_run_end_contiguous_index = (&mut bitmaps_words_iter)
                .map_while(|(contiguous_index, bitmap_word)| {
                    if bitmap_word == 0
                        && pending_subword_chunk_allocation_contiguous_index
                            .map(|p| p != contiguous_index)
                            .unwrap_or(true)
                    {
                        Some(contiguous_index)
                    } else {
                        None
                    }
                })
                .take(request_fullword_blocks as usize - 1)
                .last()
                .unwrap_or(cur_free_run_begin_contiguous_index)
                + 1;

            let cur_free_run_fullword_blocks =
                cur_free_run_end_contiguous_index - cur_free_run_begin_contiguous_index;
            total_free_fullword_blocks += cur_free_run_fullword_blocks;
            // If the current free run is acceptable in terms of the current lower bound on
            // its length, consume all that is needed for the remaining
            // allocation request size.
            let mut remaining_fullword_blocks = request_fullword_blocks - found_fullword_blocks;
            let mut cur_free_run_use_fullword_blocks = if remaining_fullword_blocks != 0
                && min_accepted_free_run_fullword_blocks <= cur_free_run_fullword_blocks
            {
                let cur_free_run_use_fullword_blocks =
                    remaining_fullword_blocks.min(cur_free_run_fullword_blocks);
                found_fullword_blocks += cur_free_run_use_fullword_blocks;
                remaining_fullword_blocks -= cur_free_run_use_fullword_blocks;
                cur_free_run_use_fullword_blocks
            } else {
                0
            };

            // Use the remaining space in the current run, if any, to perhaps
            // replace one or more shorter extents already found before.
            while cur_free_run_use_fullword_blocks < cur_free_run_fullword_blocks {
                shortest_extent = shortest_extent.or_else(|| {
                    extents
                        .iter()
                        .enumerate()
                        .map(|(i, e)| (i, u64::from(e.block_count()) >> BITMAP_WORD_BITS_LOG2))
                        .min_by_key(|(_, c)| *c)
                });
                let (shortest_extent_index, shortest_extent_fullword_blocks) = match shortest_extent
                {
                    Some(shortest_extent) => shortest_extent,
                    None => break,
                };

                // If the current run's total length is <= the shortest previously found one,
                // it would be counter-productive to shovel blocks from the latter over to the
                // former.
                // Also, it doesn't make any sense to replace a single small extent by a larger
                // one, truncating the latter in the course -- that would only
                // increase fragmentation.
                if shortest_extent_fullword_blocks >= cur_free_run_fullword_blocks
                    || (cur_free_run_use_fullword_blocks == 0
                        && extents
                            .iter()
                            .map(|e| u64::from(e.block_count()) >> BITMAP_WORD_BITS_LOG2)
                            .filter(|c| *c < cur_free_run_fullword_blocks)
                            .count()
                            < 2)
                {
                    break;
                }

                let transfer_fullword_blocks = shortest_extent_fullword_blocks
                    .min(cur_free_run_fullword_blocks - cur_free_run_use_fullword_blocks);
                cur_free_run_use_fullword_blocks += transfer_fullword_blocks;
                if extents.shrink_extent_by(
                    shortest_extent_index,
                    layout::AllocBlockCount::from(
                        transfer_fullword_blocks << BITMAP_WORD_BITS_LOG2,
                    ),
                ) {
                    // The extent got removed, revive the associated budget allocation.
                    budget += 1;
                    shortest_extent = None;
                } else {
                    shortest_extent = Some((
                        shortest_extent_index,
                        shortest_extent_fullword_blocks - transfer_fullword_blocks,
                    ));
                }
            }

            if cur_free_run_use_fullword_blocks != 0 {
                extents.extend(&layout::PhysicalAllocBlockRange::from((
                    layout::PhysicalAllocBlockIndex::from(
                        cur_free_run_begin_contiguous_index << BITMAP_WORD_BITS_LOG2,
                    ),
                    layout::AllocBlockCount::from(
                        cur_free_run_use_fullword_blocks << BITMAP_WORD_BITS_LOG2,
                    ),
                )))?;

                if cur_free_run_fullword_blocks >= request_fullword_blocks {
                    // A single extent encompassing the whole allocation request has been found, no
                    // need to look any further.
                    debug_assert_eq!(extents.len(), 1);
                    break;
                }

                if shortest_extent
                    .map(|(_, c)| c > cur_free_run_use_fullword_blocks)
                    .unwrap_or_else(|| extents.len() == 1)
                {
                    shortest_extent = Some((extents.len() - 1, cur_free_run_use_fullword_blocks));
                }

                budget -= 1;
                if remaining_fullword_blocks != 0 {
                    min_accepted_free_run_fullword_blocks =
                        update_min_accepted_free_run_fullword_blocks(
                            budget,
                            remaining_fullword_blocks,
                        );
                }
            }
        }

        if found_fullword_blocks == request_fullword_blocks {
            Ok(Some(extents))
        } else if total_free_fullword_blocks >= request_fullword_blocks {
            // The allocation with a number of extents within the budget had not been
            // possible. Fallback to an unrestricted search.
            self.find_free_fullword_blocks_fallback(
                request_fullword_blocks,
                pending_allocs,
                pending_frees,
                pending_subword_chunk_allocation,
            )
        } else {
            Ok(None)
        }
    }

    fn find_free_fullword_blocks_fallback<const AN: usize, const FN: usize>(
        &self,
        request_fullword_blocks: u64,
        pending_allocs: &SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &SparseAllocBitmapUnion<'_, FN>,
        pending_subword_chunk_allocation: Option<layout::PhysicalAllocBlockIndex>,
    ) -> Result<Option<extents::PhysicalExtents>, interface::TpmErr> {
        debug_assert!(request_fullword_blocks != 0);
        // This request for an integral multiple of fullword blocks might have been
        // issued on behalf of another request for a size with unaligned
        // remainder, whose containing fullword block needs to get dismissed in
        // the search.
        let pending_subword_chunk_allocation_contiguous_index =
            pending_subword_chunk_allocation.map(|p| u64::from(p) >> BITMAP_WORD_BITS_LOG2);
        let mut found_fullword_blocks = 0u64;
        let mut extents = extents::PhysicalExtents::new();
        // Cached shortest extent found (and used) so far: pair of index and length in
        // units of fullword blocks.
        let mut shortest_extent: Option<(usize, u64)> = None;
        let mut bitmaps_words_iter =
            AllocBitmapWordIterator::new(self, pending_allocs, pending_frees, 0);
        while let Some((cur_free_run_begin_contiguous_index, _)) =
            bitmaps_words_iter.find(|(_, bitmap_word)| *bitmap_word == 0)
        {
            if pending_subword_chunk_allocation_contiguous_index
                .map(|p| p == cur_free_run_begin_contiguous_index)
                .unwrap_or(false)
            {
                continue;
            }

            let cur_free_run_end_contiguous_index = (&mut bitmaps_words_iter)
                .map_while(|(contiguous_index, bitmap_word)| {
                    if bitmap_word == 0
                        && pending_subword_chunk_allocation_contiguous_index
                            .map(|p| p != contiguous_index)
                            .unwrap_or(true)
                    {
                        Some(contiguous_index)
                    } else {
                        None
                    }
                })
                .take(request_fullword_blocks as usize - 1)
                .last()
                .unwrap_or(cur_free_run_begin_contiguous_index)
                + 1;

            let cur_free_run_fullword_blocks =
                cur_free_run_end_contiguous_index - cur_free_run_begin_contiguous_index;
            // First consume all what is needed to work torwards completing the request...
            let mut cur_free_run_use_fullword_blocks =
                (request_fullword_blocks - found_fullword_blocks).min(cur_free_run_fullword_blocks);
            found_fullword_blocks += cur_free_run_use_fullword_blocks;
            // ... and use the remaining space in the current run, if any, to perhaps
            // replace one or more shorter extents already found before.
            while cur_free_run_use_fullword_blocks < cur_free_run_fullword_blocks {
                shortest_extent = shortest_extent.or_else(|| {
                    extents
                        .iter()
                        .enumerate()
                        .map(|(i, e)| (i, u64::from(e.block_count()) >> BITMAP_WORD_BITS_LOG2))
                        .min_by_key(|(_, c)| *c)
                });
                let (shortest_extent_index, shortest_extent_fullword_blocks) = match shortest_extent
                {
                    Some(shortest_extent) => shortest_extent,
                    None => break,
                };

                // If the current run's total length is <= the shortest previously found one,
                // it would be counter-productive to shovel blocks from the latter over to the
                // former.
                // Also, it doesn't make any sense to replace a single small extent by a larger
                // one, truncating the latter in the course -- that would only
                // increase fragmentation.
                if shortest_extent_fullword_blocks >= cur_free_run_fullword_blocks
                    || (cur_free_run_use_fullword_blocks == 0
                        && extents
                            .iter()
                            .map(|e| u64::from(e.block_count()) >> BITMAP_WORD_BITS_LOG2)
                            .filter(|c| *c < cur_free_run_fullword_blocks)
                            .count()
                            < 2)
                {
                    break;
                }

                let transfer_fullword_blocks = shortest_extent_fullword_blocks
                    .min(cur_free_run_fullword_blocks - cur_free_run_use_fullword_blocks);
                cur_free_run_use_fullword_blocks += transfer_fullword_blocks;
                if extents.shrink_extent_by(
                    shortest_extent_index,
                    layout::AllocBlockCount::from(
                        transfer_fullword_blocks << BITMAP_WORD_BITS_LOG2,
                    ),
                ) {
                    shortest_extent = None;
                } else {
                    shortest_extent = Some((
                        shortest_extent_index,
                        shortest_extent_fullword_blocks - transfer_fullword_blocks,
                    ));
                }
            }

            if cur_free_run_use_fullword_blocks != 0 {
                extents.extend(&layout::PhysicalAllocBlockRange::from((
                    layout::PhysicalAllocBlockIndex::from(
                        cur_free_run_begin_contiguous_index << BITMAP_WORD_BITS_LOG2,
                    ),
                    layout::AllocBlockCount::from(
                        cur_free_run_use_fullword_blocks << BITMAP_WORD_BITS_LOG2,
                    ),
                )))?;

                if cur_free_run_fullword_blocks >= request_fullword_blocks {
                    // A single extent encompassing the whole allocation request has been found, no
                    // need to look any further.
                    debug_assert_eq!(extents.len(), 1);
                    break;
                }

                if shortest_extent
                    .map(|(_, c)| c > cur_free_run_use_fullword_blocks)
                    .unwrap_or_else(|| extents.len() == 1)
                {
                    shortest_extent = Some((extents.len() - 1, cur_free_run_use_fullword_blocks));
                }
            }
        }

        if found_fullword_blocks == request_fullword_blocks {
            Ok(Some(extents))
        } else {
            Ok(None)
        }
    }

    fn bitmap_word_block_alloc_split_block_size_log2(
        bitmap_word_free_blocks_lsbs: BitmapWord,
        max_split_block_allocation_blocks_log2: Option<u32>,
        block_allocation_blocks_log2: u32,
        bitmap_word_blocks_lsbs_mask: BitmapWord,
        bitmap_word_blocks_lsbs_mask_table: &BitmapWordBlocksLsbsMaskTable,
    ) -> u32 {
        debug_assert_eq!(
            bitmap_word_blocks_lsbs_mask,
            bitmap_word_blocks_lsbs_mask_table
                .lookup_blocks_lsbs_mask(block_allocation_blocks_log2)
        );
        debug_assert_eq!(
            bitmap_word_free_blocks_lsbs & !bitmap_word_blocks_lsbs_mask,
            0
        );
        debug_assert_ne!(bitmap_word_free_blocks_lsbs, 0);
        // At this point it is known that not all blocks are free, so the split block
        // size will be half the range covered by the word at most.
        debug_assert_ne!(bitmap_word_free_blocks_lsbs, bitmap_word_blocks_lsbs_mask);
        let max_split_block_allocation_blocks_log2 = max_split_block_allocation_blocks_log2
            .map(|m| m.min(BITMAP_WORD_BITS_LOG2 - 1))
            .unwrap_or(BITMAP_WORD_BITS_LOG2 - 1);
        let mut split_block_allocation_blocks_log2 = block_allocation_blocks_log2;
        let mut free_split_blocks_lsbs = bitmap_word_free_blocks_lsbs;
        while split_block_allocation_blocks_log2 < max_split_block_allocation_blocks_log2 {
            let double_split_block_allocations_block_log2 = split_block_allocation_blocks_log2 + 1;
            let word_double_split_blocks_lsbs_mask = bitmap_word_blocks_lsbs_mask_table
                .lookup_blocks_lsbs_mask(double_split_block_allocations_block_log2);
            if Self::bitmap_word_filter_blocks_with_free_buddy_lsbs(
                free_split_blocks_lsbs,
                free_split_blocks_lsbs,
                split_block_allocation_blocks_log2,
                word_double_split_blocks_lsbs_mask,
            ) != 0
            {
                break;
            }

            let split_block_allocation_blocks = 1u32 << split_block_allocation_blocks_log2;
            free_split_blocks_lsbs = (free_split_blocks_lsbs
                & (free_split_blocks_lsbs >> split_block_allocation_blocks))
                & word_double_split_blocks_lsbs_mask;
            debug_assert_ne!(free_split_blocks_lsbs, 0);
            split_block_allocation_blocks_log2 += 1;
        }
        split_block_allocation_blocks_log2
    }

    fn bitmap_word_block_alloc_select_block(
        mut bitmap_word_free_blocks_lsbs: BitmapWord,
        block_allocation_blocks_log2: u32,
        bitmap_word_blocks_lsbs_mask: BitmapWord,
        bitmap_word_blocks_lsbs_mask_table: &BitmapWordBlocksLsbsMaskTable,
    ) -> u32 {
        debug_assert_eq!(
            bitmap_word_blocks_lsbs_mask,
            bitmap_word_blocks_lsbs_mask_table
                .lookup_blocks_lsbs_mask(block_allocation_blocks_log2)
        );
        debug_assert_eq!(
            bitmap_word_free_blocks_lsbs & !bitmap_word_blocks_lsbs_mask,
            0
        );
        // It is assumed that the input block_allocation_blocks_log2 has been increased
        // to the minimum required split block size already.
        debug_assert_eq!(
            block_allocation_blocks_log2,
            Self::bitmap_word_block_alloc_split_block_size_log2(
                bitmap_word_free_blocks_lsbs,
                None,
                block_allocation_blocks_log2,
                bitmap_word_blocks_lsbs_mask,
                bitmap_word_blocks_lsbs_mask_table
            )
        );
        if block_allocation_blocks_log2 < BITMAP_WORD_BITS_LOG2 - 1 {
            let double_block_allocations_block_log2 = block_allocation_blocks_log2 + 1;
            let word_double_blocks_lsbs_mask = bitmap_word_blocks_lsbs_mask_table
                .lookup_blocks_lsbs_mask(double_block_allocations_block_log2);
            bitmap_word_free_blocks_lsbs = Self::bitmap_word_filter_blocks_with_free_buddy_lsbs(
                bitmap_word_free_blocks_lsbs,
                bitmap_word_free_blocks_lsbs,
                block_allocation_blocks_log2,
                word_double_blocks_lsbs_mask,
            );
        }
        debug_assert_ne!(bitmap_word_free_blocks_lsbs, 0);
        bitmap_word_free_blocks_lsbs.trailing_zeros()
    }

    fn bitmap_word_free_blocks_lsbs(
        bitmap_word: BitmapWord,
        block_allocation_blocks_log2: u32,
        bitmap_word_blocks_lsbs_mask: BitmapWord,
    ) -> BitmapWord {
        Self::bitmap_word_nonzero_blocks_lsbs(
            bitmap_word,
            block_allocation_blocks_log2,
            bitmap_word_blocks_lsbs_mask,
        ) ^ bitmap_word_blocks_lsbs_mask
    }

    fn bitmap_word_filter_blocks_with_free_buddy_lsbs(
        bitmap_word_candidate_blocks_lsbs: BitmapWord,
        bitmap_word_free_blocks_lsbs: BitmapWord,
        block_allocation_blocks_log2: u32,
        bitmap_word_double_blocks_lsbs_masks: BitmapWord,
    ) -> BitmapWord {
        let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
        debug_assert!(block_allocation_blocks < BitmapWord::BITS);
        // Interchange the buddy block pairs in bitmap_word_free_blocks_lsbs.
        let t1 = (bitmap_word_free_blocks_lsbs
            ^ (bitmap_word_free_blocks_lsbs >> block_allocation_blocks))
            & bitmap_word_double_blocks_lsbs_masks;
        let t2 = t1 << block_allocation_blocks;
        let swapped_bitmap_word_free_blocks_lsbs = bitmap_word_free_blocks_lsbs ^ t1 ^ t2;
        // Invert to go from "free buddy" mask to "allocated buddy" mask.
        let mask = !swapped_bitmap_word_free_blocks_lsbs;
        bitmap_word_candidate_blocks_lsbs & mask
    }

    fn bitmap_word_nonzero_blocks_lsbs(
        bitmap_word: BitmapWord,
        block_allocation_blocks_log2: u32,
        bitmap_word_blocks_lsbs_mask: BitmapWord,
    ) -> BitmapWord {
        let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
        (((((bitmap_word & !bitmap_word_blocks_lsbs_mask) >> 1)
            + ((!bitmap_word_blocks_lsbs_mask) >> 1))
            >> (block_allocation_blocks - 1))
            | bitmap_word)
            & bitmap_word_blocks_lsbs_mask
    }

    fn bitmap_word_blocks_select_mask(
        block_allocation_blocks_log2: u32,
        selected_blocks_lsbs: BitmapWord,
    ) -> BitmapWord {
        let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
        let selected_blocks_msbs = selected_blocks_lsbs << (block_allocation_blocks - 1);
        (selected_blocks_msbs - selected_blocks_lsbs) | selected_blocks_msbs
    }

    /// Determine lengths of the longest strings of consecutive ones in each of
    /// a bitmap word's block fields of specified width individually.
    fn bitmap_word_blocks_maxstr_lens(
        mut bitmap_word: BitmapWord,
        block_allocation_blocks_log2: u32,
        bitmap_word_blocks_lsbs_mask: BitmapWord,
    ) -> (u32, BitmapWord) {
        // This is a modified variant of the algorithm from Hacker's Delight, 2nd
        // edition, 6-3 ("Find longest string of 1-Bits") working on individual
        // fields of block_allocation_blocks bit width each.
        if bitmap_word == 0 {
            return (0, 0);
        }

        // First part: determine the maximum power of two less or equal than the length
        // of the longest string of consecutive ones, it will be refined by the
        // backtracking part below.
        let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
        let mut s_log2 = 0u32;
        let mut s_per_block = Self::bitmap_word_nonzero_blocks_lsbs(
            bitmap_word,
            block_allocation_blocks_log2,
            bitmap_word_blocks_lsbs_mask,
        );
        while s_log2 < block_allocation_blocks_log2 {
            // Test for bitstrings of lengths at least 2 * (1 << s_log2).
            // The heading bit(s) of any such string in the original input will remain set.
            let mut y = bitmap_word & (bitmap_word << (1 << s_log2));
            // Applying masks prevents strings in neighbouring blocks from combining.
            let mask =
                (bitmap_word_blocks_lsbs_mask << (1 << s_log2)) - bitmap_word_blocks_lsbs_mask;
            y &= !mask;
            if y == 0 {
                break;
            }

            debug_assert!(y & bitmap_word_blocks_lsbs_mask == 0);
            let nonzero_blocks_lsbs = (((y >> 1) + (!bitmap_word_blocks_lsbs_mask >> 1))
                >> (block_allocation_blocks - 1))
                & bitmap_word_blocks_lsbs_mask;
            // The addition actually doubles the value in each block field where
            // nonzero_blocks_lsbs is (still) set.
            s_per_block += nonzero_blocks_lsbs << s_log2;
            // Update the bitmap_word block fields with the non-zero ones from y.
            let nonzero_blocks_select_mask = Self::bitmap_word_blocks_select_mask(
                block_allocation_blocks_log2,
                nonzero_blocks_lsbs,
            );
            bitmap_word = bitmap_word ^ ((bitmap_word ^ y) & nonzero_blocks_select_mask);
            s_log2 += 1;
        }

        // Second part: backtracking to refine the found s-value.
        let mut s_max = 1u32 << s_log2;
        let mut blocks_with_s_str_lsbs: BitmapWord = 0;
        while s_log2 > 0 {
            // Consider only those blocks which have an initial s-value (as determined in
            // the previous loop) greater than the s_delta below.
            blocks_with_s_str_lsbs |= (s_per_block >> s_log2) & bitmap_word_blocks_lsbs_mask;
            s_log2 -= 1;
            let s_delta = 1u32 << s_log2;
            let y = bitmap_word & (bitmap_word << s_delta);
            if y != 0 {
                debug_assert!(y & blocks_with_s_str_lsbs == 0);
                // Instead of and'ing with bitmap_word_blocks_lsbs_mask, and with
                // blocks_with_s_str_lsbs directly to save an additional and
                // operation.
                let nonzero_blocks_lsbs = (((y >> 1) + (!bitmap_word_blocks_lsbs_mask >> 1))
                    >> (block_allocation_blocks - 1))
                    & blocks_with_s_str_lsbs;
                s_per_block += nonzero_blocks_lsbs << s_log2;
                // Update the bitmap_word block fields with the non-zero ones from y.
                let nonzero_blocks_select_mask = Self::bitmap_word_blocks_select_mask(
                    block_allocation_blocks_log2,
                    nonzero_blocks_lsbs,
                );
                bitmap_word = bitmap_word ^ ((bitmap_word ^ y) & nonzero_blocks_select_mask);
                s_max += s_delta;
            }
        }

        (s_max, s_per_block)
    }

    fn bitmap_word_blocks_fields_geq_lsbs(
        x: BitmapWord,
        y: BitmapWord,
        block_allocation_blocks_log2: u32,
        bitmap_word_blocks_lsbs_mask: BitmapWord,
    ) -> BitmapWord {
        // Adapted from the subtraction algorithm in Hacker's Delight, 2nd edition,
        // 2-18 ("Multibyte Add, Subtract, Absolute Value")
        let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
        let bitmap_word_blocks_msbs_mask =
            bitmap_word_blocks_lsbs_mask << (block_allocation_blocks - 1);

        // The MSBs in each block of d are set iff there's no borrow carried into that
        // position.
        let d = (x | bitmap_word_blocks_msbs_mask) - (y & !bitmap_word_blocks_msbs_mask);
        // Set each block's MSB iff no borrow would be carried out of that position.
        let no_borrow_msbs = (x | (!y & d)) & (!y | d);
        (no_borrow_msbs >> (block_allocation_blocks - 1)) & bitmap_word_blocks_lsbs_mask
    }

    fn bitmap_word_blocks_fields_sub(
        x: BitmapWord,
        y: BitmapWord,
        block_allocation_blocks_log2: u32,
        bitmap_word_blocks_lsbs_mask: BitmapWord,
    ) -> BitmapWord {
        // C.f. Hacker's Delight, 2nd edition, 2-18 ("Multibyte Add, Subtract, Absolute
        // Value")
        let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
        let bitmap_word_blocks_msbs_mask =
            bitmap_word_blocks_lsbs_mask << (block_allocation_blocks - 1);

        let d = (x | bitmap_word_blocks_msbs_mask) - (y & !bitmap_word_blocks_msbs_mask);
        !(((x ^ y) | !bitmap_word_blocks_msbs_mask) ^ d)
    }
}

struct AllocBitmapWordIterator<'a, const AN: usize, const FN: usize> {
    bitmap: &'a AllocBitmap,
    pending_allocs_iter: SparseAllocBitmapUnionWordIterator<'a, AN>,
    next_pending_alloc: Option<(u64, BitmapWord)>,
    pending_frees_iter: SparseAllocBitmapUnionWordIterator<'a, FN>,
    next_pending_free: Option<(u64, BitmapWord)>,
    next_contiguous_index: u64,
}

impl<'a, const AN: usize, const FN: usize> AllocBitmapWordIterator<'a, AN, FN> {
    fn new(
        bitmap: &'a AllocBitmap,
        pending_allocs: &'a SparseAllocBitmapUnion<'a, AN>,
        pending_frees: &'a SparseAllocBitmapUnion<'a, FN>,
        contiguous_index_begin: u64,
    ) -> Self {
        let (mut pending_allocs_iter, mut pending_frees_iter) = if contiguous_index_begin == 0 {
            (
                SparseAllocBitmapUnionWordIterator::new(pending_allocs),
                SparseAllocBitmapUnionWordIterator::new(pending_frees),
            )
        } else {
            (
                SparseAllocBitmapUnionWordIterator::new_at_contiguous_index(
                    pending_allocs,
                    contiguous_index_begin,
                ),
                SparseAllocBitmapUnionWordIterator::new_at_contiguous_index(
                    pending_frees,
                    contiguous_index_begin,
                ),
            )
        };

        let next_pending_alloc = pending_allocs_iter.next();
        let next_pending_free = pending_frees_iter.next();

        Self {
            bitmap,
            pending_allocs_iter,
            next_pending_alloc,
            pending_frees_iter,
            next_pending_free,
            next_contiguous_index: contiguous_index_begin,
        }
    }
}

impl<'a, const AN: usize, const FN: usize> Iterator for AllocBitmapWordIterator<'a, AN, FN> {
    type Item = (u64, BitmapWord);

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_contiguous_index == self.bitmap.bitmap.len() as u64 {
            return None;
        }

        let contiguous_index = self.next_contiguous_index;
        self.next_contiguous_index += 1;
        let mut bitmap_word = self.bitmap.bitmap[contiguous_index as usize];

        if let Some(pending_alloc) = &self.next_pending_alloc {
            if pending_alloc.0 == contiguous_index {
                bitmap_word |= pending_alloc.1;
                self.next_pending_alloc = self.pending_allocs_iter.next();
            }
        }
        if let Some(pending_free) = &self.next_pending_free {
            if pending_free.0 == contiguous_index {
                bitmap_word &= !pending_free.1;
                self.next_pending_free = self.pending_frees_iter.next();
            }
        }

        Some((contiguous_index, bitmap_word))
    }
}

struct SparseAllocBitmapEntry {
    contiguous_index: u64,
    bitmap_word: BitmapWord,
}

pub struct SparseAllocBitmap {
    entries: vec::Vec<SparseAllocBitmapEntry>,
}

impl SparseAllocBitmap {
    fn find_entry_position(&self, contiguous_index: u64) -> Result<usize, usize> {
        self.entries
            .binary_search_by(|e| e.contiguous_index.cmp(&contiguous_index))
    }
}

pub struct SparseAllocBitmapUnion<'a, const N: usize> {
    bitmaps: &'a [&'a SparseAllocBitmap; N],
}

impl<'a, const N: usize> SparseAllocBitmapUnion<'a, N> {
    fn iter(&self) -> SparseAllocBitmapUnionWordIterator<'_, N> {
        SparseAllocBitmapUnionWordIterator::new(self)
    }

    fn iter_at_contiguous_index(
        &self,
        contiguous_index_begin: u64,
    ) -> SparseAllocBitmapUnionWordIterator<'_, N> {
        SparseAllocBitmapUnionWordIterator::new_at_contiguous_index(self, contiguous_index_begin)
    }
}

struct SparseAllocBitmapUnionWordIterator<'a, const N: usize> {
    bitmap_union: &'a SparseAllocBitmapUnion<'a, N>,
    next_sparse_entry_indices: [Option<usize>; N],
}

impl<'a, const N: usize> SparseAllocBitmapUnionWordIterator<'a, N> {
    fn new(bitmap_union: &'a SparseAllocBitmapUnion<'a, N>) -> Self {
        let next_sparse_entry_indices = array::from_fn(|i| {
            if !bitmap_union.bitmaps[i].entries.is_empty() {
                Some(i)
            } else {
                None
            }
        });
        Self {
            bitmap_union,
            next_sparse_entry_indices,
        }
    }

    fn new_at_contiguous_index(
        bitmap_union: &'a SparseAllocBitmapUnion<'a, N>,
        contiguous_index_begin: u64,
    ) -> Self {
        let next_sparse_entry_indices = array::from_fn(|i| {
            match bitmap_union.bitmaps[i].find_entry_position(contiguous_index_begin) {
                Ok(i) => Some(i),
                Err(i) => {
                    if i != bitmap_union.bitmaps[i].entries.len() {
                        Some(i)
                    } else {
                        None
                    }
                }
            }
        });
        Self {
            bitmap_union,
            next_sparse_entry_indices,
        }
    }
}

impl<'a, const N: usize> Iterator for SparseAllocBitmapUnionWordIterator<'a, N> {
    type Item = (u64, BitmapWord);

    fn next(&mut self) -> Option<Self::Item> {
        // The compiler might be able to deduce that on its own, but help it out a bit
        // in case not.
        if N == 0 {
            return None;
        }
        let (mut i, next_sparse_index) = self
            .next_sparse_entry_indices
            .iter()
            .enumerate()
            .find_map(|(i, next_sparse_entry_index)| {
                next_sparse_entry_index.map(|next_sparse_entry_index| (i, next_sparse_entry_index))
            })?;
        let mut next_contiguous_index =
            self.bitmap_union.bitmaps[i].entries[next_sparse_index].contiguous_index;
        let mut bitmap_word = self.bitmap_union.bitmaps[i].entries[next_sparse_index].bitmap_word;

        for j in i + 1..N {
            if let Some(next_sparse_index) = self.next_sparse_entry_indices[j] {
                let entry_next_contiguous_index =
                    self.bitmap_union.bitmaps[j].entries[next_sparse_index].contiguous_index;
                match entry_next_contiguous_index.cmp(&next_contiguous_index) {
                    cmp::Ordering::Less => {
                        i = j;
                        next_contiguous_index = entry_next_contiguous_index;
                        bitmap_word =
                            self.bitmap_union.bitmaps[j].entries[next_sparse_index].bitmap_word;
                    }
                    cmp::Ordering::Equal => {
                        bitmap_word |=
                            self.bitmap_union.bitmaps[j].entries[next_sparse_index].bitmap_word;
                    }
                    cmp::Ordering::Greater => (),
                }
            }
        }
        for j in i..N {
            if let Some(mut next_sparse_index) = self.next_sparse_entry_indices[j] {
                let entry_next_contiguous_offset =
                    self.bitmap_union.bitmaps[j].entries[next_sparse_index].contiguous_index;
                if entry_next_contiguous_offset == next_contiguous_index {
                    next_sparse_index += 1;
                    if next_sparse_index != self.bitmap_union.bitmaps.len() {
                        self.next_sparse_entry_indices[j] = Some(next_sparse_index);
                    } else {
                        self.next_sparse_entry_indices[j] = None;
                    }
                }
            }
        }
        Some((next_contiguous_index, bitmap_word))
    }
}
