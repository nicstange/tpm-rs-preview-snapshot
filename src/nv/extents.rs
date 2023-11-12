// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use super::error;
use super::layout::{self, LogicalAllocBlockRange, PhysicalAllocBlockRange};
use crate::interface;
use alloc::vec;
use core::slice;

pub struct PhysicalExtents {
    /// Extents stored as `(physical_begin, block_count)`, in units of
    /// allocation blocks.
    extents: vec::Vec<(u64, u64)>,
}

impl PhysicalExtents {
    pub fn new() -> Self {
        Self {
            extents: vec::Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.extents.is_empty()
    }

    pub fn len(&self) -> usize {
        self.extents.len()
    }

    pub fn get_extent_range(&self, i: usize) -> layout::PhysicalAllocBlockRange {
        let entry = &self.extents[i];
        layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(entry.0),
            layout::AllocBlockCount::from(entry.1),
        ))
    }

    pub fn extend(
        &mut self,
        range: &layout::PhysicalAllocBlockRange,
    ) -> Result<(), interface::TpmErr> {
        if u64::from(range.block_count()) == 0 {
            return Ok(());
        }
        debug_assert!(!(0..self.len()).any(|i| self.get_extent_range(i).overlaps_with(range)));
        if !self.is_empty() {
            let last = self.get_extent_range(self.len() - 1);
            if last.end() == range.begin() || last.begin() == range.end() {
                let entry = self.extents.last_mut().unwrap();
                entry.1 += u64::from(range.block_count());
                if last.begin() == range.end() {
                    entry.0 = u64::from(range.begin());
                }
                return Ok(());
            }
        }

        if self.extents.capacity() == self.extents.len() {
            self.extents
                .try_reserve_exact(1)
                .map_err(|_| tpm_err_rc!(MEMORY))?;
        }
        self.extents
            .push((u64::from(range.begin()), u64::from(range.block_count())));
        Ok(())
    }

    pub fn remove_extent(&mut self, i: usize) {
        self.extents.remove(i);
    }

    pub fn shrink_extent_by(
        &mut self,
        i: usize,
        allocation_blocks: layout::AllocBlockCount,
    ) -> bool {
        let allocation_blocks = u64::from(allocation_blocks);
        debug_assert!(allocation_blocks <= self.extents[i].1);
        if allocation_blocks == self.extents[i].1 {
            self.remove_extent(i);
            true
        } else {
            self.extents[i].1 -= allocation_blocks;
            false
        }
    }

    pub fn iter(&self) -> PhysicalExtentsIterator<'_> {
        PhysicalExtentsIterator {
            extents_iter: self.extents.iter(),
        }
    }
}

impl From<LogicalExtents> for PhysicalExtents {
    fn from(value: LogicalExtents) -> Self {
        let mut extents = value.extents;
        let mut last_logical_end = layout::LogicalAllocBlockIndex::from(0);
        for entry in extents.iter_mut() {
            let logical_end = layout::LogicalAllocBlockIndex::from(entry.1);
            entry.1 = (logical_end - last_logical_end).into();
            last_logical_end = logical_end;
        }
        Self { extents }
    }
}

pub struct PhysicalExtentsIterator<'a> {
    extents_iter: slice::Iter<'a, (u64, u64)>,
}

impl<'a> Iterator for PhysicalExtentsIterator<'a> {
    type Item = PhysicalAllocBlockRange;

    fn next(&mut self) -> Option<Self::Item> {
        self.extents_iter
            .next()
            .map(|(physical_begin, block_count)| {
                layout::PhysicalAllocBlockRange::from((
                    layout::PhysicalAllocBlockIndex::from(*physical_begin),
                    layout::AllocBlockCount::from(*block_count),
                ))
            })
    }
}

pub struct PhysicalExtentsSet {
    /// Sorted extents stored as `(physical_begin, physical_end)`, in units of
    /// allocation blocks.
    extents: vec::Vec<(u64, u64)>,
}

impl PhysicalExtentsSet {
    fn entry_physical_range(&self, index: usize) -> layout::PhysicalAllocBlockRange {
        let entry = &self.extents[index];
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(entry.0),
            layout::PhysicalAllocBlockIndex::from(entry.1),
        )
    }

    pub fn overlaps(
        &self,
        query_range: layout::PhysicalAllocBlockRange,
    ) -> PhysicalExtentsSetOverlapsIterator<'_> {
        let (index_begin, index_end) = self._overlaps(&query_range);
        PhysicalExtentsSetOverlapsIterator {
            extents: self,
            query_range,
            index_begin,
            index_end,
        }
    }

    pub fn insert(
        &mut self,
        insertion_range: layout::PhysicalAllocBlockRange,
    ) -> Result<(), error::NVError> {
        let (mut overlap_begin, mut overlap_end) = self._overlaps(&insertion_range);
        if overlap_begin != 0
            && self.entry_physical_range(overlap_begin - 1).end() == insertion_range.begin()
        {
            overlap_begin -= 1;
        }
        if overlap_end < self.extents.len()
            && self.entry_physical_range(overlap_end).begin() == insertion_range.end()
        {
            overlap_end += 1;
        }

        debug_assert!(
            overlap_begin == 0
                || self.entry_physical_range(overlap_begin - 1).end() < insertion_range.begin()
        );
        debug_assert!(
            overlap_end == self.extents.len()
                || self.entry_physical_range(overlap_end).begin() > insertion_range.end()
        );

        if overlap_begin == overlap_end {
            self.extents
                .try_reserve(1)
                .map_err(|_| error::NVError::TpmErr(tpm_err_rc!(MEMORY)))?;
            self.extents.insert(
                overlap_begin,
                (insertion_range.begin().into(), insertion_range.end().into()),
            );
        } else {
            self.extents[overlap_begin].0 = self
                .entry_physical_range(overlap_begin)
                .begin()
                .min(insertion_range.begin())
                .into();
            self.extents[overlap_begin].1 = self
                .entry_physical_range(overlap_end - 1)
                .end()
                .max(insertion_range.end())
                .into();
            self.extents.drain(overlap_begin + 1..overlap_end);
        }
        Ok(())
    }

    pub fn remove(
        &mut self,
        removal_range: &layout::PhysicalAllocBlockRange,
    ) -> Result<(), error::NVError> {
        let (mut overlap_begin, mut overlap_end) = self._overlaps(removal_range);

        if overlap_begin == overlap_end {
            return Ok(());
        }

        if overlap_begin + 1 == overlap_end
            && self.entry_physical_range(overlap_begin).begin() < removal_range.begin()
            && self.entry_physical_range(overlap_begin).end() > removal_range.end()
        {
            self.extents
                .try_reserve(1)
                .map_err(|_| error::NVError::TpmErr(tpm_err_rc!(MEMORY)))?;
            self.extents.insert(
                overlap_begin + 1,
                (
                    removal_range.end().into(),
                    self.entry_physical_range(overlap_begin).end().into(),
                ),
            );
            self.extents[overlap_begin].1 = removal_range.begin().into();
        } else {
            if self.entry_physical_range(overlap_begin).begin() < removal_range.begin() {
                self.extents[overlap_begin].1 = removal_range.begin().into();
                overlap_begin += 1;
            }
            if self.entry_physical_range(overlap_end - 1).end() > removal_range.end() {
                self.extents[overlap_end - 1].0 = removal_range.end().into();
                overlap_end -= 1;
            }
            self.extents.drain(overlap_begin..overlap_end);
        }

        Ok(())
    }

    // Pair of indices, first one points to the first entry with end >
    // query_range.begin(), second one points past the last entry with begin <
    // query_range.end(), if any.
    fn _overlaps(&self, query_range: &layout::PhysicalAllocBlockRange) -> (usize, usize) {
        if self.extents.is_empty() || self.entry_physical_range(0).begin() >= query_range.end() {
            // Return an empty interval located at the beginning.
            return (0, 0);
        } else if self.entry_physical_range(self.extents.len() - 1).end() <= query_range.begin() {
            // Return an empty interval located at the end.
            return (self.extents.len(), self.extents.len());
        }

        let mut l = 0;
        let mut u = self.extents.len() - 1;
        let mut l_index_last = 0;
        let mut u_index_last = self.extents.len() - 1;
        let index_first = loop {
            if l == u {
                debug_assert!(query_range.begin() < self.entry_physical_range(u).end());
                debug_assert!(
                    u == 0 || query_range.begin() >= self.entry_physical_range(u - 1).end()
                );
                break u;
            }

            // Compute m = (l + u) / 2 w/o overflow, c.f. Hacker's Delight, section 2-5.
            let i = (l & u) + ((l ^ u) >> 1);
            debug_assert_ne!(i, u);
            let entry_range = self.entry_physical_range(i);
            if query_range.begin() < entry_range.end() {
                u = i;
                if query_range.end() <= entry_range.begin() {
                    u_index_last = u - 1;
                }
            } else if query_range.begin() >= entry_range.end() {
                l = i + 1;
                l_index_last = i;
            }
        };

        let mut l = l_index_last;
        let mut u = u_index_last;
        let index_last = loop {
            if l == u {
                debug_assert!(query_range.end() > self.entry_physical_range(l).begin());
                debug_assert!(
                    l == self.extents.len() - 1
                        || query_range.end() <= self.entry_physical_range(l + 1).begin()
                );
                break l;
            }

            // Compute m = (l + u + 1) / 2 w/o overflow, c.f. Hacker's Delight, section 2-5.
            debug_assert!(l < u); // l + 1 won't overflow.
            let i = ((l + 1) & u) + (((l + 1) ^ u) >> 1);
            debug_assert_ne!(i, l);
            let entry_range = self.entry_physical_range(i);
            if query_range.end() <= entry_range.begin() {
                u = i - 1;
            } else if query_range.end() > entry_range.begin() {
                l = i;
            }
        };

        let index_begin = index_first;
        let index_end = index_last + 1;
        debug_assert!(index_begin <= index_end);
        (index_begin, index_end)
    }
}

impl From<PhysicalExtents> for PhysicalExtentsSet {
    fn from(value: PhysicalExtents) -> Self {
        let mut extents = value.extents;
        extents.sort_by_key(|entry| layout::PhysicalAllocBlockIndex::from(entry.0));
        for entry in extents.iter_mut() {
            entry.1 = (layout::PhysicalAllocBlockIndex::from(entry.0)
                + layout::AllocBlockCount::from(entry.1))
            .into();
        }
        Self { extents }
    }
}

pub struct PhysicalExtentsSetOverlapsIterator<'a> {
    extents: &'a PhysicalExtentsSet,
    query_range: layout::PhysicalAllocBlockRange,
    index_begin: usize,
    index_end: usize,
}

impl<'a> Iterator for PhysicalExtentsSetOverlapsIterator<'a> {
    type Item = layout::PhysicalAllocBlockRange;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index_begin < self.index_end {
            let index = self.index_begin;
            self.index_begin += 1;

            let entry_range = self.extents.entry_physical_range(index);

            Some(layout::PhysicalAllocBlockRange::new(
                entry_range.begin().max(self.query_range.begin()),
                entry_range.end().min(self.query_range.end()),
            ))
        } else {
            None
        }
    }
}

#[test]
fn test_physical_extents_set_overlaps() {
    let extents_set = PhysicalExtentsSet::from(PhysicalExtents {
        extents: vec::Vec::from([(6, 2), (4, 1), (1, 2)]),
    });

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(1),
    ));
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(2),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(2),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(2),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(2),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(3),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(3),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(2),
        layout::PhysicalAllocBlockIndex::from(3),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(2),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(4),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(4),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(2),
        layout::PhysicalAllocBlockIndex::from(4),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(2),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(3),
        layout::PhysicalAllocBlockIndex::from(4),
    ));
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(5),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(5),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(2),
        layout::PhysicalAllocBlockIndex::from(5),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(2),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(3),
        layout::PhysicalAllocBlockIndex::from(5),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(4),
        layout::PhysicalAllocBlockIndex::from(5),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(6),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(6),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(2),
        layout::PhysicalAllocBlockIndex::from(6),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(2),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(3),
        layout::PhysicalAllocBlockIndex::from(6),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(4),
        layout::PhysicalAllocBlockIndex::from(6),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(5),
        layout::PhysicalAllocBlockIndex::from(6),
    ));
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(7),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(7),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(7),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(7),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(2),
        layout::PhysicalAllocBlockIndex::from(7),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(2),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(7),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(3),
        layout::PhysicalAllocBlockIndex::from(7),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(7),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(4),
        layout::PhysicalAllocBlockIndex::from(7),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(7),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(5),
        layout::PhysicalAllocBlockIndex::from(7),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(7),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(6),
        layout::PhysicalAllocBlockIndex::from(7),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(7),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(2),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(2),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(3),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(4),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(5),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(6),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(7),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(7),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(2),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(2),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(3),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(4),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(5),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(6),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(7),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(7),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(8),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert!(overlaps.next().is_none());
}

/// Mapping of contiguous file logical allocation block extents to backing
/// storage.
pub struct LogicalExtents {
    /// Extents stored as `(physical_begin, logical_end)`, in units of
    /// allocation blocks. The virtual `logical_begin` is implicitly equal
    /// to the previous entry's `logical_end`, if any, zero otherwise.
    extents: vec::Vec<(u64, u64)>,
}

impl LogicalExtents {
    pub fn new() -> Self {
        Self {
            extents: vec::Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.extents.is_empty()
    }

    pub fn len(&self) -> usize {
        self.extents.len()
    }

    pub fn allocation_block_count(&self) -> layout::AllocBlockCount {
        layout::AllocBlockCount::from(self.extents.last().map(|e| e.1).unwrap_or(0))
    }

    pub fn extend_by_physical(
        &mut self,
        physical_extent: layout::PhysicalAllocBlockRange,
    ) -> Result<(), interface::TpmErr> {
        if self.extents.capacity() == self.extents.len() {
            self.extents
                .try_reserve_exact(1)
                .map_err(|_| tpm_err_rc!(MEMORY))?;
        }
        let logical_end = self.allocation_block_count() + physical_extent.block_count();
        self.extents
            .push((u64::from(physical_extent.begin()), u64::from(logical_end)));
        Ok(())
    }

    pub fn iter(&self) -> LogicalExtentsRangeIterator<'_> {
        if !self.extents.is_empty() {
            let index_last = self.extents.len() - 1;
            let end_in_last = self.entry_logical_range(index_last).block_count();
            let range = LogicalExtentsRange {
                index_first: 0,
                index_last,
                offset_in_first: layout::AllocBlockCount::from(0),
                end_in_last,
            };
            LogicalExtentsRangeIterator {
                extents: self,
                range: Some(range),
                index: 0,
            }
        } else {
            LogicalExtentsRangeIterator {
                extents: self,
                range: None,
                index: 0,
            }
        }
    }

    pub fn iter_range(
        &self,
        query_range: &LogicalAllocBlockRange,
    ) -> LogicalExtentsRangeIterator<'_> {
        let range = self.lookup_range(query_range);
        LogicalExtentsRangeIterator {
            extents: self,
            range,
            index: 0,
        }
    }

    fn entry_logical_range(&self, index: usize) -> layout::LogicalAllocBlockRange {
        layout::LogicalAllocBlockRange::new(
            if index != 0 {
                layout::LogicalAllocBlockIndex::from(self.extents[index - 1].1)
            } else {
                layout::LogicalAllocBlockIndex::from(0)
            },
            layout::LogicalAllocBlockIndex::from(self.extents[index].1),
        )
    }

    fn lookup_range(&self, query_range: &LogicalAllocBlockRange) -> Option<LogicalExtentsRange> {
        debug_assert!(query_range.begin() < query_range.end());
        debug_assert!(!self.extents.is_empty());
        debug_assert!(query_range.end() <= self.entry_logical_range(self.extents.len() - 1).end());

        let mut l = 0;
        let mut u = self.extents.len() - 1;
        let mut u_index_last = self.extents.len() - 1;
        let index_first = loop {
            // Compute m = (l + u) / 2 w/o overflow, c.f. Hacker's Delight, section 2-5.
            let i = (l & u) + ((l ^ u) >> 1);
            let entry_range = self.entry_logical_range(i);
            if query_range.begin() < entry_range.begin() {
                u = i - 1;
                if query_range.end() <= entry_range.begin() {
                    u_index_last = u;
                }
            } else if query_range.begin() >= entry_range.end() {
                l = i + 1;
            } else {
                break i;
            }
            if u < l {
                return None;
            }
        };

        let mut l = index_first;
        let mut u = u_index_last;
        let index_last = loop {
            // Compute m = (l + u) / 2 w/o overflow, c.f. Hacker's Delight, section 2-5.
            let i = (l & u) + ((l ^ u) >> 1);
            let entry_range = self.entry_logical_range(i);
            if query_range.end() <= entry_range.begin() {
                u = i - 1;
            } else if query_range.end() > entry_range.end() {
                l = i + 1;
            } else {
                break i;
            }
            if u < l {
                return None;
            }
        };

        let offset_in_first = query_range.begin() - self.entry_logical_range(index_first).begin();
        let end_in_last = query_range.end() - self.entry_logical_range(index_last).begin();

        Some(LogicalExtentsRange {
            index_first,
            index_last,
            offset_in_first,
            end_in_last,
        })
    }
}

#[test]
fn test_logical_extents_lookup_range() {
    let extents = LogicalExtents::from(PhysicalExtents {
        extents: vec::Vec::from([(6, 2), (4, 1), (0, 2)]),
    });

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(0),
                layout::LogicalAllocBlockIndex::from(1)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 0,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(0),
                layout::LogicalAllocBlockIndex::from(2)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 0,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(2),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(1),
                layout::LogicalAllocBlockIndex::from(2)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 0,
            offset_in_first: layout::AllocBlockCount::from(1),
            end_in_last: layout::AllocBlockCount::from(2),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(0),
                layout::LogicalAllocBlockIndex::from(3)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 1,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(1),
                layout::LogicalAllocBlockIndex::from(3)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 1,
            offset_in_first: layout::AllocBlockCount::from(1),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(2),
                layout::LogicalAllocBlockIndex::from(3)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 1,
            index_last: 1,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(0),
                layout::LogicalAllocBlockIndex::from(4)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(1),
                layout::LogicalAllocBlockIndex::from(4)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(1),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(2),
                layout::LogicalAllocBlockIndex::from(4)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 1,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(3),
                layout::LogicalAllocBlockIndex::from(4)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 2,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(0),
                layout::LogicalAllocBlockIndex::from(5)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(2),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(1),
                layout::LogicalAllocBlockIndex::from(5)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(1),
            end_in_last: layout::AllocBlockCount::from(2),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(2),
                layout::LogicalAllocBlockIndex::from(5)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 1,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(2),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(3),
                layout::LogicalAllocBlockIndex::from(5)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 2,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(2),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(4),
                layout::LogicalAllocBlockIndex::from(5)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 2,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(1),
            end_in_last: layout::AllocBlockCount::from(2),
        }
    );
}

impl From<PhysicalExtents> for LogicalExtents {
    fn from(value: PhysicalExtents) -> Self {
        let mut extents = value.extents;
        let mut logical_end = 0;
        for entry in extents.iter_mut() {
            logical_end += entry.1;
            entry.1 = logical_end;
        }
        Self { extents }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct LogicalExtentsRange {
    index_first: usize,
    index_last: usize,
    offset_in_first: layout::AllocBlockCount,
    end_in_last: layout::AllocBlockCount,
}

pub struct LogicalExtent {
    logical_begin: layout::LogicalAllocBlockIndex,
    physical_begin: layout::PhysicalAllocBlockIndex,
    allocation_block_count: layout::AllocBlockCount,
}

impl LogicalExtent {
    pub fn logical_range(&self) -> layout::LogicalAllocBlockRange {
        let logical_end = self.logical_begin + self.allocation_block_count;
        layout::LogicalAllocBlockRange::new(self.logical_begin, logical_end)
    }

    pub fn physical_range(&self) -> layout::PhysicalAllocBlockRange {
        let physical_end = self.physical_begin + self.allocation_block_count;
        layout::PhysicalAllocBlockRange::new(self.physical_begin, physical_end)
    }
}

pub struct LogicalExtentsRangeIterator<'a> {
    extents: &'a LogicalExtents,
    range: Option<LogicalExtentsRange>,
    index: usize,
}

impl<'a> Iterator for LogicalExtentsRangeIterator<'a> {
    type Item = LogicalExtent;

    fn next(&mut self) -> Option<Self::Item> {
        let range = self.range.as_ref()?;
        let index = self.index;
        if index == range.index_last + 1 {
            return None;
        }
        self.index += 1;

        let logical_range = self.extents.entry_logical_range(index);
        let mut logical_begin = logical_range.begin();
        let mut physical_begin =
            layout::PhysicalAllocBlockIndex::from(self.extents.extents[index].0);
        if index == range.index_first {
            logical_begin += range.offset_in_first;
            physical_begin += range.offset_in_first;
        }

        let logical_end = if index != range.index_last {
            logical_range.end()
        } else {
            logical_range.begin() + range.end_in_last
        };

        Some(LogicalExtent {
            logical_begin,
            physical_begin,
            allocation_block_count: logical_end - logical_begin,
        })
    }
}
