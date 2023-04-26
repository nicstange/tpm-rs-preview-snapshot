extern crate alloc;

use crate::index_permutation::apply_and_invert_index_perm;
use crate::interface;
use alloc::slice;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::{Index, IndexMut};

pub trait LockedLeaseGuard<'a> {}

pub trait Lease {
    fn get_handle(&self) -> u32;
}

pub struct Leases<L: Lease> {
    sorted_leases: Vec<L>,
    index_perm: Vec<usize>,
}

impl<L: Lease> Leases<L> {
    pub fn new(mut leases: Vec<L>) -> Result<Self, interface::TpmErr> {
        // Create an index permutation describing the sort operation on the leases.
        let mut index_perm = Vec::new();
        index_perm
            .try_reserve_exact(leases.len())
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        for i in 0..index_perm.len() {
            index_perm.push(i);
        }
        // Unstable sort avoids internal memory allocation and suffices here.
        index_perm.sort_unstable_by_key(|i| leases[*i].get_handle());

        // After application and inversion of the permuation, leases is sorted by handle
        // and (the now inverted) index_perm describes the mapping from original
        // index to the bew position within the sorted leases.
        apply_and_invert_index_perm(&mut index_perm, &mut leases);

        // Remove duplicates
        let mut i = 1;
        while i < leases.len() {
            if leases[i - 1].get_handle() == leases[i].get_handle() {
                // Adjust all indices in the index_perm as appropriate.
                for j in index_perm.iter_mut() {
                    if *j >= i {
                        *j -= 1;
                    }
                }
                leases.remove(i);
            } else {
                i += 1;
            }
        }

        Ok(Self {
            sorted_leases: leases,
            index_perm,
        })
    }

    pub fn empty() -> Self {
        Self {
            sorted_leases: Vec::new(),
            index_perm: Vec::new(),
        }
    }

    pub fn push(&mut self, lease: L) -> Result<(), interface::TpmErr> {
        self.index_perm
            .try_reserve_exact(1)
            .map_err(|_| tpm_err_rc!(MEMORY))?;
        let i = self.sorted_index_for_handle(lease.get_handle());
        match i {
            Ok(i) => {
                self.index_perm.push(i);
            }
            Err(i) => {
                self.sorted_leases
                    .try_reserve_exact(1)
                    .map_err(|_| tpm_err_rc!(MEMORY))?;
                self.sorted_leases.insert(i, lease);
                for j in self.index_perm.iter_mut() {
                    if *j >= i {
                        *j += 1;
                    }
                }
                self.index_perm.push(i);
            }
        };
        Ok(())
    }

    fn sorted_index_for_handle(&self, handle: u32) -> Result<usize, usize> {
        self.sorted_leases
            .binary_search_by_key(&handle, |l| l.get_handle())
    }

    pub fn remove(&mut self, index: usize) {
        let sorted_index = self.index_perm.remove(index);
        if self.index_perm.iter().any(|i| *i == sorted_index) {
            self.sorted_leases.remove(sorted_index);
            for j in self.index_perm.iter_mut() {
                if *j > sorted_index {
                    *j -= 1;
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.index_perm.len()
    }

    pub fn distinct_len(&self) -> usize {
        self.sorted_leases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sorted_leases.is_empty()
    }

    pub fn index_with_handle_iter(&self, handle: u32) -> IndexWithHandleIterator<L> {
        let sorted_index = self.sorted_index_for_handle(handle).ok();
        IndexWithHandleIterator {
            leases: self,
            sorted_index,
            next_index: 0,
        }
    }

    pub fn try_hold<'a, G: LockedLeaseGuard<'a>, TH>(
        &'a self,
        try_hold: &mut TH,
    ) -> Result<LockedLeasesGuards<'a, L, G>, interface::TpmErr>
    where
        TH: FnMut(&'a [L]) -> Result<Vec<G>, interface::TpmErr>,
    {
        Ok(LockedLeasesGuards {
            leases: self,
            guards: try_hold(&self.sorted_leases)?,
        })
    }
}

impl<L: Lease> Index<usize> for Leases<L> {
    type Output = L;

    fn index(&self, index: usize) -> &Self::Output {
        &self.sorted_leases[self.index_perm[index]]
    }
}

pub struct IndexWithHandleIterator<'a, L: Lease> {
    leases: &'a Leases<L>,
    sorted_index: Option<usize>,
    next_index: usize,
}

impl<'a, L: Lease> Iterator for IndexWithHandleIterator<'a, L> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let sorted_index = self.sorted_index?;
        let index = self
            .leases
            .index_perm
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                if *s == sorted_index && i >= self.next_index {
                    Some(i)
                } else {
                    None
                }
            })
            .min();
        if let Some(index) = &index {
            self.next_index = index + 1;
        }
        index
    }
}

pub struct LockedLeasesGuards<'a, L: Lease, G: LockedLeaseGuard<'a>> {
    leases: &'a Leases<L>,
    guards: Vec<G>,
}

impl<'a, L: Lease, G: LockedLeaseGuard<'a>> LockedLeasesGuards<'a, L, G> {
    pub fn len(&self) -> usize {
        self.leases.len()
    }

    pub fn distinct_len(&self) -> usize {
        self.leases.distinct_len()
    }

    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    pub fn iter_distinct<'b>(&'b self) -> DistinctLockedLeasesIterator<'a, 'b, L, G> {
        DistinctLockedLeasesIterator {
            guards_iter: self.guards.iter(),
            _phantom: PhantomData,
        }
    }

    pub fn iter_distinct_mut<'b>(&'b mut self) -> DistinctLockedLeasesMutIterator<'a, 'b, L, G> {
        DistinctLockedLeasesMutIterator {
            guards_iter: self.guards.iter_mut(),
            _phantom: PhantomData,
        }
    }

    pub fn get_distinct(&self, index: usize) -> &G {
        &self.guards[index]
    }

    pub fn get_distinct_mut(&mut self, index: usize) -> &mut G {
        &mut self.guards[index]
    }

    pub fn drain<F, E>(mut self, f: &mut F) -> Result<(), E>
    where
        F: FnMut(G) -> Result<(), E>,
    {
        for guard in self.guards.drain(..) {
            f(guard)?;
        }
        Ok(())
    }
}

impl<'a, L: Lease, G: LockedLeaseGuard<'a>> Index<usize> for LockedLeasesGuards<'a, L, G> {
    type Output = G;

    fn index(&self, index: usize) -> &Self::Output {
        &self.guards[self.leases.index_perm[index]]
    }
}

impl<'a, L: Lease, G: LockedLeaseGuard<'a>> IndexMut<usize> for LockedLeasesGuards<'a, L, G> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.guards[self.leases.index_perm[index]]
    }
}

pub struct DistinctLockedLeasesIterator<'a, 'b, L: Lease, G: LockedLeaseGuard<'a>> {
    guards_iter: slice::Iter<'b, G>,
    _phantom: PhantomData<&'b LockedLeasesGuards<'a, L, G>>,
}

impl<'a, 'b, L: Lease, G: LockedLeaseGuard<'a>> Iterator
    for DistinctLockedLeasesIterator<'a, 'b, L, G>
{
    type Item = &'b G;

    fn next(&mut self) -> Option<Self::Item> {
        self.guards_iter.next()
    }
}

pub struct DistinctLockedLeasesMutIterator<'a, 'b, L: Lease, G: LockedLeaseGuard<'a>> {
    guards_iter: slice::IterMut<'b, G>,
    _phantom: PhantomData<&'b mut LockedLeasesGuards<'a, L, G>>,
}

impl<'a, 'b, L: Lease, G: LockedLeaseGuard<'a>> Iterator
    for DistinctLockedLeasesMutIterator<'a, 'b, L, G>
{
    type Item = &'b mut G;

    fn next(&mut self) -> Option<Self::Item> {
        self.guards_iter.next()
    }
}
