// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use core::{iter, slice};

pub struct IoSlicesMut<'a, 'b> {
    // Until slice::take_first() has been stabilized,
    // slices needs to live in a Option<>.
    slices: Option<&'a mut [Option<&'b mut [u8]>]>,
}

impl<'a, 'b> IoSlicesMut<'a, 'b> {
    pub fn new(slices: &'a mut [Option<&'b mut [u8]>]) -> Self {
        let mut slices = Self {
            slices: Some(slices),
        };
        slices.advance(0);
        slices
    }

    pub fn len(&self) -> usize {
        let mut l = 0;
        for s in self.slices.as_deref().unwrap().iter() {
            l += s.as_ref().map(|s| s.len()).unwrap_or(0);
        }
        l
    }

    pub fn is_empty(&self) -> bool {
        self.slices.as_deref().unwrap().is_empty()
    }

    pub fn first(&mut self) -> Option<&mut [u8]> {
        self.slices
            .as_deref_mut()
            .unwrap()
            .first_mut()
            .and_then(|s| s.as_deref_mut())
    }

    pub fn take_first(&mut self) -> Option<&'b mut [u8]> {
        while !self.is_empty() {
            let slices = self.slices.take().unwrap();
            let first = slices[0].take();
            self.slices = Some(&mut slices[1..]);
            if let Some(first) = first {
                if !first.is_empty() {
                    return Some(first);
                }
            }
        }
        None
    }

    pub fn advance(&mut self, mut distance: usize) {
        let mut slices = self.slices.take().unwrap();
        while !slices.is_empty()
            && (distance > 0 || slices[0].as_ref().map(|s| s.is_empty()).unwrap_or(true))
        {
            let s0_len = slices[0].as_ref().map(|s| s.len()).unwrap_or(0);
            if s0_len <= distance {
                distance -= s0_len;
                slices = &mut slices[1..];
            } else {
                let s0 = slices[0].take().unwrap();
                let s0 = &mut s0[distance..];
                slices[0] = Some(s0);
                distance = 0;
            }
        }
        self.slices = Some(slices);
    }

    pub fn iter(&self) -> IoMutSlicesIter<'_, 'b> {
        IoMutSlicesIter {
            iter: self.slices.as_deref().unwrap().iter(),
        }
    }
}

pub struct IoMutSlicesIter<'a, 'b> {
    iter: slice::Iter<'a, Option<&'b mut [u8]>>,
}

impl<'a, 'b> iter::Iterator for IoMutSlicesIter<'a, 'b> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.iter.next() {
                Some(Some(s)) => {
                    if !s.is_empty() {
                        break Some(&(**s)[..]);
                    }
                }
                Some(&None) => (),
                None => break None,
            }
        }
    }
}

#[test]
fn test_io_slices_mut() {
    let mut a = [0u8, 0u8];
    let mut b: [u8; 0] = [0u8; 0];
    let mut c = [0u8, 0u8];
    let mut d: [u8; 0] = [0u8; 0];
    let mut slices = [
        None,
        Some(a.as_mut_slice()),
        None,
        Some(b.as_mut_slice()),
        None,
        Some(c.as_mut_slice()),
        None,
        Some(d.as_mut_slice()),
        None,
    ];
    let mut slices = IoSlicesMut::new(&mut slices);
    assert_eq!(slices.len(), 4);
    slices.first().unwrap()[0] = 1;
    slices.advance(1);
    assert_eq!(slices.len(), 3);
    slices.first().unwrap()[0] = 2;
    slices.advance(1);
    assert_eq!(slices.len(), 2);
    slices.first().unwrap()[0] = 3;
    slices.advance(1);
    assert_eq!(slices.len(), 1);
    slices.first().unwrap()[0] = 4;
    slices.advance(1);
    assert_eq!(slices.len(), 0);
    assert!(slices.is_empty());
    assert_eq!(a, [1, 2]);
    assert_eq!(c, [3, 4]);

    let mut a = [0u8, 0u8];
    let mut b: [u8; 0] = [0u8; 0];
    let mut c = [0u8, 0u8];
    let mut d: [u8; 0] = [0u8; 0];
    let mut slices = [
        None,
        Some(a.as_mut_slice()),
        None,
        Some(b.as_mut_slice()),
        None,
        Some(c.as_mut_slice()),
        None,
        Some(d.as_mut_slice()),
        None,
    ];
    let mut slices = IoSlicesMut::new(&mut slices);
    let s = slices.take_first().unwrap();
    assert_eq!(s.len(), 2);
    s[0] = 1;
    s[1] = 2;
    let s = slices.take_first().unwrap();
    assert_eq!(s.len(), 2);
    s[0] = 3;
    s[1] = 4;
    assert!(slices.take_first().is_none());
    assert_eq!(a, [1, 2]);
    assert_eq!(c, [3, 4]);
}

pub struct IoSlices<'a, 'b> {
    // Until slice::take_first() has been stabilized,
    // slices needs to live in a Option<>.
    slices: Option<&'a mut [Option<&'b [u8]>]>,
}

impl<'a, 'b> IoSlices<'a, 'b> {
    pub fn new(slices: &'a mut [Option<&'b [u8]>]) -> Self {
        let mut slices = Self {
            slices: Some(slices),
        };
        slices.advance(0);
        slices
    }

    pub fn len(&self) -> usize {
        let mut l = 0;
        for s in self.slices.as_deref().unwrap().iter() {
            l += s.as_ref().map(|s| s.len()).unwrap_or(0);
        }
        l
    }

    pub fn is_empty(&self) -> bool {
        self.slices.as_deref().unwrap().is_empty()
    }

    pub fn first(&mut self) -> Option<&[u8]> {
        self.slices
            .as_deref()
            .unwrap()
            .first()
            .and_then(|s| s.as_deref())
    }

    pub fn take_first(&mut self) -> Option<&'b [u8]> {
        while !self.is_empty() {
            let slices = self.slices.take().unwrap();
            let first = slices[0].take();
            self.slices = Some(&mut slices[1..]);
            if let Some(first) = first {
                if !first.is_empty() {
                    return Some(first);
                }
            }
        }
        None
    }

    pub fn advance(&mut self, mut distance: usize) {
        let mut slices = self.slices.take().unwrap();
        while !slices.is_empty()
            && (distance > 0 || slices[0].as_ref().map(|s| s.is_empty()).unwrap_or(true))
        {
            let s0_len = slices[0].as_ref().map(|s| s.len()).unwrap_or(0);
            if s0_len <= distance {
                distance -= s0_len;
                slices = &mut slices[1..];
            } else {
                let s0 = slices[0].take().unwrap();
                let s0 = &s0[distance..];
                slices[0] = Some(s0);
                distance = 0;
            }
        }
        self.slices = Some(slices);
    }

    pub fn iter(&self) -> IoSlicesIter<'_, 'b> {
        IoSlicesIter {
            iter: self.slices.as_deref().unwrap().iter(),
        }
    }
}

pub struct IoSlicesIter<'a, 'b> {
    iter: slice::Iter<'a, Option<&'b [u8]>>,
}

impl<'a, 'b> iter::Iterator for IoSlicesIter<'a, 'b> {
    type Item = &'b [u8];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.iter.next() {
                Some(&Some(s)) => {
                    if !s.is_empty() {
                        break Some(s);
                    }
                }
                Some(&None) => (),
                None => break None,
            }
        }
    }
}

#[test]
fn test_io_slices() {
    let a = [1u8, 2u8];
    let b: [u8; 0] = [0u8; 0];
    let c = [3u8, 4u8];
    let d: [u8; 0] = [0u8; 0];
    let mut slices = [
        None,
        Some(a.as_slice()),
        None,
        Some(b.as_slice()),
        None,
        Some(c.as_slice()),
        None,
        Some(d.as_slice()),
        None,
    ];
    let mut slices = IoSlices::new(&mut slices);
    assert_eq!(slices.len(), 4);
    assert_eq!(slices.first().unwrap()[0], 1);
    slices.advance(1);
    assert_eq!(slices.len(), 3);
    assert_eq!(slices.first().unwrap()[0], 2);
    slices.advance(1);
    assert_eq!(slices.len(), 2);
    assert_eq!(slices.first().unwrap()[0], 3);
    slices.advance(1);
    assert_eq!(slices.len(), 1);
    assert_eq!(slices.first().unwrap()[0], 4);
    slices.advance(1);
    assert_eq!(slices.len(), 0);
    assert!(slices.is_empty());
    assert_eq!(a, [1, 2]);
    assert_eq!(c, [3, 4]);

    let a = [1u8, 2u8];
    let b: [u8; 0] = [0u8; 0];
    let c = [3u8, 4u8];
    let d: [u8; 0] = [0u8; 0];
    let mut slices = [
        None,
        Some(a.as_slice()),
        None,
        Some(b.as_slice()),
        None,
        Some(c.as_slice()),
        None,
        Some(d.as_slice()),
        None,
    ];
    let mut slices = IoSlices::new(&mut slices);
    let s = slices.take_first().unwrap();
    assert_eq!(s, [1, 2]);
    let s = slices.take_first().unwrap();
    assert_eq!(s, [3, 4]);
    assert!(slices.take_first().is_none());
}
