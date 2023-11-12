// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

macro_rules! impl_bitmanip_common {
    ($t:ty, $ut:ty, $st:ty) => {
        fn trailing_bits_mask(count: u32) -> $t {
            debug_assert!(count <= <$t>::BITS);
            let all = count / <$t>::BITS;
            let count = count % <$t>::BITS;
            (((1 as $ut) << count) - 1).wrapping_sub(all as $ut) as $t
        }

        fn is_nonzero(self) -> Self {
            let value = self as $ut;
            ((value | value.wrapping_neg()) >> (<$ut>::BITS - 1)) as $t
        }

        fn is_pow2(self) -> bool {
            let value = <Self as BitManip>::abs(self);
            value & value.wrapping_sub(1) == 0
        }

        fn is_aligned_pow2(self, pow2_log2: u32) -> bool {
            <Self as BitManip>::abs(self) & <$ut as BitManip>::trailing_bits_mask(pow2_log2) == 0
        }
    };
}

macro_rules! impl_bitmanip_u {
    ($ut:ty, $st:ty) => {
        impl BitManip for $ut {
            type UnsignedType = $ut;

            impl_bitmanip_common!($ut, $ut, $st);

            fn abs(self) -> Self::UnsignedType {
                self
            }

            fn exp2(pow2_log2: u32) -> Self {
                debug_assert!(pow2_log2 < <$ut>::BITS);
                (1 as $ut) << pow2_log2
            }

            fn significant_bits(self) -> u32 {
                // A zero should still have one significant bit.
                let lz = (self | 1).leading_zeros();
                debug_assert!(lz < <$ut>::BITS);
                <$ut>::BITS - lz
            }

            fn sign_extend(self, sign_bit_pos: u32) -> Self {
                let leading_bits = <$ut>::BITS - sign_bit_pos - 1;
                (((self << leading_bits) as $st) >> leading_bits) as $ut
            }
        }
    }
}

macro_rules! impl_ubitmanip {
    ($ut:ty, $st:ty) => {
        impl UBitManip for $ut {
            fn round_down_pow2(self, pow2_log2: u32) -> Self {
                debug_assert!(pow2_log2 < <$ut>::BITS);
                (self >> pow2_log2) << pow2_log2
            }

            fn round_up_pow2(self, pow2_log2: u32) -> Option<Self> {
                let t = ((1 as $ut) << pow2_log2) - 1;
                Some(self.checked_add(t)? & !t)
            }

            fn round_up_next_pow2(self) -> Option<Self> {
                let lz = self.wrapping_sub(1).leading_zeros();
                if lz != 0 {
                    Some((1 as $ut) << (<$ut>::BITS - lz))
                } else {
                    if self == 0 {
                        Some(0)
                    } else {
                        None
                    }
                }
            }

            fn expand_from_right(self, mut mask: $ut) -> Self {
                // Refer to Hacker's Delight, 2nd ed., 7-5 ("Expand, or Generalized Insert").
                const BITS_LOG2: u32 = <$ut>::BITS.ilog2();
                let mut x = self;
                let mut a = [0 as $ut; BITS_LOG2 as usize];

                let m0 = mask;
                let mut mk = !mask << 1;

                for i in 0..BITS_LOG2 {
                    let mut mp = mk;
                    for j in 0..BITS_LOG2 {
                        mp = mp ^ (mp << (1 << j));
                    }
                    let mv = mp & mask;
                    a[i as usize] = mv;
                    mask = (mask ^ mv) | (mv >> (1 << i));
                    mk &= !mp;
                }

                let mut i = BITS_LOG2;
                while i > 0 {
                    i -= 1;
                    let mv = a[i as usize];
                    let t = x << (1 << i);
                    x = (x & !mv) | (t & mv);
                }
                return x & m0;
            }

            fn expand_from_left(self, mut mask: $ut) -> Self {
                // Refer to Hacker's Delight, 2nd ed., 7-5 ("Expand, or Generalized Insert").
                const BITS_LOG2: u32 = <$ut>::BITS.ilog2();
                let mut x = self;
                let mut a = [0 as $ut; BITS_LOG2 as usize];

                let m0 = mask;
                let mut mk = !mask >> 1;

                for i in 0..BITS_LOG2 {
                    let mut mp = mk;
                    for j in 0..BITS_LOG2 {
                        mp = mp ^ (mp >> (1 << j));
                    }
                    let mv = mp & mask;
                    a[i as usize] = mv;
                    mask = (mask ^ mv) | (mv << (1 << i));
                    mk &= !mp;
                }

                let mut i = BITS_LOG2;
                while i > 0 {
                    i -= 1;
                    let mv = a[i as usize];
                    let t = x >> (1 << i);
                    x = (x & !mv) | (t & mv);
                }
                return x & m0;
            }
        }
    };
}

macro_rules! impl_bitmanip_s {
    ($ut:ty, $st:ty) => {
        impl BitManip for $st {
            type UnsignedType = $ut;

            impl_bitmanip_common!($st, $ut, $st);

            fn abs(self) -> Self::UnsignedType {
                let neg_mask = (self >> (<$st>::BITS - 1)) as $ut;
                ((self as $ut) ^ neg_mask).wrapping_sub(neg_mask)
            }

            fn exp2(pow2_log2: u32) -> Self {
                debug_assert!(pow2_log2 < <$st>::BITS - 1);
                (1 as $st) << pow2_log2
            }

            fn significant_bits(self) -> u32 {
                let value = self as $ut;
                // Invert if negative.
                let value = value ^ (0 as $ut).wrapping_sub(value >> (<$ut>::BITS - 1));

                let lz = value.leading_zeros();
                debug_assert!(lz != 0 && lz <= <$ut>::BITS);
                <$ut>::BITS - (lz - 1)
            }

            fn sign_extend(self, sign_bit_pos: u32) -> Self {
                (self as $ut).sign_extend(sign_bit_pos) as $st
            }
        }
    }
}

pub trait BitManip: Copy {
    type UnsignedType;

    fn trailing_bits_mask(count: u32) -> Self;
    fn abs(self) -> Self::UnsignedType;
    fn is_nonzero(self) -> Self;

    fn exp2(pow2_log2: u32) -> Self;

    fn is_pow2(self) -> bool;

    fn is_aligned_pow2(self, pow2_log2: u32) -> bool;

    fn significant_bits(self) -> u32;
    fn sign_extend(self, sign_bit_pos: u32) -> Self;
}

pub trait UBitManip: Sized + BitManip<UnsignedType = Self> {
    fn round_down_pow2(self, pow2_log2: u32) -> Self;
    fn round_up_pow2(self, pow2_log2: u32) -> Option<Self>;
    fn round_up_next_pow2(self) -> Option<Self>;
    fn expand_from_right(self, mask: Self) -> Self;
    fn expand_from_left(self, mask: Self) -> Self;
}

impl_bitmanip_u!(u8, i8);
impl_ubitmanip!(u8, i8);
impl_bitmanip_u!(u16, i16);
impl_ubitmanip!(u16, i16);
impl_bitmanip_u!(u32, i32);
impl_ubitmanip!(u32, i32);
impl_bitmanip_u!(u64, i64);
impl_ubitmanip!(u64, i64);
impl_bitmanip_u!(usize, isize);
impl_ubitmanip!(usize, isize);

impl_bitmanip_s!(u8, i8);
impl_bitmanip_s!(u16, i16);
impl_bitmanip_s!(u32, i32);
impl_bitmanip_s!(u64, i64);
