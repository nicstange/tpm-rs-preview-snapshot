use cmpa::{self, LimbType};
use core::mem;

fn _ct_bytes_all_zero(bytes: &[u8]) -> cmpa::LimbChoice {
    let mut any_nonzero: cmpa::LimbType = 0;
    for b in bytes.iter() {
        any_nonzero |= *b as LimbType;
    }
    cmpa::ct_eq_l_l(any_nonzero, 0)
}

pub fn ct_bytes_all_zero(bytes: &[u8]) -> cmpa::LimbChoice {
    // Split bytes[] into regions of &[u8], &[LimbType], &[u8].
    let (bytes_head, limbs, bytes_tail) = unsafe { bytes.align_to::<cmpa::LimbType>() };
    let mut all_zero = _ct_bytes_all_zero(bytes_head);
    let mut limbs_any_nonzero: cmpa::LimbType = 0;
    for l in limbs.iter() {
        limbs_any_nonzero |= l;
    }
    all_zero &= cmpa::ct_eq_l_l(limbs_any_nonzero, 0);
    all_zero &= _ct_bytes_all_zero(bytes_tail);
    all_zero
}

#[test]
fn test_ct_bytes_all_zero() {
    let mut bytes = [0u8; 32 + mem::size_of::<cmpa::LimbType>() - 1];
    for i in 0..mem::size_of::<cmpa::LimbType>() - 1 {
        let bytes = &mut bytes[i..i + 32];
        bytes.fill(0);
        assert_ne!(ct_bytes_all_zero(bytes).unwrap(), 0);

        for j in 0..bytes.len() {
            bytes.fill(0);
            bytes[j] = 1;
            assert_eq!(ct_bytes_all_zero(bytes).unwrap(), 0);
        }
    }
}

fn _ct_bytes_eq(bytes0: &[u8], bytes1: &[u8]) -> cmpa::LimbChoice {
    debug_assert_eq!(bytes0.len(), bytes1.len());
    let mut any_neq: cmpa::LimbType = 0;
    for pair in bytes0.iter().zip(bytes1.iter()) {
        any_neq |= (*pair.0 as LimbType) ^ (*pair.1 as LimbType);
    }
    cmpa::ct_eq_l_l(any_neq, 0)
}

pub fn ct_bytes_eq(bytes0: &[u8], bytes1: &[u8]) -> cmpa::LimbChoice {
    debug_assert_eq!(bytes0.len(), bytes1.len());

    // Split bytes0 and bytes1 into regions of &[u8], &[LimbType], &[u8] each.
    let (bytes0_head, bytes0_limbs, bytes0_tail) = unsafe { bytes0.align_to::<cmpa::LimbType>() };
    let (bytes1_head, bytes1_limbs, bytes1_tail) = unsafe { bytes1.align_to::<cmpa::LimbType>() };

    // Now, bytes0_head.len() is not necessarily equal to bytes1_head.len().
    // Grab the missing bytes back from the &[LimbType] region as appropriate.
    // Conditionally swap bytes0 and bytes1 such that bytes0 refers to the one
    // with the shorter &[u8] head part.
    let (bytes0_head, bytes0_limbs, bytes0_tail, bytes1_head, bytes1_limbs, bytes1_tail) =
        if bytes0_head.len() <= bytes1_head.len() {
            (
                bytes0_head,
                bytes0_limbs,
                bytes0_tail,
                bytes1_head,
                bytes1_limbs,
                bytes1_tail,
            )
        } else {
            (
                bytes1_head,
                bytes1_limbs,
                bytes1_tail,
                bytes0_head,
                bytes0_limbs,
                bytes0_tail,
            )
        };
    debug_assert!(bytes0_head.len() <= bytes1_head.len());
    if (bytes1_head.len() - bytes0_head.len()) % mem::size_of::<cmpa::LimbType>() != 0 {
        // The LimbType regions are in no correspondence.
        return _ct_bytes_eq(bytes0, bytes1);
    }
    let bytes0_head_0 = bytes0_head;
    // bytes1_head_0 corresponds to bytes0_head_0, bytes1_head_1 to the
    // head of dst_limbs.
    let (bytes1_head_0, bytes1_head_1) = bytes1_head.split_at(bytes0_head_0.len());
    debug_assert_eq!(bytes1_head_1.len() % mem::size_of::<cmpa::LimbType>(), 0);
    if bytes1_head_1.len() >= mem::size_of_val(bytes0_limbs) {
        // All of bytes0's LimbType region would get converted back into bytes anyway.
        return _ct_bytes_eq(bytes0, bytes1);
    }
    let (bytes0_limbs_head, bytes0_limbs) =
        bytes0_limbs.split_at(bytes1_head_1.len() / mem::size_of::<cmpa::LimbType>());
    let bytes0_head_1 = cmpa::limb_slice_as_bytes(bytes0_limbs_head);
    debug_assert_eq!(bytes0_head_0.len(), bytes1_head_0.len());
    debug_assert_eq!(bytes0_head_1.len(), bytes1_head_1.len());

    // Handle the tails. Swap the remaining parts such that bytes0_* refers to the
    // part with the longer LimbType region.
    let (bytes0_limbs, bytes0_tail, bytes1_limbs, bytes1_tail) =
        if bytes1_limbs.len() <= bytes0_limbs.len() {
            (bytes0_limbs, bytes0_tail, bytes1_limbs, bytes1_tail)
        } else {
            (bytes1_limbs, bytes1_tail, bytes0_limbs, bytes0_tail)
        };
    debug_assert!(bytes1_limbs.len() <= bytes0_limbs.len());
    // bytes1_tail_0 corresponds to the tail part of bytes0_limbs,
    // bytes1_tail_1 to bytes0_tail.
    let bytes0_tail_1 = bytes0_tail;
    let (bytes0_limbs, bytes0_limbs_tail) = bytes0_limbs.split_at(bytes1_limbs.len());
    let bytes0_tail_0 = cmpa::limb_slice_as_bytes(bytes0_limbs_tail);
    let (bytes1_tail_0, bytes1_tail_1) = bytes1_tail.split_at(bytes0_tail_0.len());
    debug_assert_eq!(bytes0_tail_0.len(), bytes1_tail_0.len());
    debug_assert_eq!(bytes0_tail_1.len(), bytes1_tail_1.len());

    let mut all_eq = _ct_bytes_eq(bytes0_head_0, bytes1_head_0);
    all_eq &= _ct_bytes_eq(bytes0_head_1, bytes1_head_1);
    let mut any_neq: cmpa::LimbType = 0;
    for pair in bytes0_limbs.iter().zip(bytes1_limbs.iter()) {
        any_neq |= pair.0 ^ pair.1;
    }
    all_eq &= cmpa::ct_eq_l_l(any_neq, 0);
    all_eq &= _ct_bytes_eq(bytes0_tail_0, bytes1_tail_0);
    all_eq &= _ct_bytes_eq(bytes0_tail_1, bytes1_tail_1);
    all_eq
}

#[test]
fn test_ct_bytes_eq() {
    let mut bytes0 = [0u8; 32 + mem::size_of::<cmpa::LimbType>() - 1];
    let mut bytes1 = [0u8; 32 + mem::size_of::<cmpa::LimbType>() - 1];
    for i in 0..mem::size_of::<cmpa::LimbType>() - 1 {
        for j in 0..mem::size_of::<cmpa::LimbType>() - 1 {
            let bytes0 = &mut bytes0[i..i + 32];
            let bytes1 = &mut bytes1[j..j + 32];
            bytes0.fill(0xcc);
            bytes1.fill(0xcc);
            assert_ne!(ct_bytes_eq(bytes0, bytes1).unwrap(), 0);

            for k in 0..32 {
                bytes0.fill(0xcc);
                bytes1.fill(0xcc);
                bytes0[k] = 0x77;
                assert_eq!(ct_bytes_eq(bytes0, bytes1).unwrap(), 0);

                bytes0.fill(0xcc);
                bytes1.fill(0xcc);
                bytes1[k] = 0x77;
                assert_eq!(ct_bytes_eq(bytes0, bytes1).unwrap(), 0);
            }
        }
    }
}
