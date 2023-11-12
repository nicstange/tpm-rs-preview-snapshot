// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use crate::interface;
use crate::utils::{self, cfg_zeroize};
use alloc::vec::Vec;
use cmpa::{self, MpBigEndianUIntByteSlice, MpMutUInt as _, MpUIntCommon as _};

mod weierstrass_arithmetic_impl;

pub struct CurveFieldOps {
    p: cmpa::MpBigEndianUIntByteSlice<'static>,
    mg_neg_p0_inv_mod_l: cmpa::LimbType,
    mg_radix2_mod_p: Vec<cmpa::LimbType>,
}

impl CurveFieldOps {
    fn try_new(p: cmpa::MpBigEndianUIntByteSlice<'static>) -> Result<Self, interface::TpmErr> {
        let mut mg_radix2_mod_p = utils::try_alloc_vec::<cmpa::LimbType>(
            cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p.len()),
        )?;

        cmpa::ct_montgomery_radix2_mod_n_mp(
            &mut cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut mg_radix2_mod_p),
            &p,
        )
        .unwrap();
        let mg_neg_p0_inv_mod_l =
            cmpa::ct_montgomery_neg_n0_inv_mod_l_mp(&p).map_err(|_| tpm_err_internal!())?;
        Ok(Self {
            p,
            mg_radix2_mod_p,
            mg_neg_p0_inv_mod_l,
        })
    }

    pub fn get_p(&self) -> &cmpa::MpBigEndianUIntByteSlice {
        &self.p
    }

    fn convert_from_mg_form(&self, element: &mut cmpa::MpMutNativeEndianUIntLimbsSlice) {
        debug_assert!(self.p.len_is_compatible_with(element.len()));
        debug_assert_ne!(cmpa::ct_lt_mp_mp(element, &self.p).unwrap(), 0);
        cmpa::ct_montgomery_redc_mp(element, &self.p, self.mg_neg_p0_inv_mod_l).unwrap();
    }

    fn _convert_to_mg_form<ET: cmpa::MpUIntCommon>(
        &self,
        mg_result: &mut cmpa::MpMutNativeEndianUIntLimbsSlice,
        element: &ET,
    ) {
        debug_assert_ne!(cmpa::ct_lt_mp_mp(element, &self.p).unwrap(), 0);
        debug_assert!(self.p.len_is_compatible_with(mg_result.len()));

        cmpa::ct_to_montgomery_form_mp(
            mg_result,
            element,
            &self.p,
            self.mg_neg_p0_inv_mod_l,
            &self.get_mg_radix2_mod_p(),
        )
        .unwrap();
    }

    fn convert_to_mg_form<ET: cmpa::MpUIntCommon>(
        &self,
        element: &ET,
    ) -> Result<Vec<cmpa::LimbType>, interface::TpmErr> {
        let mut mg_element_buf = utils::try_alloc_vec::<cmpa::LimbType>(
            cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(self.p.len()),
        )?;
        let mut mg_element = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut mg_element_buf);
        self._convert_to_mg_form(&mut mg_element, element);
        Ok(mg_element_buf)
    }

    fn mg_identity(&self) -> Result<Vec<cmpa::LimbType>, interface::TpmErr> {
        let mut mg_identity_buf = utils::try_alloc_vec::<cmpa::LimbType>(
            cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(self.p.len()),
        )?;
        let mut mg_identity =
            cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut mg_identity_buf);
        mg_identity.copy_from(&self.get_mg_radix2_mod_p());
        cmpa::ct_montgomery_redc_mp(&mut mg_identity, &self.p, self.mg_neg_p0_inv_mod_l).unwrap();
        Ok(mg_identity_buf)
    }

    fn get_mg_radix2_mod_p(&self) -> cmpa::MpNativeEndianUIntLimbsSlice {
        cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.mg_radix2_mod_p)
    }

    pub fn add<T1: cmpa::MpUIntCommon>(
        &self,
        mg_op0: &mut cmpa::MpMutNativeEndianUIntLimbsSlice,
        mg_op1: &T1,
    ) {
        cmpa::ct_add_mod_mp_mp(mg_op0, mg_op1, &self.p).unwrap();
    }

    pub fn sub<T1: cmpa::MpUIntCommon>(
        &self,
        mg_op0: &mut cmpa::MpMutNativeEndianUIntLimbsSlice,
        mg_op1: &T1,
    ) {
        cmpa::ct_sub_mod_mp_mp(mg_op0, mg_op1, &self.p).unwrap();
    }

    pub fn mul<T0: cmpa::MpUIntCommon, T1: cmpa::MpUIntCommon>(
        &self,
        mg_result: &mut cmpa::MpMutNativeEndianUIntLimbsSlice,
        mg_op0: &T0,
        mg_op1: &T1,
    ) {
        cmpa::ct_montgomery_mul_mod_mp_mp(
            mg_result,
            mg_op0,
            mg_op1,
            &self.p,
            self.mg_neg_p0_inv_mod_l,
        )
        .unwrap();
    }
}

pub struct AffinePointMontgomeryForm {
    mg_x: cfg_zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    mg_y: cfg_zeroize::Zeroizing<Vec<cmpa::LimbType>>,
}

impl AffinePointMontgomeryForm {
    pub fn _try_from_plain_coordinates(
        x: &cmpa::MpBigEndianUIntByteSlice,
        y: &cmpa::MpBigEndianUIntByteSlice,
        field_ops: &CurveFieldOps,
    ) -> Result<Self, interface::TpmErr> {
        let mg_x = field_ops.convert_to_mg_form(x)?;
        let mg_x = cfg_zeroize::Zeroizing::from(mg_x);
        let mg_y = field_ops.convert_to_mg_form(y)?;
        let mg_y = cfg_zeroize::Zeroizing::from(mg_y);
        Ok(Self { mg_x, mg_y })
    }

    pub fn try_from_plain_coordinates(
        x: &cmpa::MpBigEndianUIntByteSlice,
        y: &cmpa::MpBigEndianUIntByteSlice,
        field_ops: &CurveFieldOps,
    ) -> Result<Self, interface::TpmErr> {
        if !x.len_is_compatible_with(field_ops.p.len())
            || !y.len_is_compatible_with(field_ops.p.len())
            || cmpa::ct_geq_mp_mp(x, &field_ops.p).unwrap() != 0
            || cmpa::ct_geq_mp_mp(y, &field_ops.p).unwrap() != 0
        {
            return Err(tpm_err_rc!(NO_RESULT));
        }
        Self::_try_from_plain_coordinates(x, y, field_ops)
    }

    pub fn into_plain_coordinates(
        mut self,
        result_x: &mut cmpa::MpMutBigEndianUIntByteSlice,
        result_y: Option<&mut cmpa::MpMutBigEndianUIntByteSlice>,
        field_ops: &CurveFieldOps,
    ) {
        debug_assert!(field_ops.p.len_is_compatible_with(result_x.len()));
        let mut src_x = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut self.mg_x);
        field_ops.convert_from_mg_form(&mut src_x);
        result_x.copy_from(&src_x);
        if let Some(result_y) = result_y {
            debug_assert!(field_ops.p.len_is_compatible_with(result_y.len()));
            let mut src_y = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut self.mg_y);
            field_ops.convert_from_mg_form(&mut src_y);
            result_y.copy_from(&src_y);
        }
    }

    pub fn to_plain_coordinates(
        &self,
        result_x: &mut cmpa::MpMutBigEndianUIntByteSlice,
        result_y: Option<&mut cmpa::MpMutBigEndianUIntByteSlice>,
        field_ops: &CurveFieldOps,
    ) -> Result<(), interface::TpmErr> {
        debug_assert!(field_ops.p.len_is_compatible_with(result_x.len()));
        let mut scratch = utils::try_alloc_zeroizing_vec::<cmpa::LimbType>(
            cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(field_ops.p.len()),
        )?;
        let mut scratch = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch);
        let (mg_x, mg_y) = self.get_mg_coordinates();
        scratch.copy_from(&mg_x);
        field_ops.convert_from_mg_form(&mut scratch);
        result_x.copy_from(&scratch);
        if let Some(result_y) = result_y {
            debug_assert!(field_ops.p.len_is_compatible_with(result_y.len()));
            scratch.copy_from(&mg_y);
            field_ops.convert_from_mg_form(&mut scratch);
            result_y.copy_from(&scratch);
        }
        Ok(())
    }

    pub fn into_projective(
        self,
        field_ops: &CurveFieldOps,
    ) -> Result<ProjectivePoint, interface::TpmErr> {
        let mg_z = cfg_zeroize::Zeroizing::from(field_ops.mg_identity()?);
        Ok(ProjectivePoint {
            mg_x: self.mg_x,
            mg_y: self.mg_y,
            mg_z,
        })
    }

    fn get_mg_coordinates(
        &self,
    ) -> (
        cmpa::MpNativeEndianUIntLimbsSlice,
        cmpa::MpNativeEndianUIntLimbsSlice,
    ) {
        (
            cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.mg_x),
            cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.mg_y),
        )
    }
}

impl cfg_zeroize::ZeroizeOnDrop for AffinePointMontgomeryForm {}

#[derive(Debug)]
pub enum ProjectivePointIntoAffineError {
    PointIsIdentity,
}

pub struct ProjectivePoint {
    mg_x: cfg_zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    mg_y: cfg_zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    mg_z: cfg_zeroize::Zeroizing<Vec<cmpa::LimbType>>,
}

impl ProjectivePoint {
    fn try_new_identity(field_ops: &CurveFieldOps) -> Result<Self, interface::TpmErr> {
        let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(field_ops.p.len());
        let mg_x_buf = utils::try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
        let mg_y_buf = field_ops.mg_identity()?;
        let mg_z_buf = utils::try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
        Ok(Self {
            mg_x: mg_x_buf,
            mg_y: cfg_zeroize::Zeroizing::from(mg_y_buf),
            mg_z: mg_z_buf,
        })
    }

    fn try_new(p_len: usize) -> Result<Self, interface::TpmErr> {
        let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p_len);
        let mg_x_buf = utils::try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
        let mg_y_buf = utils::try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
        let mg_z_buf = utils::try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
        Ok(Self {
            mg_x: mg_x_buf,
            mg_y: mg_y_buf,
            mg_z: mg_z_buf,
        })
    }

    fn get_mg_coordinates(
        &self,
    ) -> (
        cmpa::MpNativeEndianUIntLimbsSlice,
        cmpa::MpNativeEndianUIntLimbsSlice,
        cmpa::MpNativeEndianUIntLimbsSlice,
    ) {
        (
            cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.mg_x),
            cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.mg_y),
            cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.mg_z),
        )
    }

    fn get_mg_coordinates_mut(
        &mut self,
    ) -> (
        cmpa::MpMutNativeEndianUIntLimbsSlice,
        cmpa::MpMutNativeEndianUIntLimbsSlice,
        cmpa::MpMutNativeEndianUIntLimbsSlice,
    ) {
        (
            cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut self.mg_x),
            cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut self.mg_y),
            cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut self.mg_z),
        )
    }

    fn copy_from(&mut self, src: &ProjectivePoint) {
        let (mut mg_x, mut mg_y, mut mg_z) = self.get_mg_coordinates_mut();
        let (src_mg_x, src_mg_y, src_mg_z) = src.get_mg_coordinates();
        mg_x.copy_from(&src_mg_x);
        mg_y.copy_from(&src_mg_y);
        mg_z.copy_from(&src_mg_z);
    }

    fn copy_from_cond(&mut self, src: &ProjectivePoint, cond: cmpa::LimbChoice) {
        let (mut mg_x, mut mg_y, mut mg_z) = self.get_mg_coordinates_mut();
        let (src_mg_x, src_mg_y, src_mg_z) = src.get_mg_coordinates();
        mg_x.copy_from_cond(&src_mg_x, cond);
        mg_y.copy_from_cond(&src_mg_y, cond);
        mg_z.copy_from_cond(&src_mg_z, cond);
    }

    pub fn into_affine(
        mut self,
        field_ops: &CurveFieldOps,
        scratch: Option<&mut CurveOpsScratch>,
    ) -> Result<Result<AffinePointMontgomeryForm, ProjectivePointIntoAffineError>, interface::TpmErr>
    {
        let mut scratch0: cfg_zeroize::Zeroizing<Vec<cmpa::LimbType>> =
            cfg_zeroize::Zeroizing::from(Vec::new());
        let mut scratch1: cfg_zeroize::Zeroizing<Vec<cmpa::LimbType>> =
            cfg_zeroize::Zeroizing::from(Vec::new());
        let mut scratch2: cfg_zeroize::Zeroizing<Vec<cmpa::LimbType>> =
            cfg_zeroize::Zeroizing::from(Vec::new());
        let (scratch0, scratch1, scratch2) = if let Some(scratch) = scratch {
            (
                &mut scratch.scratch.scratch0,
                &mut scratch.scratch.scratch1,
                &mut scratch.scratch.scratch2,
            )
        } else {
            let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(field_ops.p.len());
            for s in [&mut scratch0, &mut scratch1, &mut scratch2].iter_mut() {
                **s = utils::try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
            }
            (&mut scratch0, &mut scratch1, &mut scratch2)
        };

        // Redc z back from Montgomery form.
        let mut z = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut self.mg_z);
        field_ops.convert_from_mg_form(&mut z);

        // Invert z modulo p.
        let mut z_inv = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch2);
        match cmpa::ct_inv_mod_odd_mp_mp(&mut z_inv, &mut z, &field_ops.p, [scratch0, scratch1]) {
            Ok(()) => (),
            Err(e) => match e {
                cmpa::CtInvModOddMpMpError::OperandsNotCoprime => {
                    return Ok(Err(ProjectivePointIntoAffineError::PointIsIdentity));
                }
                _ => unreachable!(),
            },
        };
        // And bring z_inv back into Montgomery form.
        let mut mg_z_inv = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch0);
        field_ops._convert_to_mg_form(&mut mg_z_inv, &z_inv);

        // Divide x and y by z.
        let Self {
            mg_x: mg_x_buf,
            mg_y: mg_y_buf,
            mg_z: mg_z_buf,
        } = self;
        let mg_x = cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&mg_x_buf);
        let mg_y = cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&mg_y_buf);
        // Recycle self.mg_z_buf for resulting x component.
        let mut affine_mg_x_buf = mg_z_buf;
        let mut affine_mg_x =
            cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut affine_mg_x_buf);
        field_ops.mul(&mut affine_mg_x, &mg_x, &mg_z_inv);
        // Recycle self.mg_x_buf for resulting y component.
        let mut affine_mg_y_buf = mg_x_buf;
        let mut affine_mg_y =
            cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut affine_mg_y_buf);
        field_ops.mul(&mut affine_mg_y, &mg_y, &mg_z_inv);

        Ok(Ok(AffinePointMontgomeryForm {
            mg_x: affine_mg_x_buf,
            mg_y: affine_mg_y_buf,
        }))
    }

    #[allow(clippy::type_complexity)]
    pub fn into_affine_plain_coordinates(
        mut self,
        result_x: &mut cmpa::MpMutBigEndianUIntByteSlice,
        result_y: Option<&mut cmpa::MpMutBigEndianUIntByteSlice>,
        field_ops: &CurveFieldOps,
        scratch: Option<&mut CurveOpsScratch>,
    ) -> Result<Result<(), ProjectivePointIntoAffineError>, interface::TpmErr> {
        let mut scratch0: cfg_zeroize::Zeroizing<Vec<cmpa::LimbType>> =
            cfg_zeroize::Zeroizing::from(Vec::new());
        let mut scratch1: cfg_zeroize::Zeroizing<Vec<cmpa::LimbType>> =
            cfg_zeroize::Zeroizing::from(Vec::new());
        let mut scratch2: cfg_zeroize::Zeroizing<Vec<cmpa::LimbType>> =
            cfg_zeroize::Zeroizing::from(Vec::new());
        let (scratch0, scratch1, scratch2) = if let Some(scratch) = scratch {
            (
                &mut scratch.scratch.scratch0,
                &mut scratch.scratch.scratch1,
                &mut scratch.scratch.scratch2,
            )
        } else {
            let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(field_ops.p.len());
            for s in [&mut scratch0, &mut scratch1, &mut scratch2].iter_mut() {
                **s = utils::try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
            }
            (&mut scratch0, &mut scratch1, &mut scratch2)
        };

        // Redc z back from Montgomery form.
        let (_, _, mut z) = self.get_mg_coordinates_mut();
        cmpa::ct_montgomery_redc_mp(&mut z, &field_ops.p, field_ops.mg_neg_p0_inv_mod_l).unwrap();

        // Invert z modulo p.
        let mut z_inv = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch2);
        match cmpa::ct_inv_mod_odd_mp_mp(&mut z_inv, &mut z, &field_ops.p, [scratch0, scratch1]) {
            Ok(()) => (),
            Err(e) => match e {
                cmpa::CtInvModOddMpMpError::OperandsNotCoprime => {
                    return Ok(Err(ProjectivePointIntoAffineError::PointIsIdentity));
                }
                _ => unreachable!(),
            },
        };

        // Divide x and y by z. Note that the Montgomery multiplication removes the
        // final remaining Montgomery radix factor still present in mg_x / mg_y.
        // That is, the multiplication brings the result implicitly back into
        // plain form.
        let (mg_x, mg_y, _) = self.get_mg_coordinates();
        cmpa::ct_montgomery_mul_mod_mp_mp(
            result_x,
            &mg_x,
            &z_inv,
            &field_ops.p,
            field_ops.mg_neg_p0_inv_mod_l,
        )
        .unwrap();
        if let Some(result_y) = result_y {
            cmpa::ct_montgomery_mul_mod_mp_mp(
                result_y,
                &mg_y,
                &z_inv,
                &field_ops.p,
                field_ops.mg_neg_p0_inv_mod_l,
            )
            .unwrap();
        }

        Ok(Ok(()))
    }
}

impl cfg_zeroize::ZeroizeOnDrop for ProjectivePoint {}

#[cfg(feature = "ecc_nist_p192")]
const NIST_P192_P: [u8; 24] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<24>("fffffffffffffffffffffffffffffffeffffffffffffffff");
#[cfg(feature = "ecc_nist_p192")]
const NIST_P192_N: [u8; 24] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<24>("ffffffffffffffffffffffff99def836146bc9b1b4d22831");
#[cfg(feature = "ecc_nist_p192")]
const NIST_P192_A: [u8; 24] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<24>("fffffffffffffffffffffffffffffffefffffffffffffffc");
#[cfg(feature = "ecc_nist_p192")]
const NIST_P192_B: [u8; 24] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<24>("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1");
#[cfg(feature = "ecc_nist_p192")]
const NIST_P192_G_X: [u8; 24] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<24>("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012");
#[cfg(feature = "ecc_nist_p192")]
const NIST_P192_G_Y: [u8; 24] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<24>("07192b95ffc8da78631011ed6b24cdd573f977a11e794811");

#[cfg(feature = "ecc_nist_p224")]
const NIST_P224_P: [u8; 28] = cmpa::hexstr::bytes_from_hexstr_cnst::<28>(
    "ffffffffffffffffffffffffffffffff000000000000000000000001",
);
#[cfg(feature = "ecc_nist_p224")]
const NIST_P224_N: [u8; 28] = cmpa::hexstr::bytes_from_hexstr_cnst::<28>(
    "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
);
#[cfg(feature = "ecc_nist_p224")]
const NIST_P224_A: [u8; 28] = cmpa::hexstr::bytes_from_hexstr_cnst::<28>(
    "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
);
#[cfg(feature = "ecc_nist_p224")]
const NIST_P224_B: [u8; 28] = cmpa::hexstr::bytes_from_hexstr_cnst::<28>(
    "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
);
#[cfg(feature = "ecc_nist_p224")]
const NIST_P224_G_X: [u8; 28] = cmpa::hexstr::bytes_from_hexstr_cnst::<28>(
    "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
);
#[cfg(feature = "ecc_nist_p224")]
const NIST_P224_G_Y: [u8; 28] = cmpa::hexstr::bytes_from_hexstr_cnst::<28>(
    "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
);

#[cfg(feature = "ecc_nist_p256")]
const NIST_P256_P: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
);
#[cfg(feature = "ecc_nist_p256")]
const NIST_P256_N: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
);
#[cfg(feature = "ecc_nist_p256")]
const NIST_P256_A: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
);
#[cfg(feature = "ecc_nist_p256")]
const NIST_P256_B: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
);
#[cfg(feature = "ecc_nist_p256")]
const NIST_P256_G_X: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
);
#[cfg(feature = "ecc_nist_p256")]
const NIST_P256_G_Y: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
);

#[cfg(feature = "ecc_nist_p384")]
const NIST_P384_P: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
     ffffffff0000000000000000ffffffff",
);
#[cfg(feature = "ecc_nist_p384")]
const NIST_P384_N: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
     581a0db248b0a77aecec196accc52973",
);
#[cfg(feature = "ecc_nist_p384")]
const NIST_P384_A: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
     ffffffff0000000000000000fffffffc",
);
#[cfg(feature = "ecc_nist_p384")]
const NIST_P384_B: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a\
     c656398d8a2ed19d2a85c8edd3ec2aef",
);
#[cfg(feature = "ecc_nist_p384")]
const NIST_P384_G_X: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
     5502f25dbf55296c3a545e3872760ab7",
);
#[cfg(feature = "ecc_nist_p384")]
const NIST_P384_G_Y: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
     0a60b1ce1d7e819d7a431d7c90ea0e5f",
);

#[cfg(feature = "ecc_nist_p521")]
const NIST_P521_P: [u8; 66] = cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
     ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
     ffff",
);
#[cfg(feature = "ecc_nist_p521")]
const NIST_P521_N: [u8; 66] = cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
     fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138\
     6409",
);
#[cfg(feature = "ecc_nist_p521")]
const NIST_P521_A: [u8; 66] = cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
     ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
     fffc",
);
#[cfg(feature = "ecc_nist_p521")]
const NIST_P521_B: [u8; 66] = cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
    "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1\
     09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b50\
     3f00",
);
#[cfg(feature = "ecc_nist_p521")]
const NIST_P521_G_X: [u8; 66] = cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
    "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d\
     3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5\
     bd66",
);
#[cfg(feature = "ecc_nist_p521")]
const NIST_P521_G_Y: [u8; 66] = cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
    "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e\
     662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd1\
     6650",
);

#[cfg(feature = "ecc_bn_p256")]
const BN_P256_P: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "fffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33013",
);
#[cfg(feature = "ecc_bn_p256")]
const BN_P256_N: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "fffffffffffcf0cd46e5f25eee71a49e0cdc65fb1299921af62d536cd10b500d",
);
#[cfg(feature = "ecc_bn_p256")]
const BN_P256_A: [u8; 0] = cmpa::hexstr::bytes_from_hexstr_cnst::<0>("");
#[cfg(feature = "ecc_bn_p256")]
const BN_P256_B: [u8; 1] = cmpa::hexstr::bytes_from_hexstr_cnst::<1>("03");
#[cfg(feature = "ecc_bn_p256")]
const BN_P256_G_X: [u8; 1] = cmpa::hexstr::bytes_from_hexstr_cnst::<1>("01");
#[cfg(feature = "ecc_bn_p256")]
const BN_P256_G_Y: [u8; 1] = cmpa::hexstr::bytes_from_hexstr_cnst::<1>("02");

#[cfg(feature = "ecc_bn_p638")]
const BN_P638_P: [u8; 80] = cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
    "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52f\
         fffdd0e00008de55c00086520021e55bfffff51ffff4eb800000004c80015acd\
         ffffffffffffece00000000000000067",
);
#[cfg(feature = "ecc_bn_p638")]
const BN_P638_N: [u8; 80] = cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
    "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52f\
         fffdd0e00008de55600086550021e555fffff54ffff4eac000000049800154d9\
         ffffffffffffeda00000000000000061",
);
#[cfg(feature = "ecc_bn_p638")]
const BN_P638_A: [u8; 0] = cmpa::hexstr::bytes_from_hexstr_cnst::<0>("");
#[cfg(feature = "ecc_bn_p638")]
const BN_P638_B: [u8; 2] = cmpa::hexstr::bytes_from_hexstr_cnst::<2>("0101");
#[cfg(feature = "ecc_bn_p638")]
const BN_P638_G_X: [u8; 80] = cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
    "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52f\
         fffdd0e00008de55c00086520021e55bfffff51ffff4eb800000004c80015acd\
         ffffffffffffece00000000000000066",
);
#[cfg(feature = "ecc_bn_p638")]
const BN_P638_G_Y: [u8; 1] = cmpa::hexstr::bytes_from_hexstr_cnst::<1>("10");

#[cfg(feature = "ecc_bp_p256_r1")]
const BP_P256_R1_P: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
);
#[cfg(feature = "ecc_bp_p256_r1")]
const BP_P256_R1_N: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
);
#[cfg(feature = "ecc_bp_p256_r1")]
const BP_P256_R1_A: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
);
#[cfg(feature = "ecc_bp_p256_r1")]
const BP_P256_R1_B: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
);
#[cfg(feature = "ecc_bp_p256_r1")]
const BP_P256_R1_G_X: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
);
#[cfg(feature = "ecc_bp_p256_r1")]
const BP_P256_R1_G_Y: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
);

#[cfg(feature = "ecc_bp_p384_r1")]
const BP_P384_R1_P: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123\
     acd3a729901d1a71874700133107ec53",
);
#[cfg(feature = "ecc_bp_p384_r1")]
const BP_P384_R1_N: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7\
     cf3ab6af6b7fc3103b883202e9046565",
);
#[cfg(feature = "ecc_bp_p384_r1")]
const BP_P384_R1_A: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f\
     8aa5814a503ad4eb04a8c7dd22ce2826",
);
#[cfg(feature = "ecc_bp_p384_r1")]
const BP_P384_R1_B: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d5\
     7cb4390295dbc9943ab78696fa504c11",
);
#[cfg(feature = "ecc_bp_p384_r1")]
const BP_P384_R1_G_X: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8\
     e826e03436d646aaef87b2e247d4af1e",
);
#[cfg(feature = "ecc_bp_p384_r1")]
const BP_P384_R1_G_Y: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff9912928\
     0e4646217791811142820341263c5315",
);

#[cfg(feature = "ecc_bp_p512_r1")]
const BP_P512_R1_P: [u8; 64] = cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
    "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330871\
     7d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
);
#[cfg(feature = "ecc_bp_p512_r1")]
const BP_P512_R1_N: [u8; 64] = cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
    "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870\
     553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
);
#[cfg(feature = "ecc_bp_p512_r1")]
const BP_P512_R1_A: [u8; 64] = cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
    "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc\
     2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
);
#[cfg(feature = "ecc_bp_p512_r1")]
const BP_P512_R1_B: [u8; 64] = cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
    "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a7\
     2bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
);
#[cfg(feature = "ecc_bp_p512_r1")]
const BP_P512_R1_G_X: [u8; 64] = cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
    "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098e\
     ff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
);
#[cfg(feature = "ecc_bp_p512_r1")]
const BP_P512_R1_G_Y: [u8; 64] = cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
    "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111\
     b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
);

#[cfg(feature = "ecc_sm2_p256")]
const SM2_P256_P: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
);
#[cfg(feature = "ecc_sm2_p256")]
const SM2_P256_N: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
);
#[cfg(feature = "ecc_sm2_p256")]
const SM2_P256_A: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc",
);
#[cfg(feature = "ecc_sm2_p256")]
const SM2_P256_B: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93",
);
#[cfg(feature = "ecc_sm2_p256")]
const SM2_P256_G_X: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
);
#[cfg(feature = "ecc_sm2_p256")]
const SM2_P256_G_Y: [u8; 32] = cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
    "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
);

pub struct Curve {
    curve_id: interface::TpmEccCurve,
    p: &'static [u8],
    n: &'static [u8],
    cofactor_log2: u8,
    nbits: usize,
}

impl Curve {
    pub fn new(curve_id: interface::TpmEccCurve) -> Result<Self, interface::TpmErr> {
        let curve = match curve_id {
            interface::TpmEccCurve::None => return Err(tpm_err_rc!(NO_RESULT)),
            #[cfg(feature = "ecc_nist_p192")]
            interface::TpmEccCurve::NistP192 => Self {
                curve_id,
                p: &NIST_P192_P,
                n: &NIST_P192_N,
                cofactor_log2: 0,
                nbits: 192,
            },
            #[cfg(feature = "ecc_nist_p224")]
            interface::TpmEccCurve::NistP224 => Self {
                curve_id,
                p: &NIST_P224_P,
                n: &NIST_P224_N,
                cofactor_log2: 0,
                nbits: 224,
            },
            #[cfg(feature = "ecc_nist_p256")]
            interface::TpmEccCurve::NistP256 => Self {
                curve_id,
                p: &NIST_P256_P,
                n: &NIST_P256_N,
                cofactor_log2: 0,
                nbits: 256,
            },
            #[cfg(feature = "ecc_nist_p384")]
            interface::TpmEccCurve::NistP384 => Self {
                curve_id,
                p: &NIST_P384_P,
                n: &NIST_P384_N,
                cofactor_log2: 0,
                nbits: 384,
            },
            #[cfg(feature = "ecc_nist_p521")]
            interface::TpmEccCurve::NistP521 => Self {
                curve_id,
                p: &NIST_P521_P,
                n: &NIST_P521_N,
                cofactor_log2: 0,
                nbits: 521,
            },
            #[cfg(feature = "ecc_bn_p256")]
            interface::TpmEccCurve::BnP256 => Self {
                curve_id,
                p: &BN_P256_P,
                n: &BN_P256_N,
                cofactor_log2: 0,
                nbits: 256,
            },
            #[cfg(feature = "ecc_bn_p638")]
            interface::TpmEccCurve::BnP638 => Self {
                curve_id,
                p: &BN_P638_P,
                n: &BN_P638_N,
                cofactor_log2: 0,
                nbits: 638,
            },
            #[cfg(feature = "ecc_bp_p256_r1")]
            interface::TpmEccCurve::BpP256R1 => Self {
                curve_id,
                p: &BP_P256_R1_P,
                n: &BP_P256_R1_N,
                cofactor_log2: 0,
                nbits: 256,
            },
            #[cfg(feature = "ecc_bp_p384_r1")]
            interface::TpmEccCurve::BpP384R1 => Self {
                curve_id,
                p: &BP_P384_R1_P,
                n: &BP_P384_R1_N,
                cofactor_log2: 0,
                nbits: 384,
            },
            #[cfg(feature = "ecc_bp_p512_r1")]
            interface::TpmEccCurve::BpP512R1 => Self {
                curve_id,
                p: &BP_P512_R1_P,
                n: &BP_P512_R1_N,
                cofactor_log2: 0,
                nbits: 512,
            },
            #[cfg(feature = "ecc_sm2_p256")]
            interface::TpmEccCurve::Sm2P256 => Self {
                curve_id,
                p: &SM2_P256_P,
                n: &SM2_P256_N,
                cofactor_log2: 0,
                nbits: 256,
            },
        };
        Ok(curve)
    }

    pub fn get_curve_id(&self) -> interface::TpmEccCurve {
        self.curve_id
    }

    pub fn get_p(&self) -> cmpa::MpBigEndianUIntByteSlice<'static> {
        cmpa::MpBigEndianUIntByteSlice::from_bytes(self.p)
    }

    pub fn get_p_len(&self) -> usize {
        self.p.len()
    }

    pub fn get_order(&self) -> cmpa::MpBigEndianUIntByteSlice<'static> {
        cmpa::MpBigEndianUIntByteSlice::from_bytes(self.n)
    }

    pub fn validate_scalar<ST: cmpa::MpUIntCommon>(
        &self,
        scalar: &ST,
    ) -> Result<(), interface::TpmErr> {
        let order = self.get_order();
        if scalar.len_is_compatible_with(self.get_p_len())
            && cmpa::ct_geq_mp_mp(scalar, &order).unwrap() == 0
        {
            Ok(())
        } else {
            Err(tpm_err_rc!(NO_RESULT))
        }
    }

    pub fn get_cofactor_log2(&self) -> u8 {
        self.cofactor_log2
    }

    pub fn get_nbits(&self) -> usize {
        self.nbits
    }

    pub fn field_ops(&self) -> Result<CurveFieldOps, interface::TpmErr> {
        CurveFieldOps::try_new(self.get_p())
    }

    pub fn curve_ops(&self) -> Result<CurveOps, interface::TpmErr> {
        CurveOps::try_new(self)
    }

    fn get_curve_coefficients(
        &self,
    ) -> (
        MpBigEndianUIntByteSlice<'static>,
        MpBigEndianUIntByteSlice<'static>,
    ) {
        let (a, b): (&[u8], &[u8]) = match self.curve_id {
            interface::TpmEccCurve::None => unreachable!(),
            #[cfg(feature = "ecc_nist_p192")]
            interface::TpmEccCurve::NistP192 => (&NIST_P192_A, &NIST_P192_B),
            #[cfg(feature = "ecc_nist_p224")]
            interface::TpmEccCurve::NistP224 => (&NIST_P224_A, &NIST_P224_B),
            #[cfg(feature = "ecc_nist_p256")]
            interface::TpmEccCurve::NistP256 => (&NIST_P256_A, &NIST_P256_B),
            #[cfg(feature = "ecc_nist_p384")]
            interface::TpmEccCurve::NistP384 => (&NIST_P384_A, &NIST_P384_B),
            #[cfg(feature = "ecc_nist_p521")]
            interface::TpmEccCurve::NistP521 => (&NIST_P521_A, &NIST_P521_B),
            #[cfg(feature = "ecc_bn_p256")]
            interface::TpmEccCurve::BnP256 => (&BN_P256_A, &BN_P256_B),
            #[cfg(feature = "ecc_bn_p638")]
            interface::TpmEccCurve::BnP638 => (&BN_P638_A, &BN_P638_B),
            #[cfg(feature = "ecc_bp_p256_r1")]
            interface::TpmEccCurve::BpP256R1 => (&BP_P256_R1_A, &BP_P256_R1_B),
            #[cfg(feature = "ecc_bp_p384_r1")]
            interface::TpmEccCurve::BpP384R1 => (&BP_P384_R1_A, &BP_P384_R1_B),
            #[cfg(feature = "ecc_bp_p512_r1")]
            interface::TpmEccCurve::BpP512R1 => (&BP_P512_R1_A, &BP_P512_R1_B),
            #[cfg(feature = "ecc_sm2_p256")]
            interface::TpmEccCurve::Sm2P256 => (&SM2_P256_A, &SM2_P256_B),
        };
        (
            cmpa::MpBigEndianUIntByteSlice::from_bytes(a),
            cmpa::MpBigEndianUIntByteSlice::from_bytes(b),
        )
    }

    fn get_generator_coordinates(
        &self,
    ) -> (
        MpBigEndianUIntByteSlice<'static>,
        MpBigEndianUIntByteSlice<'static>,
    ) {
        let (g_x, g_y): (&[u8], &[u8]) = match self.curve_id {
            interface::TpmEccCurve::None => unreachable!(),
            #[cfg(feature = "ecc_nist_p192")]
            interface::TpmEccCurve::NistP192 => (&NIST_P192_G_X, &NIST_P192_G_Y),
            #[cfg(feature = "ecc_nist_p224")]
            interface::TpmEccCurve::NistP224 => (&NIST_P224_G_X, &NIST_P224_G_Y),
            #[cfg(feature = "ecc_nist_p256")]
            interface::TpmEccCurve::NistP256 => (&NIST_P256_G_X, &NIST_P256_G_Y),
            #[cfg(feature = "ecc_nist_p384")]
            interface::TpmEccCurve::NistP384 => (&NIST_P384_G_X, &NIST_P384_G_Y),
            #[cfg(feature = "ecc_nist_p521")]
            interface::TpmEccCurve::NistP521 => (&NIST_P521_G_X, &NIST_P521_G_Y),
            #[cfg(feature = "ecc_bn_p256")]
            interface::TpmEccCurve::BnP256 => (&BN_P256_G_X, &BN_P256_G_Y),
            #[cfg(feature = "ecc_bn_p638")]
            interface::TpmEccCurve::BnP638 => (&BN_P638_G_X, &BN_P638_G_Y),
            #[cfg(feature = "ecc_bp_p256_r1")]
            interface::TpmEccCurve::BpP256R1 => (&BP_P256_R1_G_X, &BP_P256_R1_G_Y),
            #[cfg(feature = "ecc_bp_p384_r1")]
            interface::TpmEccCurve::BpP384R1 => (&BP_P384_R1_G_X, &BP_P384_R1_G_Y),
            #[cfg(feature = "ecc_bp_p512_r1")]
            interface::TpmEccCurve::BpP512R1 => (&BP_P512_R1_G_X, &BP_P512_R1_G_Y),
            #[cfg(feature = "ecc_sm2_p256")]
            interface::TpmEccCurve::Sm2P256 => (&SM2_P256_G_X, &SM2_P256_G_Y),
        };
        (
            cmpa::MpBigEndianUIntByteSlice::from_bytes(g_x),
            cmpa::MpBigEndianUIntByteSlice::from_bytes(g_y),
        )
    }
}

pub struct CurveOpsScratch {
    scratch: weierstrass_arithmetic_impl::WeierstrassCurveOpsScratch,
}

impl CurveOpsScratch {
    fn try_new(p_len: usize) -> Result<Self, interface::TpmErr> {
        let scratch = weierstrass_arithmetic_impl::WeierstrassCurveOpsScratch::try_new(p_len)?;
        Ok(Self { scratch })
    }
}

pub struct CurveOps<'a> {
    curve: &'a Curve,
    field_ops: CurveFieldOps,
    ops: weierstrass_arithmetic_impl::WeierstrassCurveOps,
}

impl<'a> CurveOps<'a> {
    fn try_new(curve: &'a Curve) -> Result<Self, interface::TpmErr> {
        let field_ops = curve.field_ops()?;
        let (a, b) = curve.get_curve_coefficients();
        let ops = weierstrass_arithmetic_impl::WeierstrassCurveOps::try_new(&field_ops, &a, &b)?;
        Ok(Self {
            curve,
            field_ops,
            ops,
        })
    }

    pub fn try_alloc_scratch(&self) -> Result<CurveOpsScratch, interface::TpmErr> {
        CurveOpsScratch::try_new(self.curve.get_p_len())
    }

    pub fn generator(&self) -> Result<AffinePointMontgomeryForm, interface::TpmErr> {
        let (g_x, g_y) = self.curve.get_generator_coordinates();
        AffinePointMontgomeryForm::_try_from_plain_coordinates(&g_x, &g_y, &self.field_ops)
    }

    pub fn get_curve(&self) -> &Curve {
        self.curve
    }

    pub fn get_field_ops(&self) -> &CurveFieldOps {
        &self.field_ops
    }

    fn _point_scalar_mul<ST: cmpa::MpUIntCommon>(
        &self,
        scalar: &ST,
        point: &AffinePointMontgomeryForm,
        scratch: &mut CurveOpsScratch,
    ) -> Result<ProjectivePoint, interface::TpmErr> {
        // The scalar is always strictly less than the order, except for the
        // point_is_in_generator_subgroup() check.
        debug_assert!(scalar.len_is_compatible_with((self.curve.nbits + 7) / 8));
        debug_assert!(cmpa::ct_gt_mp_mp(scalar, &self.curve.get_order()).unwrap() == 0);
        self.ops.point_scalar_mul(
            scalar,
            self.curve.nbits.min(8 * scalar.len()),
            point,
            &self.field_ops,
            &mut scratch.scratch,
        )
    }

    pub fn point_scalar_mul<ST: cmpa::MpUIntCommon>(
        &self,
        scalar: &ST,
        point: &AffinePointMontgomeryForm,
        scratch: &mut CurveOpsScratch,
    ) -> Result<ProjectivePoint, interface::TpmErr> {
        self.curve.validate_scalar(scalar)?;
        self._point_scalar_mul(scalar, point, scratch)
    }

    pub fn point_add(
        &self,
        op0: &ProjectivePoint,
        op1: &ProjectivePoint,
        scratch: &mut CurveOpsScratch,
    ) -> Result<ProjectivePoint, interface::TpmErr> {
        self.ops
            .point_add(op0, op1, &self.field_ops, &mut scratch.scratch)
    }

    pub fn point_double_repeated(
        &self,
        op0: ProjectivePoint,
        repeat_count: u8,
        scratch: &mut CurveOpsScratch,
    ) -> Result<ProjectivePoint, interface::TpmErr> {
        self.ops
            .point_double_repeated(op0, repeat_count, &self.field_ops, &mut scratch.scratch)
    }

    pub fn point_is_on_curve(
        &self,
        point: &AffinePointMontgomeryForm,
        scratch: Option<&mut CurveOpsScratch>,
    ) -> Result<bool, interface::TpmErr> {
        self.ops
            .point_is_on_curve(point, &self.field_ops, scratch.map(|s| &mut s.scratch))
    }

    pub fn point_is_in_generator_subgroup(
        &self,
        point: &AffinePointMontgomeryForm,
        scratch: &mut CurveOpsScratch,
    ) -> Result<bool, interface::TpmErr> {
        if !self.point_is_on_curve(point, Some(scratch))? {
            return Ok(false);
        }

        // C.f. NIST SP800-65Ar3, section 5.6.2.3.3 ("ECC Full Public-Key Validation
        // Routine") or NIST SP800-186, section D.1.1.2. ("Full Public Key
        // Validation"). If the cofactor equals one, this test could be skipped.
        // But NIST says otherwise, so do it.
        let identity = self._point_scalar_mul(&self.curve.get_order(), point, scratch)?;
        Ok(cmpa::ct_is_zero_mp(&identity.get_mg_coordinates().2).unwrap() != 0)
    }
}

#[cfg(test)]
fn test_point_scalar_mul_common(curve_id: interface::TpmEccCurve) {
    use cmpa::MpMutUInt as _;

    let curve = Curve::new(curve_id).unwrap();
    let curve_ops = curve.curve_ops().unwrap();
    let mut scratch = curve_ops.try_alloc_scratch().unwrap();
    let g = curve_ops.generator().unwrap();

    // Multiplication of generator with a zero scalar.
    let mut scalar_buf = utils::try_alloc_vec::<u8>(curve.get_order().len()).unwrap();
    let result = curve_ops
        .point_scalar_mul(
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&scalar_buf),
            &g,
            &mut scratch,
        )
        .unwrap();
    assert!(matches!(
        result
            .into_affine(curve_ops.get_field_ops(), Some(&mut scratch))
            .unwrap(),
        Err(ProjectivePointIntoAffineError::PointIsIdentity)
    ));

    // Multiplication of generator with a one.
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.set_to_u8(1);
    let result = curve_ops
        .point_scalar_mul(
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&scalar_buf),
            &g,
            &mut scratch,
        )
        .unwrap();
    // Go the ProjectivePoint -> AffinePointMontgomeryForm -> plain coordinates
    // route
    let result = result
        .into_affine(curve_ops.get_field_ops(), Some(&mut scratch))
        .unwrap()
        .unwrap();
    let mut result_x_buf = utils::try_alloc_vec::<u8>(curve.get_p().len()).unwrap();
    let mut result_x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut result_x_buf);
    let mut result_y_buf = utils::try_alloc_vec::<u8>(curve.get_p().len()).unwrap();
    let mut result_y = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut result_y_buf);
    result.into_plain_coordinates(
        &mut result_x,
        Some(&mut result_y),
        curve_ops.get_field_ops(),
    );
    let (g_x, g_y) = curve.get_generator_coordinates();
    assert_ne!(cmpa::ct_eq_mp_mp(&result_x, &g_x).unwrap(), 0);
    assert_ne!(cmpa::ct_eq_mp_mp(&result_y, &g_y).unwrap(), 0);

    // Multiplication with a scalar equal to the group order minus one. The result
    // should equal the generator again, with the y component possibly negated.
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.copy_from(&curve.get_order());
    cmpa::ct_sub_mp_l(&mut scalar, 1);
    let result = curve_ops
        .point_scalar_mul(
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&scalar_buf),
            &g,
            &mut scratch,
        )
        .unwrap();
    // Go the direct ProjectivePoint -> plain coordinates route this time.
    let mut result_x_buf = utils::try_alloc_vec::<u8>(curve.get_p().len()).unwrap();
    let mut result_x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut result_x_buf);
    let mut result_y_buf = utils::try_alloc_vec::<u8>(curve.get_p().len()).unwrap();
    let mut result_y = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut result_y_buf);
    result
        .into_affine_plain_coordinates(
            &mut result_x,
            Some(&mut result_y),
            curve_ops.get_field_ops(),
            Some(&mut scratch),
        )
        .unwrap()
        .unwrap();
    assert_ne!(cmpa::ct_eq_mp_mp(&result_x, &g_x).unwrap(), 0);
    let mut neg_result_y_buf = utils::try_alloc_vec::<u8>(curve.get_p().len()).unwrap();
    let mut neg_result_y = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut neg_result_y_buf);
    neg_result_y.copy_from(&curve.get_p());
    cmpa::ct_sub_mp_mp(&mut neg_result_y, &result_y);
    assert!(
        cmpa::ct_eq_mp_mp(&result_y, &g_y).unwrap() != 0
            || cmpa::ct_eq_mp_mp(&neg_result_y, &g_y).unwrap() != 0
    );
}

#[cfg(feature = "ecc_nist_p192")]
#[test]
fn test_point_scalar_mul_nist_p192() {
    test_point_scalar_mul_common(interface::TpmEccCurve::NistP192)
}

#[cfg(feature = "ecc_nist_p224")]
#[test]
fn test_point_scalar_mul_nist_p224() {
    test_point_scalar_mul_common(interface::TpmEccCurve::NistP224)
}

#[cfg(feature = "ecc_nist_p256")]
#[test]
fn test_point_scalar_mul_nist_p256() {
    test_point_scalar_mul_common(interface::TpmEccCurve::NistP256)
}

#[cfg(feature = "ecc_nist_p384")]
#[test]
fn test_point_scalar_mul_nist_p384() {
    test_point_scalar_mul_common(interface::TpmEccCurve::NistP384)
}

#[cfg(feature = "ecc_nist_p521")]
#[test]
fn test_point_scalar_mul_nist_p521() {
    test_point_scalar_mul_common(interface::TpmEccCurve::NistP521)
}

#[cfg(feature = "ecc_bn_p256")]
#[test]
fn test_point_scalar_mul_bn_p256() {
    test_point_scalar_mul_common(interface::TpmEccCurve::BnP256)
}

#[cfg(feature = "ecc_bn_p638")]
#[test]
fn test_point_scalar_mul_bn_p638() {
    test_point_scalar_mul_common(interface::TpmEccCurve::BnP638)
}

#[cfg(feature = "ecc_bp_p256_r1")]
#[test]
fn test_point_scalar_mul_bp_p256_r1() {
    test_point_scalar_mul_common(interface::TpmEccCurve::BpP256R1)
}

#[cfg(feature = "ecc_bp_p384_r1")]
#[test]
fn test_point_scalar_mul_bp_p384_r1() {
    test_point_scalar_mul_common(interface::TpmEccCurve::BpP384R1)
}

#[cfg(feature = "ecc_bp_p512_r1")]
#[test]
fn test_point_scalar_mul_bp_p512_r1() {
    test_point_scalar_mul_common(interface::TpmEccCurve::BpP512R1)
}

#[cfg(feature = "ecc_sm2_p256")]
#[test]
fn test_point_scalar_mul_sm2_p256() {
    test_point_scalar_mul_common(interface::TpmEccCurve::Sm2P256)
}

#[cfg(test)]
fn test_point_add_common(curve_id: interface::TpmEccCurve) {
    use cmpa::MpMutUInt as _;

    // Multiply the generator by three, add it independently two times to itself and
    // verify that the respective results match.
    let curve = Curve::new(curve_id).unwrap();
    let curve_ops = curve.curve_ops().unwrap();
    let mut scratch = curve_ops.try_alloc_scratch().unwrap();
    let g = curve_ops.generator().unwrap();
    assert!(curve_ops.point_is_on_curve(&g, Some(&mut scratch)).unwrap());

    // Multiply generator by three.
    let mut scalar_buf = utils::try_alloc_vec::<u8>(curve.get_order().len()).unwrap();
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.set_to_u8(3);
    let expected = curve_ops
        .point_scalar_mul(&scalar, &g, &mut scratch)
        .unwrap();
    let expected = expected
        .into_affine(curve_ops.get_field_ops(), Some(&mut scratch))
        .unwrap()
        .unwrap();

    // Now add it two times to itself.
    scalar.set_to_u8(1);
    let g = g.into_projective(curve_ops.get_field_ops()).unwrap();
    let two_g = curve_ops.point_add(&g, &g, &mut scratch).unwrap();
    let result = curve_ops.point_add(&two_g, &g, &mut scratch).unwrap();
    let result = result
        .into_affine(curve_ops.get_field_ops(), Some(&mut scratch))
        .unwrap()
        .unwrap();

    let (expected_x, expected_y) = expected.get_mg_coordinates();
    let (result_x, result_y) = result.get_mg_coordinates();
    assert_ne!(cmpa::ct_eq_mp_mp(&result_x, &expected_x).unwrap(), 0);
    assert_ne!(cmpa::ct_eq_mp_mp(&result_y, &expected_y).unwrap(), 0);
}

#[cfg(feature = "ecc_nist_p192")]
#[test]
fn test_point_add_nist_p192() {
    test_point_add_common(interface::TpmEccCurve::NistP192)
}

#[cfg(feature = "ecc_nist_p224")]
#[test]
fn test_point_add_nist_p224() {
    test_point_add_common(interface::TpmEccCurve::NistP224)
}

#[cfg(feature = "ecc_nist_p256")]
#[test]
fn test_point_add_nist_p256() {
    test_point_add_common(interface::TpmEccCurve::NistP256)
}

#[cfg(feature = "ecc_nist_p384")]
#[test]
fn test_point_add_nist_p384() {
    test_point_add_common(interface::TpmEccCurve::NistP384)
}

#[cfg(feature = "ecc_nist_p521")]
#[test]
fn test_point_add_nist_p521() {
    test_point_add_common(interface::TpmEccCurve::NistP521)
}

#[cfg(feature = "ecc_bn_p256")]
#[test]
fn test_point_add_bn_p256() {
    test_point_add_common(interface::TpmEccCurve::BnP256)
}

#[cfg(feature = "ecc_bn_p638")]
#[test]
fn test_point_add_bn_p638() {
    test_point_add_common(interface::TpmEccCurve::BnP638)
}

#[cfg(feature = "ecc_bp_p256_r1")]
#[test]
fn test_point_add_bp_p256_r1() {
    test_point_add_common(interface::TpmEccCurve::BpP256R1)
}

#[cfg(feature = "ecc_bp_p384_r1")]
#[test]
fn test_point_add_bp_p384_r1() {
    test_point_add_common(interface::TpmEccCurve::BpP384R1)
}

#[cfg(feature = "ecc_bp_p512_r1")]
#[test]
fn test_point_add_bp_p512_r1() {
    test_point_add_common(interface::TpmEccCurve::BpP512R1)
}

#[cfg(feature = "ecc_sm2_p256")]
#[test]
fn test_point_add_sm2_p256() {
    test_point_add_common(interface::TpmEccCurve::Sm2P256)
}

#[cfg(test)]
fn test_point_double_repeated_common(curve_id: interface::TpmEccCurve) {
    use cmpa::MpMutUInt as _;

    // Multiply the generator by four, double it independently twice and
    // verify that the respective results match.
    let curve = Curve::new(curve_id).unwrap();
    let curve_ops = curve.curve_ops().unwrap();
    let mut scratch = curve_ops.try_alloc_scratch().unwrap();
    let g = curve_ops.generator().unwrap();
    assert!(curve_ops.point_is_on_curve(&g, Some(&mut scratch)).unwrap());

    // Multiply generator by four.
    let mut scalar_buf = utils::try_alloc_vec::<u8>(curve.get_order().len()).unwrap();
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.set_to_u8(4);
    let expected = curve_ops
        .point_scalar_mul(&scalar, &g, &mut scratch)
        .unwrap();
    let expected = expected
        .into_affine(curve_ops.get_field_ops(), Some(&mut scratch))
        .unwrap()
        .unwrap();

    // Now double the generator twice.
    let g = g.into_projective(curve_ops.get_field_ops()).unwrap();
    let result = curve_ops.point_double_repeated(g, 2, &mut scratch).unwrap();
    let result = result
        .into_affine(curve_ops.get_field_ops(), Some(&mut scratch))
        .unwrap()
        .unwrap();

    let (expected_x, expected_y) = expected.get_mg_coordinates();
    let (result_x, result_y) = result.get_mg_coordinates();
    assert_ne!(cmpa::ct_eq_mp_mp(&result_x, &expected_x).unwrap(), 0);
    assert_ne!(cmpa::ct_eq_mp_mp(&result_y, &expected_y).unwrap(), 0);
}

#[cfg(feature = "ecc_nist_p192")]
#[test]
fn test_point_double_repeated_nist_p192() {
    test_point_double_repeated_common(interface::TpmEccCurve::NistP192)
}

#[cfg(feature = "ecc_nist_p224")]
#[test]
fn test_point_double_repeated_nist_p224() {
    test_point_double_repeated_common(interface::TpmEccCurve::NistP224)
}

#[cfg(feature = "ecc_nist_p256")]
#[test]
fn test_point_double_repeated_nist_p256() {
    test_point_double_repeated_common(interface::TpmEccCurve::NistP256)
}

#[cfg(feature = "ecc_nist_p384")]
#[test]
fn test_point_double_repeated_nist_p384() {
    test_point_double_repeated_common(interface::TpmEccCurve::NistP384)
}

#[cfg(feature = "ecc_nist_p521")]
#[test]
fn test_point_double_repeated_nist_p521() {
    test_point_double_repeated_common(interface::TpmEccCurve::NistP521)
}

#[cfg(feature = "ecc_bn_p256")]
#[test]
fn test_point_double_repeated_bn_p256() {
    test_point_double_repeated_common(interface::TpmEccCurve::BnP256)
}

#[cfg(feature = "ecc_bn_p638")]
#[test]
fn test_point_double_repeated_bn_p638() {
    test_point_double_repeated_common(interface::TpmEccCurve::BnP638)
}

#[cfg(feature = "ecc_bp_p256_r1")]
#[test]
fn test_point_double_repeated_bp_p256_r1() {
    test_point_double_repeated_common(interface::TpmEccCurve::BpP256R1)
}

#[cfg(feature = "ecc_bp_p384_r1")]
#[test]
fn test_point_double_repeated_bp_p384_r1() {
    test_point_double_repeated_common(interface::TpmEccCurve::BpP384R1)
}

#[cfg(feature = "ecc_bp_p512_r1")]
#[test]
fn test_point_double_repeated_bp_p512_r1() {
    test_point_double_repeated_common(interface::TpmEccCurve::BpP512R1)
}

#[cfg(feature = "ecc_sm2_p256")]
#[test]
fn test_point_double_repeated_sm2_p256() {
    test_point_double_repeated_common(interface::TpmEccCurve::Sm2P256)
}

#[cfg(test)]
fn test_point_is_on_curve_common(curve_id: interface::TpmEccCurve) {
    use cmpa::MpMutUInt as _;

    let curve = Curve::new(curve_id).unwrap();
    let curve_ops = curve.curve_ops().unwrap();
    let mut scratch = curve_ops.try_alloc_scratch().unwrap();
    let g = curve_ops.generator().unwrap();
    assert!(curve_ops.point_is_on_curve(&g, Some(&mut scratch)).unwrap());

    // Multiply generator by three and verify it's on the curve.
    let mut scalar_buf = utils::try_alloc_vec::<u8>(curve.get_order().len()).unwrap();
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.set_to_u8(3);
    let point = curve_ops
        .point_scalar_mul(&scalar, &g, &mut scratch)
        .unwrap();
    let mut point = point
        .into_affine(curve_ops.get_field_ops(), Some(&mut scratch))
        .unwrap()
        .unwrap();
    assert!(curve_ops
        .point_is_on_curve(&point, Some(&mut scratch))
        .unwrap());

    // Now mess with the point a bit and verify it's correctly reported as not being
    // on the curve anymore.
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.set_to_u8(1);
    curve_ops.get_field_ops().add(
        &mut cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut point.mg_x),
        &scalar,
    );
    assert!(!curve_ops
        .point_is_on_curve(&point, Some(&mut scratch))
        .unwrap());
}

#[cfg(feature = "ecc_nist_p192")]
#[test]
fn test_point_is_on_curve_nist_p192() {
    test_point_is_on_curve_common(interface::TpmEccCurve::NistP192)
}

#[cfg(feature = "ecc_nist_p224")]
#[test]
fn test_point_is_on_curve_nist_p224() {
    test_point_is_on_curve_common(interface::TpmEccCurve::NistP224)
}

#[cfg(feature = "ecc_nist_p256")]
#[test]
fn test_point_is_on_curve_nist_p256() {
    test_point_is_on_curve_common(interface::TpmEccCurve::NistP256)
}

#[cfg(feature = "ecc_nist_p384")]
#[test]
fn test_point_is_on_curve_nist_p384() {
    test_point_is_on_curve_common(interface::TpmEccCurve::NistP384)
}

#[cfg(feature = "ecc_nist_p521")]
#[test]
fn test_point_is_on_curve_nist_p521() {
    test_point_is_on_curve_common(interface::TpmEccCurve::NistP521)
}

#[cfg(feature = "ecc_bn_p256")]
#[test]
fn test_point_is_on_curve_bn_p256() {
    test_point_is_on_curve_common(interface::TpmEccCurve::BnP256)
}

#[cfg(feature = "ecc_bn_p638")]
#[test]
fn test_point_is_on_curve_bn_p638() {
    test_point_is_on_curve_common(interface::TpmEccCurve::BnP638)
}

#[cfg(feature = "ecc_bp_p256_r1")]
#[test]
fn test_point_is_on_curve_bp_p256_r1() {
    test_point_is_on_curve_common(interface::TpmEccCurve::BpP256R1)
}

#[cfg(feature = "ecc_bp_p384_r1")]
#[test]
fn test_point_is_on_curve_bp_p384_r1() {
    test_point_is_on_curve_common(interface::TpmEccCurve::BpP384R1)
}

#[cfg(feature = "ecc_bp_p512_r1")]
#[test]
fn test_point_is_on_curve_bp_p512_r1() {
    test_point_is_on_curve_common(interface::TpmEccCurve::BpP512R1)
}

#[cfg(feature = "ecc_sm2_p256")]
#[test]
fn test_point_is_on_curve_sm2_p256() {
    test_point_is_on_curve_common(interface::TpmEccCurve::Sm2P256)
}

#[cfg(test)]
fn test_point_is_in_generator_subgroup_common(curve_id: interface::TpmEccCurve) {
    use cmpa::MpMutUInt as _;

    let curve = Curve::new(curve_id).unwrap();
    let curve_ops = curve.curve_ops().unwrap();
    let mut scratch = curve_ops.try_alloc_scratch().unwrap();
    let g = curve_ops.generator().unwrap();
    assert!(curve_ops
        .point_is_in_generator_subgroup(&g, &mut scratch)
        .unwrap());

    // Multiply generator by three and verify it's in the generator's subgroup.
    let mut scalar_buf = utils::try_alloc_vec::<u8>(curve.get_order().len()).unwrap();
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.set_to_u8(3);
    let point = curve_ops
        .point_scalar_mul(&scalar, &g, &mut scratch)
        .unwrap();
    let mut point = point
        .into_affine(curve_ops.get_field_ops(), Some(&mut scratch))
        .unwrap()
        .unwrap();
    assert!(curve_ops
        .point_is_in_generator_subgroup(&point, &mut scratch)
        .unwrap());

    // Now mess with the point a bit and verify it's correctly reported as not being
    // on the curve anymore.
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.set_to_u8(1);
    curve_ops.get_field_ops().add(
        &mut cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut point.mg_x),
        &scalar,
    );
    assert!(!curve_ops
        .point_is_in_generator_subgroup(&point, &mut scratch)
        .unwrap());
}

#[cfg(feature = "ecc_nist_p192")]
#[test]
fn test_point_is_in_generator_subgroup_nist_p192() {
    test_point_is_in_generator_subgroup_common(interface::TpmEccCurve::NistP192)
}

#[cfg(feature = "ecc_nist_p224")]
#[test]
fn test_point_is_in_generator_subgroup_nist_p224() {
    test_point_is_in_generator_subgroup_common(interface::TpmEccCurve::NistP224)
}

#[cfg(feature = "ecc_nist_p256")]
#[test]
fn test_point_is_in_generator_subgroup_nist_p256() {
    test_point_is_in_generator_subgroup_common(interface::TpmEccCurve::NistP256)
}

#[cfg(feature = "ecc_nist_p384")]
#[test]
fn test_point_is_in_generator_subgroup_nist_p384() {
    test_point_is_in_generator_subgroup_common(interface::TpmEccCurve::NistP384)
}

#[cfg(feature = "ecc_nist_p521")]
#[test]
fn test_point_is_in_generator_subgroup_nist_p521() {
    test_point_is_in_generator_subgroup_common(interface::TpmEccCurve::NistP521)
}

#[cfg(feature = "ecc_bn_p256")]
#[test]
fn test_point_is_in_generator_subgroup_bn_p256() {
    test_point_is_in_generator_subgroup_common(interface::TpmEccCurve::BnP256)
}

#[cfg(feature = "ecc_bn_p638")]
#[test]
fn test_point_is_in_generator_subgroup_bn_p638() {
    test_point_is_in_generator_subgroup_common(interface::TpmEccCurve::BnP638)
}

#[cfg(feature = "ecc_bp_p256_r1")]
#[test]
fn test_point_is_in_generator_subgroup_bp_p256_r1() {
    test_point_is_in_generator_subgroup_common(interface::TpmEccCurve::BpP256R1)
}

#[cfg(feature = "ecc_bp_p384_r1")]
#[test]
fn test_point_is_in_generator_subgroup_bp_p384_r1() {
    test_point_is_in_generator_subgroup_common(interface::TpmEccCurve::BpP384R1)
}

#[cfg(feature = "ecc_bp_p512_r1")]
#[test]
fn test_point_is_in_generator_subgroup_bp_p512_r1() {
    test_point_is_in_generator_subgroup_common(interface::TpmEccCurve::BpP512R1)
}

#[cfg(feature = "ecc_sm2_p256")]
#[test]
fn test_point_is_in_generator_subgroup_sm2_p256() {
    test_point_is_in_generator_subgroup_common(interface::TpmEccCurve::Sm2P256)
}

#[cfg(test)]
macro_rules! cfg_select_curve_id {
    (($f:literal, $id:ident)) => {
        #[cfg(feature = $f)]
        return interface::TpmEccCurve::$id;
        #[cfg(not(feature = $f))]
        {
            "Force compile error for no ECC curve configured"
        }
    };
    (($f:literal, $id:ident), $(($f_more:literal, $id_more:ident)),+) => {
        #[cfg(feature = $f)]
        return interface::TpmEccCurve::$id;
        #[cfg(not(feature = $f))]
        {
            cfg_select_curve_id!($(($f_more, $id_more)),+)
        }
    };
}

#[cfg(test)]
pub fn test_curve_id() -> interface::TpmEccCurve {
    cfg_select_curve_id!(
        ("ecc_nist_p192", NistP192),
        ("ecc_nist_p224", NistP224),
        ("ecc_nist_p384", NistP384),
        ("ecc_nist_p512", NistP521),
        ("ecc_bn_p256", BnP256),
        ("ecc_bn_p638", BnP638),
        ("ecc_bp_p256_r1", BpP256R1),
        ("ecc_bp_p384_r1", BpP384R1),
        ("ecc_bp_p512_r1", BpP512R1),
        ("ecc_sm2_p256", Sm2P256)
    );
}
