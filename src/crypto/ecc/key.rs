extern crate alloc;
use super::{curve, gen_random_scalar_impl};
use crate::crypto::{ct_cmp, io_slices, rng};
use crate::interface;
use crate::utils::{self, cfg_zeroize};
use alloc::vec::Vec;
use cmpa::{self, MpMutUInt as _, MpUIntCommon as _};
use core::convert;

pub struct EccPublicKey {
    curve_id: interface::TpmEccCurve,
    point: curve::AffinePointMontgomeryForm,
}

impl EccPublicKey {
    pub fn get_curve_id(&self) -> interface::TpmEccCurve {
        self.curve_id
    }

    pub fn get_point(&self) -> &curve::AffinePointMontgomeryForm {
        &self.point
    }
}

impl<'a, 'b> convert::TryFrom<(&curve::CurveOps<'a>, &mut interface::TpmsEccPoint<'b>)>
    for EccPublicKey
{
    type Error = interface::TpmErr;

    fn try_from(
        value: (&curve::CurveOps<'a>, &mut interface::TpmsEccPoint<'b>),
    ) -> Result<Self, Self::Error> {
        // Load and validate the public key point.
        let (curve_ops, src_point) = value;
        let curve_id = curve_ops.get_curve().get_curve_id();
        src_point.stabilize()?;
        let interface::TpmsEccPoint { x: src_x, y: src_y } = &src_point;
        let point = curve::AffinePointMontgomeryForm::try_from_plain_coordinates(
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&src_x.buffer),
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&src_y.buffer),
            curve_ops.get_field_ops(),
        )?;

        let mut curve_ops_scratch = curve_ops.try_alloc_scratch()?;
        if !curve_ops.point_is_in_generator_subgroup(&point, &mut curve_ops_scratch)? {
            return Err(tpm_err_rc!(ECC_POINT));
        }

        Ok(Self { curve_id, point })
    }
}

impl convert::TryFrom<(&curve::CurveFieldOps, EccPublicKey)> for interface::TpmsEccPoint<'static> {
    type Error = interface::TpmErr;

    fn try_from(value: (&curve::CurveFieldOps, EccPublicKey)) -> Result<Self, Self::Error> {
        let (field_ops, pub_key) = value;
        let mut x_buf = utils::try_alloc_zeroizing_vec::<u8>(field_ops.get_p().len())?;
        let mut x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut x_buf);
        let mut y_buf = utils::try_alloc_zeroizing_vec::<u8>(field_ops.get_p().len())?;
        let mut y = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut y_buf);
        let EccPublicKey { curve_id: _, point } = pub_key;
        point.into_plain_coordinates(&mut x, Some(&mut y), field_ops);
        let x = interface::Tpm2bEccParameter {
            buffer: interface::TpmBuffer::Owned(
                #[allow(clippy::useless_conversion)]
                x_buf.into(),
            ),
        };
        let y = interface::Tpm2bEccParameter {
            #[allow(clippy::useless_conversion)]
            buffer: interface::TpmBuffer::Owned(
                #[allow(clippy::useless_conversion)]
                y_buf.into(),
            ),
        };
        Ok(Self { x, y })
    }
}

impl convert::TryFrom<(&curve::CurveFieldOps, &EccPublicKey)> for interface::TpmsEccPoint<'static> {
    type Error = interface::TpmErr;

    fn try_from(value: (&curve::CurveFieldOps, &EccPublicKey)) -> Result<Self, Self::Error> {
        let (field_ops, pub_key) = value;
        let mut x_buf = utils::try_alloc_zeroizing_vec::<u8>(field_ops.get_p().len())?;
        let mut x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut x_buf);
        let mut y_buf = utils::try_alloc_zeroizing_vec::<u8>(field_ops.get_p().len())?;
        let mut y = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut y_buf);
        pub_key
            .get_point()
            .to_plain_coordinates(&mut x, Some(&mut y), field_ops)?;
        let x = interface::Tpm2bEccParameter {
            buffer: interface::TpmBuffer::Owned(
                #[allow(clippy::useless_conversion)]
                x_buf.into(),
            ),
        };
        let y = interface::Tpm2bEccParameter {
            buffer: interface::TpmBuffer::Owned(
                #[allow(clippy::useless_conversion)]
                y_buf.into(),
            ),
        };
        Ok(Self { x, y })
    }
}

impl cfg_zeroize::ZeroizeOnDrop for EccPublicKey {}

pub struct EccPrivateKey {
    d: cfg_zeroize::Zeroizing<Vec<u8>>,
}

impl EccPrivateKey {
    pub fn get_d(&self) -> cmpa::MpBigEndianUIntByteSlice {
        cmpa::MpBigEndianUIntByteSlice::from_bytes(&self.d)
    }
}

impl cfg_zeroize::ZeroizeOnDrop for EccPrivateKey {}

pub struct EccKey {
    pub_key: EccPublicKey,
    priv_key: Option<EccPrivateKey>,
}

impl EccKey {
    pub fn generate(
        curve_ops: &curve::CurveOps,
        rng: &mut dyn rng::RngCore,
        additional_rng_generate_input: Option<&io_slices::IoSlices>,
    ) -> Result<Self, interface::TpmErr> {
        let curve = curve_ops.get_curve();
        let mut d = utils::try_alloc_zeroizing_vec::<u8>(curve.get_p_len())?;
        gen_random_scalar_impl::gen_random_scalar(
            &mut d,
            &curve.get_order(),
            curve.get_nbits(),
            rng,
            additional_rng_generate_input,
        )?;

        let g = curve_ops.generator()?;
        let mut curve_ops_scratch = curve_ops.try_alloc_scratch()?;
        let point = curve_ops.point_scalar_mul(
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&d),
            &g,
            &mut curve_ops_scratch,
        )?;
        let point =
            match point.into_affine(curve_ops.get_field_ops(), Some(&mut curve_ops_scratch))? {
                Ok(point) => point,
                Err(curve::ProjectivePointIntoAffineError::PointIsIdentity) => {
                    return Err(tpm_err_internal!());
                }
            };

        Ok(Self {
            pub_key: EccPublicKey {
                curve_id: curve.get_curve_id(),
                point,
            },
            priv_key: Some(EccPrivateKey { d }),
        })
    }

    pub fn pub_key(&self) -> &EccPublicKey {
        &self.pub_key
    }

    pub fn priv_key(&self) -> Option<&EccPrivateKey> {
        self.priv_key.as_ref()
    }

    pub fn take_public(self) -> EccPublicKey {
        self.pub_key
    }
}

impl cfg_zeroize::ZeroizeOnDrop for EccKey {}

impl<'a, 'b, 'c>
    convert::TryFrom<(
        &curve::CurveOps<'a>,
        &mut interface::TpmsEccPoint<'b>,
        Option<&mut interface::Tpm2bEccParameter<'c>>,
    )> for EccKey
{
    type Error = interface::TpmErr;

    fn try_from(
        value: (
            &curve::CurveOps<'a>,
            &mut interface::TpmsEccPoint<'b>,
            Option<&mut interface::Tpm2bEccParameter<'c>>,
        ),
    ) -> Result<Self, Self::Error> {
        let (curve_ops, src_point, src_d) = value;
        if let Some(src_d) = src_d {
            // With private key given. Validate it and regenerate the public key from it.
            // Verify that the externally provided public key matches the
            // regenerated one.
            let curve = curve_ops.get_curve();
            src_d.stabilize()?;
            let src_d = cmpa::MpBigEndianUIntByteSlice::from_bytes(&src_d.buffer);
            curve.validate_scalar(&src_d).map_err(|e| match e {
                interface::TpmErr::Rc(interface::TpmRc::NO_RESULT) => tpm_err_rc!(BINDING),
                e => e,
            })?;

            let mut d_buf = utils::try_alloc_zeroizing_vec::<u8>(curve.get_p_len())?;
            let mut d = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut d_buf);
            d.copy_from(&src_d);

            let g = curve_ops.generator()?;
            let mut curve_ops_scratch = curve_ops.try_alloc_scratch()?;
            let point = curve_ops.point_scalar_mul(&d, &g, &mut curve_ops_scratch)?;
            let point =
                match point.into_affine(curve_ops.get_field_ops(), Some(&mut curve_ops_scratch))? {
                    Ok(point) => point,
                    Err(curve::ProjectivePointIntoAffineError::PointIsIdentity) => {
                        return Err(tpm_err_rc!(BINDING));
                    }
                };
            drop(curve_ops_scratch);

            // And compare with the input public key. Don't stabilize -- it won't get used
            // further henceafter anyways and equality at some point in time is
            // good enough as far as this check here is concerned.
            let mut plain_x = utils::try_alloc_zeroizing_vec::<u8>(curve.get_p_len())?;
            let mut plain_y = utils::try_alloc_zeroizing_vec::<u8>(curve.get_p_len())?;
            point.to_plain_coordinates(
                &mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut plain_x),
                Some(&mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(
                    &mut plain_y,
                )),
                curve_ops.get_field_ops(),
            )?;

            if (ct_cmp::ct_bytes_eq(&plain_x, &src_point.x.buffer)
                & ct_cmp::ct_bytes_eq(&plain_y, &src_point.y.buffer))
            .unwrap()
                == 0
            {
                return Err(tpm_err_rc!(BINDING));
            }

            Ok(Self {
                pub_key: EccPublicKey {
                    curve_id: curve.get_curve_id(),
                    point,
                },
                priv_key: Some(EccPrivateKey { d: d_buf }),
            })
        } else {
            Ok(Self {
                pub_key: EccPublicKey::try_from((curve_ops, src_point))?,
                priv_key: None,
            })
        }
    }
}
