use itertools::izip;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::DcrtTable;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

use crate::rlwe::{DcrtRlweIter, DcrtRlweIterMut};

use super::CrtRlev;

/// A representation of Ring Learning with Errors (RLWE) ciphertexts with respect to different base,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::rlwe::DcrtRlwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct DcrtRlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(DcrtRlev<S>);
impl_bytes_conversion!(DcrtRlev<S>);
impl_zero!(DcrtRlev<S>);
impl_iters!(DcrtRlev);
impl_iter_sub_structure!(DcrtRlev<S>, DcrtRlwe);
impl_basic_operation_multiple_modulus!(DcrtRlev<S>);
impl_crt_intt!(DcrtRlev<S>, CrtRlev);
