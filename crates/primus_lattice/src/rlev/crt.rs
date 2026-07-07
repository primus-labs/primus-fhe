use itertools::izip;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::DcrtTable;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

use crate::rlwe::{CrtRlweIter, CrtRlweIterMut};

use super::DcrtRlev;

/// A representation of Ring Learning with Errors (RLWE) ciphertexts with respect to different base,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::rlwe::CrtRlwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct CrtRlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(CrtRlev<S>);
impl_bytes_conversion!(CrtRlev<S>);
impl_zero!(CrtRlev<S>);
impl_iters!(CrtRlev);
impl_iter_sub_structure!(CrtRlev<S>, CrtRlwe);
impl_basic_operation_multiple_modulus!(CrtRlev<S>);
impl_crt_ntt!(CrtRlev<S>, DcrtRlev);
