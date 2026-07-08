use itertools::izip;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::DcrtTable;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

use crate::glwe::{CrtGlweIter, CrtGlweIterMut};

use super::DcrtGlev;

/// A representation of Module Learning with Errors (MLWE) ciphertexts with respect to different base,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::glwe::CrtGlwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct CrtGlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(CrtGlev<S>);
impl_bytes_conversion!(CrtGlev<S>);
impl_zero!(CrtGlev<S>);
impl_iters!(CrtGlev);
impl_iter_sub_structure!(CrtGlev<S>, CrtGlwe);
impl_basic_operation_multiple_modulus!(CrtGlev<S>);
impl_crt_ntt!(CrtGlev<S>, DcrtGlev);
