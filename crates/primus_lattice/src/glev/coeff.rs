use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

use crate::glwe::{GlweIter, GlweIterMut};

use super::NttGlev;

/// A representation of Module Learning with Errors (MLWE) ciphertexts with respect to different base,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::glwe::Glwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct Glev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(Glev<S>);
impl_bytes_conversion!(Glev<S>);
impl_zero!(Glev<S>);
impl_iters!(Glev);
impl_iter_sub_structure!(Glev<S>, Glwe);
impl_basic_operation_single_modulus!(Glev<S>);
impl_ntt!(Glev<S>, NttGlev);
