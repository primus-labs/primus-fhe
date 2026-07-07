use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

use crate::glwe::{NttGlweIter, NttGlweIterMut};

use super::Glev;

/// A representation of Module Learning with Errors (MLWE) ciphertexts with respect to different base,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::glwe::NttGlwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct NttGlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(NttGlev<S>);
impl_bytes_conversion!(NttGlev<S>);
impl_zero!(NttGlev<S>);
impl_iters!(NttGlev);
impl_iter_sub_structure!(NttGlev<S>, NttGlwe);
impl_basic_operation_single_modulus!(NttGlev<S>);
impl_intt!(NttGlev<S>, Glev);
