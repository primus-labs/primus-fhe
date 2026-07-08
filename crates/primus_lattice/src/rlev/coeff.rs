use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

use crate::rlwe::{RlweIter, RlweIterMut};

use super::NttRlev;

/// A representation of Ring Learning with Errors (RLWE) ciphertexts with respect to different base,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::rlwe::Rlwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct Rlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(Rlev<S>);
impl_bytes_conversion!(Rlev<S>);
impl_zero!(Rlev<S>);
impl_iters!(Rlev);
impl_iter_sub_structure!(Rlev<S>, Rlwe);
impl_basic_operation_single_modulus!(Rlev<S>);
impl_ntt!(Rlev<S>, NttRlev);
