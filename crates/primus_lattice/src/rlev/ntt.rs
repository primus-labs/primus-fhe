use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

use crate::rlwe::{NttRlweIter, NttRlweIterMut};

use super::Rlev;

/// A representation of Ring Learning with Errors (RLWE) ciphertexts with respect to different base,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::rlwe::NttRlwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct NttRlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(NttRlev<S>);
impl_bytes_conversion!(NttRlev<S>);
impl_zero!(NttRlev<S>);
impl_iters!(NttRlev);
impl_iter_sub_structure!(NttRlev<S>, NttRlwe);
impl_basic_operation_single_modulus!(NttRlev<S>);
impl_intt!(NttRlev<S>, Rlev);
