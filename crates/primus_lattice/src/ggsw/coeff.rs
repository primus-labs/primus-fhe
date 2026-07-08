use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

use crate::glev::{GlevIter, GlevIterMut};

use super::NttGgsw;

/// Represents a ciphertext in the General-GSW homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`crate::glev::Glev`] with same parameter, `k` is the dimension.
#[derive(Clone)]
pub struct Ggsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(Ggsw<S>);
impl_bytes_conversion!(Ggsw<S>);
impl_zero!(Ggsw<S>);
impl_iters!(Ggsw);
impl_iter_sub_structure!(Ggsw<S>, Glev);
impl_basic_operation_single_modulus!(Ggsw<S>);
impl_ntt!(Ggsw<S>, NttGgsw);
