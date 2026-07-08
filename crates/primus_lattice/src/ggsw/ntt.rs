use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

use crate::glev::{NttGlevIter, NttGlevIterMut};

use super::Ggsw;

/// Represents a ciphertext in the General-GSW homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`crate::glev::NttGlev`] with same parameter, `k` is the dimension.
#[derive(Clone)]
pub struct NttGgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(NttGgsw<S>);
impl_bytes_conversion!(NttGgsw<S>);
impl_zero!(NttGgsw<S>);
impl_iters!(NttGgsw);
impl_iter_sub_structure!(NttGgsw<S>, NttGlev);
impl_basic_operation_single_modulus!(NttGgsw<S>);
impl_intt!(NttGgsw<S>, Ggsw);
