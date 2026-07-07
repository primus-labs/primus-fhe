use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

use crate::rlev::{NttRlevIter, NttRlevIterMut};

use super::Rgsw;

/// Represents a ciphertext in the Ring-GSW (Ring Learning With Errors) homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`crate::rlev::NttRlev`] with same parameter, `k` is the dimension.
#[derive(Clone)]
pub struct NttRgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(NttRgsw<S>);
impl_bytes_conversion!(NttRgsw<S>);
impl_zero!(NttRgsw<S>);
impl_iters!(NttRgsw);
impl_iter_sub_structure!(NttRgsw<S>, NttRlev);
impl_basic_operation_single_modulus!(NttRgsw<S>);
impl_intt!(NttRgsw<S>, Rgsw);
