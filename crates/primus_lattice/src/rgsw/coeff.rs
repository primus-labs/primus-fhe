use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

use crate::rlev::{RlevIter, RlevIterMut};

use super::NttRgsw;

/// Represents a ciphertext in the Ring-GSW (Ring Learning With Errors) homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`crate::rlev::Rlev`] with same parameter, `k` is the dimension.
#[derive(Clone)]
pub struct Rgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(Rgsw<S>);
impl_bytes_conversion!(Rgsw<S>);
impl_zero!(Rgsw<S>);
impl_iters!(Rgsw);
impl_iter_sub_structure!(Rgsw<S>, Rlev);
impl_basic_operation_single_modulus!(Rgsw<S>);
impl_ntt!(Rgsw<S>, NttRgsw);
