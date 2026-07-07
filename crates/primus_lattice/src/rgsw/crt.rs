use itertools::izip;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::DcrtTable;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

use crate::rlev::{CrtRlevIter, CrtRlevIterMut};

use super::DcrtRgsw;

/// Represents a ciphertext in the Ring-GSW (Ring Learning With Errors) homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`crate::rlev::CrtRlev`] with same parameter, `k` is the dimension.
#[derive(Clone)]
pub struct CrtRgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(CrtRgsw<S>);
impl_bytes_conversion!(CrtRgsw<S>);
impl_zero!(CrtRgsw<S>);
impl_iters!(CrtRgsw);
impl_iter_sub_structure!(CrtRgsw<S>, CrtRlev);
impl_basic_operation_multiple_modulus!(CrtRgsw<S>);
impl_crt_ntt!(CrtRgsw<S>, DcrtRgsw);
