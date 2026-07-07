use itertools::izip;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::DcrtTable;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

use crate::rlev::{DcrtRlevIter, DcrtRlevIterMut};

use super::CrtRgsw;

/// Represents a ciphertext in the Ring-GSW (Ring Learning With Errors) homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`crate::rlev::DcrtRlev`] with same parameter, `k` is the dimension.
#[derive(Clone)]
pub struct DcrtRgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(DcrtRgsw<S>);
impl_bytes_conversion!(DcrtRgsw<S>);
impl_zero!(DcrtRgsw<S>);
impl_iters!(DcrtRgsw);
impl_iter_sub_structure!(DcrtRgsw<S>, DcrtRlev);
impl_basic_operation_multiple_modulus!(DcrtRgsw<S>);
impl_crt_intt!(DcrtRgsw<S>, CrtRgsw);
