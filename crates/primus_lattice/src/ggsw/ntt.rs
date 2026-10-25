mod cmux;
mod external_product;
mod ternary;

use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;

#[allow(unused_imports)]
use crate::glev::{NttGlev, NttGlevIter, NttGlevIterMut};

use super::Ggsw;

/// Represents a ciphertext in the General-GSW homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`NttGlev`] with same parameter, `k` is the dimension.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Stored values must use the matching NTT table, modulus, and evaluation
/// order; a representation wrapper alone does not perform a transform.
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct NttGgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(NttGgsw);

impl_iters!(NttGgsw);
impl_iter_sub_structure!(NttGgsw, NttGlev);

impl_basic_operation_single_modulus!(NttGgsw);
impl_neg_single_modulus!(NttGgsw);
impl_mul_scalar_single_modulus!(NttGgsw);
impl_mul_factor_single_modulus!(NttGgsw);
impl_gadget_diagonal_single_modulus!(NttGgsw, NttPolynomial);
impl_ntt_polynomial_mul!(NttGgsw);
impl_ntt_monomial!(NttGgsw);

impl_ntt!(Ggsw, NttGgsw);
impl_intt!(NttGgsw, Ggsw);
