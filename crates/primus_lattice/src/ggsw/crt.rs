use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

#[allow(unused_imports)]
use crate::glev::{CrtGlev, CrtGlevIter, CrtGlevIterMut};

/// Represents a ciphertext in the General-GSW homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`CrtGlev`] with same parameter, `k` is the dimension.
///
/// Arithmetic preserves every gadget level and its layout. Operands must use
/// matching ciphertext dimensions, gadget bases, level order, ordered RNS bases,
/// and key semantics. Scalar and factor multiplication applies the same RNS
/// scalar to every level and ciphertext component.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Each polynomial contains consecutive modulus blocks in one fixed RNS
/// base order, with the same polynomial length for every modulus.
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct CrtGgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(CrtGgsw);

impl_iters!(CrtGgsw);
impl_iter_sub_structure!(CrtGgsw, CrtGlev);

impl_basic_operation_multiple_modulus!(CrtGgsw);
impl_neg_multiple_modulus!(CrtGgsw);
impl_mul_scalar_multiple_modulus!(CrtGgsw);
impl_mul_factor_multiple_modulus!(CrtGgsw);
impl_monomial_multiple_modulus!(CrtGgsw);
impl_gadget_diagonal_multiple_modulus!(CrtGgsw, CrtPolynomial);
