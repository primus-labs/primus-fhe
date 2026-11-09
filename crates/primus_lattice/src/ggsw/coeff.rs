use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

#[allow(unused_imports)]
use crate::glev::{Glev, GlevIter, GlevIterMut};

/// Represents a ciphertext in the General-GSW homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`Glev`] with same parameter, `k` is the dimension.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct Ggsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(Ggsw);

impl_iters!(Ggsw);
impl_iter_sub_structure!(Ggsw, Glev);

impl_basic_operation_single_modulus!(Ggsw);
impl_neg_single_modulus!(Ggsw);
impl_mul_scalar_single_modulus!(Ggsw);
impl_mul_factor_single_modulus!(Ggsw);
impl_monomial_single_modulus!(Ggsw);
impl_gadget_diagonal_single_modulus!(Ggsw, Polynomial);
