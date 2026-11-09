use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

#[allow(unused_imports)]
use crate::glwe::{Glwe, GlweIter, GlweIterMut};

/// A representation of Module Learning with Errors (MLWE) ciphertexts at different levels of one gadget basis,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`Glwe`] with same parameter, `d` is the decompose length.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct Glev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(Glev);

impl_iters!(Glev);
impl_iter_sub_structure!(Glev, Glwe);

impl_basic_operation_single_modulus!(Glev);
impl_neg_single_modulus!(Glev);
impl_mul_scalar_single_modulus!(Glev);
impl_mul_factor_single_modulus!(Glev);
impl_monomial_single_modulus!(Glev);
