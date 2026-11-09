use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

#[allow(unused_imports)]
use crate::ntru::{Ntru, NtruIter, NtruIterMut};

/// A gadget-decomposed NTRU ciphertext in the coefficient domain.
///
/// For gadget scalars `v_0, ..., v_{L-1}`, an encryption of `beta` is
/// `(NTRU_f[v_i * beta])_{i in [L]}`.
///
/// ## Layout
///
/// ```text
/// |--ntru_level_0--| ... |--ntru_level_{L-1}--|
/// ```
///
/// Each level contains one coefficient-domain [`Ntru`] polynomial.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct Nlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(Nlev);

impl_iters!(Nlev);
impl_iter_sub_structure!(Nlev, Ntru);

impl_basic_operation_single_modulus!(Nlev);
impl_neg_single_modulus!(Nlev);
impl_mul_scalar_single_modulus!(Nlev);
impl_mul_factor_single_modulus!(Nlev);
impl_monomial_single_modulus!(Nlev);
