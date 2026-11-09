use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

#[allow(unused_imports)]
use crate::ntru::{Ntru, NtruIter, NtruIterMut};

/// A GSW-style NTRU ciphertext in the coefficient domain.
///
/// For gadget scalars `v_0, ..., v_{L-1}`, an encryption of `beta` is
/// `NLEV_f[f * beta]`, whose level `i` is
/// `NTRU_f[v_i * f * beta] = g_i / f + v_i * beta`, where `f` is the
/// invertible secret polynomial and `g_i` is that level's noise polynomial.
///
/// Although this has the same flat layout as an NLev ciphertext, it is a
/// distinct type because the encrypted phase and valid products differ.
///
/// ## Layout
///
/// ```text
/// |--ntru_level_0--| ... |--ntru_level_{L-1}--|
/// ```
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct Ngsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(Ngsw);

impl_iters!(Ngsw);
impl_iter_sub_structure!(Ngsw, Ntru);

impl_basic_operation_single_modulus!(Ngsw);
impl_neg_single_modulus!(Ngsw);
impl_mul_scalar_single_modulus!(Ngsw);
impl_mul_factor_single_modulus!(Ngsw);
impl_monomial_single_modulus!(Ngsw);
