mod external_product;
mod external_product_sum;
mod lift;

use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;

#[allow(unused_imports)]
use crate::ntru::{NttNtru, NttNtruIter, NttNtruIterMut};

use super::Nlev;

/// An NTT-domain [`Nlev`] ciphertext.
///
/// The data is a flat list of NTT-domain NTRU polynomials, one per gadget
/// decomposition level.
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
pub struct NttNlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(NttNlev);

impl_iters!(NttNlev);
impl_iter_sub_structure!(NttNlev, NttNtru);

impl_basic_operation_single_modulus!(NttNlev);
impl_neg_single_modulus!(NttNlev);
impl_mul_scalar_single_modulus!(NttNlev);
impl_mul_factor_single_modulus!(NttNlev);
impl_ntt_polynomial_mul!(NttNlev);
impl_ntt_monomial!(NttNlev);

impl_ntt!(Nlev, NttNlev);
impl_intt!(NttNlev, Nlev);
