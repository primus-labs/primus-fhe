mod cmux;
mod cmux_k;
mod external_product;
mod ternary;

use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;

#[allow(unused_imports)]
use crate::ntru::{NttNtru, NttNtruIter, NttNtruIterMut};

use super::Ngsw;

/// An NTT-domain [`Ngsw`] ciphertext.
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
pub struct NttNgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(NttNgsw);

impl_iters!(NttNgsw);
impl_iter_sub_structure!(NttNgsw, NttNtru);

impl_basic_operation_single_modulus!(NttNgsw);
impl_neg_single_modulus!(NttNgsw);
impl_mul_scalar_single_modulus!(NttNgsw);
impl_mul_factor_single_modulus!(NttNgsw);
impl_ntt_polynomial_mul!(NttNgsw);
impl_ntt_monomial!(NttNgsw);

impl_ntt!(Ngsw, NttNgsw);
impl_intt!(NttNgsw, Ngsw);
