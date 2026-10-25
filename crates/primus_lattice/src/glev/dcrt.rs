mod external_product;

use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

#[allow(unused_imports)]
use crate::glwe::{DcrtGlwe, DcrtGlweIter, DcrtGlweIterMut};

use super::CrtGlev;

/// A representation of Module Learning with Errors (MLWE) ciphertexts at different levels of one gadget basis,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`DcrtGlwe`] with same parameter, `d` is the decompose length.
///
/// Arithmetic preserves every gadget level and its layout. Operands must use
/// matching ciphertext dimensions, gadget bases, level order, ordered RNS bases,
/// and key semantics. Scalar and factor multiplication applies the same RNS
/// scalar to every level and ciphertext component.
/// Same-domain polynomial multiplication likewise applies one DCRT polynomial
/// to every component and preserves the gadget type; it does not decompose an
/// input or accumulate across gadget levels as an external product does.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Each polynomial contains consecutive modulus blocks in one fixed RNS
/// base order, with the same polynomial length for every modulus.
/// Stored values must use the matching NTT table, modulus, and evaluation
/// order; a representation wrapper alone does not perform a transform.
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct DcrtGlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(DcrtGlev);

impl_iters!(DcrtGlev);
impl_iter_sub_structure!(DcrtGlev, DcrtGlwe);

impl_basic_operation_multiple_modulus!(DcrtGlev);
impl_neg_multiple_modulus!(DcrtGlev);
impl_mul_scalar_multiple_modulus!(DcrtGlev);
impl_mul_factor_multiple_modulus!(DcrtGlev);
impl_dcrt_polynomial_mul!(DcrtGlev);

impl_crt_ntt!(CrtGlev, DcrtGlev);
impl_crt_intt!(DcrtGlev, CrtGlev);
