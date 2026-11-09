use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

#[allow(unused_imports)]
use crate::glwe::{NttGlwe, NttGlweIter, NttGlweIterMut};

use super::Glev;
use crate::workspace::NttGlweExternalProductWorkspace;

/// A representation of Module Learning with Errors (MLWE) ciphertexts at different levels of one gadget basis,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`NttGlwe`] with same parameter, `d` is the decompose length.
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
pub struct NttGlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(NttGlev);

impl_iters!(NttGlev);
impl_iter_sub_structure!(NttGlev, NttGlwe);

impl_basic_operation_single_modulus!(NttGlev);
impl_neg_single_modulus!(NttGlev);
impl_mul_scalar_single_modulus!(NttGlev);
impl_mul_factor_single_modulus!(NttGlev);
impl_ntt_polynomial_mul!(NttGlev);
impl_ntt_monomial!(NttGlev);

impl_ntt!(Glev, NttGlev);
impl_intt!(NttGlev, Glev);

impl<T: FheUint> NttGlev<&[T]> {
    /// Multiplies a coefficient polynomial by this gadget, overwriting an NTT GLWE.
    ///
    /// Computes `sum_j D_j(input) * self[j]`. Output and decomposition scratch
    /// are initialized by the operation; no inverse NTT or allocation occurs.
    ///
    /// # Correctness
    ///
    /// For `size = workspace.size()`, input has exactly `N` coefficients,
    /// this gadget has `size.glev_len()` elements, and output has
    /// `size.glwe_len()` elements, where `N` is the bound polynomial length.
    /// Levels follow `basis.decomposer_iter()` order and use its level count.
    /// Input and key values are canonical residues. Basis, modulus and table
    /// must agree on the modulus; the table must have length `N` and use the
    /// gadget's evaluation order. Output uses that same NTT representation.
    pub fn polynomial_external_product_ntt_to<M, Table>(
        &self,
        input: Polynomial<&[T]>,
        mut output: NttGlwe<&mut [T]>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let size = workspace.size();
        let n = size.glwe_size().poly_length().get();
        debug_assert_eq!(output.as_ref().len(), size.glwe_len());
        debug_assert_eq!(input.as_ref().len(), n);
        debug_assert_eq!(self.as_ref().len(), size.glev_len());
        debug_assert_eq!(basis.level_count(), size.level_count());
        debug_assert_eq!(basis.modulus(), Some(modulus.value()));
        debug_assert_eq!(ntt.poly_length().get(), n);

        // A polynomial contributes one gadget row. Keep the established GGSW
        // schedule unchanged; both products use the same decomposition, NTT and
        // modular-MAC primitives without a per-component dispatch layer.
        let mut workspace = workspace.as_mut_with_accumulator(&mut output);
        workspace.ntt_accumulator.set_zero();
        basis.init_value_carry_slice_to(input.as_ref(), workspace.adjusted_poly, workspace.carries);
        for (decomposer, key) in basis
            .decomposer_iter()
            .zip(self.iter_ntt_glwe(size.glwe_len()))
        {
            decomposer.decompose_slice_to(
                workspace.adjusted_poly,
                workspace.decomposed_ntt,
                workspace.carries,
            );
            ntt.transform_slice(workspace.decomposed_ntt);
            workspace.ntt_accumulator.add_mul_ntt_polynomial_assign(
                &key,
                &NttPolynomial::new(&*workspace.decomposed_ntt),
                modulus,
            );
        }
    }
}
