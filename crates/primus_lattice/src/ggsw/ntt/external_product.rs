//! GGSW external products in the NTT domain.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::NttPolynomial;
use primus_reduce::FieldContext;

use crate::glwe::{Glwe, NttGlwe};
use crate::workspace::{NttGlweExternalProductWorkspace, NttGlweExternalProductWorkspaceRefMut};

use super::NttGgsw;

impl<S> NttGgsw<S>
where
    S: RawData,
    S::Elem: FheUint,
{
    /// Computes `output = self external_product input`.
    ///
    /// The input and output are coefficient-domain GLWE ciphertexts with every
    /// coefficient reduced to `[0, q)`. `basis` and `modulus` must match those
    /// used to construct `self`.
    ///
    /// # Correctness
    ///
    /// Let `size = workspace.size()`, `N = size.glwe_size().poly_length().get()`,
    /// and `L = size.level_count().get()`. Input and output each have
    /// `size.glwe_size().glwe_len()` elements; `self` has exactly
    /// `size.ggsw_len()` elements. The `k + 1` GLev rows correspond
    /// to the input mask polynomials followed by its body, with `L` levels
    /// per row in `basis.decomposer_iter()` order. Keys must be compatible.
    /// `basis`, `modulus`, and the NTT table must use the same modulus.
    /// The NTT polynomial length must be `N`, and gadget evaluations must
    /// use that table's order. Input and gadget values must be canonical residues.
    /// Output is overwritten and workspace scratch is initialized as needed;
    /// no manual reset is required. Context dimensions do not validate the
    /// basis, key, table, or actual ciphertext buffers.
    pub fn external_product_to<T, M, Table, A, C>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweExternalProductWorkspace<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
        S: Data<Elem = T>,
    {
        debug_assert_eq!(
            output.as_ref().len(),
            workspace.size().glwe_size().glwe_len()
        );
        let mut workspace = workspace.as_mut();
        workspace.ntt_accumulator.set_zero();
        self.as_view().accumulate_external_product(
            input.as_view(),
            basis,
            modulus,
            ntt,
            &mut workspace,
        );
        workspace.ntt_accumulator.write_coeff_form(output, ntt);
    }

    /// Computes `output = self external_product input` and keeps the output in
    /// the NTT domain.
    ///
    /// The input is a coefficient-domain GLWE ciphertext reduced to `[0, q)`.
    /// The output is overwritten in NTT form. This variant avoids the inverse
    /// transform performed by [`Self::external_product_to`] when a composed
    /// operation consumes the product in the NTT domain.
    ///
    /// # Correctness
    ///
    /// All contracts of [`Self::external_product_to`] apply, except that the
    /// output uses the supplied table's NTT representation. It must contain
    /// exactly `workspace.size().glwe_size().glwe_len()` elements. The caller
    /// need not initialize output; the product clears it before accumulating.
    pub fn external_product_ntt_to<T, M, Table, A, C>(
        &self,
        input: &Glwe<A>,
        output: &mut NttGlwe<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweExternalProductWorkspace<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
        S: Data<Elem = T>,
    {
        debug_assert_eq!(
            output.as_ref().len(),
            workspace.size().glwe_size().glwe_len()
        );
        let mut workspace = workspace.as_mut_with_accumulator(output);
        workspace.ntt_accumulator.set_zero();
        self.as_view().accumulate_external_product(
            input.as_view(),
            basis,
            modulus,
            ntt,
            &mut workspace,
        );
    }
}

impl<T: FheUint> NttGgsw<&[T]> {
    /// Adds `self external_product input` to the existing NTT accumulator.
    /// This does not clear the accumulator; the caller must initialize it first.
    ///
    /// # Correctness
    ///
    /// The input, gadget, basis, table, and workspace must satisfy
    /// [`Self::external_product_to`]. The workspace accumulator takes the role
    /// of output and must have the corresponding transform-domain layout.
    pub(super) fn accumulate_external_product<M, Table>(
        &self,
        input: Glwe<&[T]>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweExternalProductWorkspaceRefMut<'_, T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let size = workspace.size();
        let glwe_size = size.glwe_size();
        let poly_len = glwe_size.poly_length().get();
        let glwe_len = glwe_size.glwe_len();
        let glev_len = size.glev_len();

        debug_assert_eq!(ntt.poly_length().get(), poly_len);
        debug_assert_eq!(basis.modulus(), Some(modulus.value()));
        debug_assert_eq!(basis.level_count().get(), size.level_count().get());
        debug_assert_eq!(input.as_ref().len(), glwe_len);
        debug_assert_eq!(self.as_ref().len(), size.ggsw_len());

        for (coeff_poly, key_row) in input.iter_poly(poly_len).zip(self.iter_ntt_glev(glev_len)) {
            basis.init_value_carry_slice_to(
                coeff_poly.as_ref(),
                workspace.adjusted_poly,
                workspace.carries,
            );
            for (decomposer, key_glwe) in
                basis.decomposer_iter().zip(key_row.iter_ntt_glwe(glwe_len))
            {
                decomposer.decompose_slice_to(
                    workspace.adjusted_poly,
                    workspace.decomposed_ntt,
                    workspace.carries,
                );
                ntt.transform_slice(workspace.decomposed_ntt);
                let digit = NttPolynomial::new(&*workspace.decomposed_ntt);
                workspace
                    .ntt_accumulator
                    .add_mul_ntt_polynomial_assign(&key_glwe, &digit, modulus);
            }
        }
    }
}
