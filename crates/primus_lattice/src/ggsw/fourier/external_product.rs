//! GGSW external products in the Fourier domain.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_poly::FourierPolynomial;

use crate::glwe::{FourierGlwe, TorusGlwe};
use crate::workspace::{
    FourierGlweExternalProductWorkspace, FourierGlweExternalProductWorkspaceRefMut,
};

use super::FourierGgsw;

impl<S> FourierGgsw<S>
where
    S: Data<Elem = Complex64>,
{
    /// Computes `output = self external_product input`.
    ///
    /// This operation uses the implicit native torus modulus. `input` and
    /// `output` are coefficient-domain torus GLWE ciphertexts. `basis` must be
    /// the decomposition basis used to construct `self`.
    ///
    /// # Correctness
    ///
    /// Let `size = workspace.size()`, `N = size.glwe_size().poly_length().get()`,
    /// and `L = size.level_count().get()`. Input and output each have
    /// `size.glwe_size().glwe_len()` elements; `self` has exactly
    /// `size.fourier_ggsw_len()` elements. The `k + 1` GLev rows correspond
    /// to the input mask polynomials followed by its body, with `L` levels
    /// per row in `basis.decomposer_iter()` order. Keys must be compatible.
    /// `basis` must use the implicit native modulus (`basis.modulus() == None`).
    /// The FFT engine must have polynomial length `N` and Fourier length
    /// `N / 2`; gadget values must use its packing and normalized torus scale.
    /// Output is overwritten and workspace scratch is initialized as needed;
    /// no manual reset is required. Context dimensions do not validate the
    /// basis, key, table, or actual ciphertext buffers.
    pub fn external_product_to<T, Table, A, C>(
        &self,
        input: &TorusGlwe<A>,
        output: &mut TorusGlwe<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        debug_assert_eq!(
            output.as_ref().len(),
            workspace.size().glwe_size().glwe_len()
        );
        let mut workspace = workspace.as_mut();
        workspace.fourier_accumulator.set_zero();
        self.as_view()
            .accumulate_external_product(input.as_view(), basis, fft, &mut workspace);
        workspace.fourier_accumulator.write_torus_form(output, fft);
    }

    /// Computes an external product directly into Fourier output, without an inverse FFT.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::external_product_to`]'s contracts, except that output
    /// has `workspace.size().glwe_size().fourier_glwe_len()` complex values in
    /// the key's FFT representation. Output is cleared before accumulation.
    pub fn external_product_fourier_to<T, Table, A, C>(
        &self,
        input: &TorusGlwe<A>,
        output: &mut FourierGlwe<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
        C: DataMut<Elem = Complex64>,
    {
        debug_assert_eq!(
            output.as_ref().len(),
            workspace.size().glwe_size().fourier_glwe_len()
        );
        let mut workspace = workspace.as_mut_with_accumulator(output);
        workspace.fourier_accumulator.set_zero();
        self.as_view()
            .accumulate_external_product(input.as_view(), basis, fft, &mut workspace);
    }
}

impl FourierGgsw<&[Complex64]> {
    /// Adds `self external_product input` to the existing Fourier accumulator.
    /// This does not clear the accumulator; the caller must initialize it first.
    ///
    /// # Correctness
    ///
    /// The input, gadget, basis, table, and workspace must satisfy
    /// [`Self::external_product_to`]. The workspace accumulator takes the role
    /// of output and must have the corresponding transform-domain layout.
    pub(super) fn accumulate_external_product<T, Table>(
        &self,
        input: TorusGlwe<&[T]>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweExternalProductWorkspaceRefMut<'_, T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
    {
        let size = workspace.size();
        let glwe_size = size.glwe_size();
        let poly_len = glwe_size.poly_length().get();
        let fourier_poly_len = glwe_size.fourier_poly_len();
        let fourier_glwe_len = glwe_size.fourier_glwe_len();
        let fourier_glev_len = size.fourier_glev_len();

        debug_assert_eq!(fft.poly_length().get(), poly_len);
        debug_assert_eq!(fft.fourier_length(), fourier_poly_len);
        debug_assert_eq!(basis.modulus(), None);
        debug_assert_eq!(basis.level_count().get(), size.level_count().get());
        debug_assert_eq!(input.as_ref().len(), glwe_size.glwe_len());
        debug_assert_eq!(self.as_ref().len(), size.fourier_ggsw_len());

        for (coeff_poly, key_row) in input
            .iter_poly(poly_len)
            .zip(self.iter_glev(fourier_glev_len))
        {
            basis.init_carry_slice(coeff_poly.0, workspace.carries);
            for (decomposer, key_glwe) in basis
                .decomposer_iter()
                .zip(key_row.iter_glwe(fourier_glwe_len))
            {
                decomposer.decompose_slice_to(
                    coeff_poly.0,
                    workspace.decomposed_poly,
                    workspace.carries,
                );
                fft.forward_as_integer(workspace.decomposed_poly, workspace.decomposed_fourier);
                workspace
                    .fourier_accumulator
                    .add_mul_fourier_polynomial_assign(
                        &key_glwe,
                        &FourierPolynomial::new(&*workspace.decomposed_fourier),
                    );
            }
        }
    }
}
