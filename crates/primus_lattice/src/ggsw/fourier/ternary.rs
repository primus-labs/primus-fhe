//! Ternary encrypted rotations using one external product.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;

use crate::glwe::TorusGlwe;
use crate::workspace::FourierGlweTernaryCmuxWorkspace;

use super::FourierGgsw;

impl<S> FourierGgsw<S>
where
    S: Data<Elem = Complex64>,
{
    /// Rotates `input` by an encrypted ternary multiple of `exponent`.
    ///
    /// `self` and `negative` encrypt bits `s⁺` and `s⁻`.
    /// For `s = s⁺ - s⁻`, the ideal output is `X^(exponent * s) * input`.
    /// This computes `input + (self - X^-exponent * negative) ⊠ ((X^exponent - 1) * input)`
    /// with one external product. Decomposition, control noise, and Fourier
    /// rounding errors need not match two successive binary CMUX operations.
    /// Both control encryptions contribute noise, even for `s=0`.
    ///
    /// # Correctness
    ///
    /// Both controls, input, output, basis, and engine must satisfy
    /// [`Self::external_product_to`] with `workspace.size()`. Control bits must be
    /// mutually exclusive (unchecked) and use the same key and native basis.
    /// The usual noise estimate requires independent encryptions. Both controls
    /// must use the engine's exact table instance, ordering, and normalized torus scale.
    ///
    /// `exponent` is already quantized into `0..2N`. Its negative is derived from
    /// that same exponent modulo `2N`. The monomial is transformed at integer
    /// scale; applying torus scaling to it would destroy the control's scale.
    /// Output is overwritten in coefficient form without allocation or reset.
    /// A public zero exponent copies `input` exactly without evaluating controls.
    ///
    /// # Panics
    ///
    /// Zero-exponent copying panics if input and output lengths differ.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep controls, operands, basis, transform, and scratch explicit"
    )]
    pub fn cmux_ternary_monomial_to<T, Table, A, B, C>(
        &self,
        negative: &FourierGgsw<A>,
        input: &TorusGlwe<B>,
        exponent: usize,
        output: &mut TorusGlwe<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweTernaryCmuxWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let size = workspace.size();
        let poly_length = size.glwe_size().poly_length().get();
        debug_assert!(exponent < 2 * poly_length);
        debug_assert_eq!(self.as_ref().len(), size.fourier_ggsw_len());
        debug_assert_eq!(negative.as_ref().len(), size.fourier_ggsw_len());
        debug_assert_eq!(input.as_ref().len(), size.glwe_size().glwe_len());
        debug_assert_eq!(output.as_ref().len(), size.glwe_size().glwe_len());
        if exponent == 0 {
            output.as_mut().copy_from_slice(input.as_ref());
            return;
        }

        let inverse_exponent = 2 * poly_length - exponent;
        // Reuse the external-product digit buffer for the integer monomial;
        // decomposition overwrites it after control combination.
        self.sub_mul_monomial_to(
            negative,
            inverse_exponent,
            &mut workspace.combined_control,
            fft,
            &mut workspace.external_product.decomposed_poly,
            &mut workspace.control_factor_fourier,
        );

        input.mul_monomial_sub_one_to(exponent, output, poly_length, NativeModulus::new());
        let mut product = workspace.external_product.as_mut();
        product.fourier_accumulator.set_zero();
        workspace
            .combined_control
            .as_view()
            .accumulate_external_product(output.as_view(), basis, fft, &mut product);
        product.fourier_accumulator.write_torus_form(output, fft);
        output.add_assign(input, NativeModulus::new());
    }
}
