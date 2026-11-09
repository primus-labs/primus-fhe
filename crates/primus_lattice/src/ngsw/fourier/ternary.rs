//! Ternary encrypted rotations using one external product.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;

use crate::ntru::{Ntru, accumulate_fourier_gadget_product};
use crate::workspace::FourierNtruCmuxWorkspace;

use super::FourierNgsw;

impl<S> FourierNgsw<S>
where
    S: Data<Elem = Complex64>,
{
    /// Rotates `input` by an encrypted ternary multiple of `exponent`.
    ///
    /// `self` and `negative` encrypt mutually exclusive bits `s⁺` and `s⁻`.
    /// For `s = s⁺ - s⁻`, the ideal output is `X^(exponent * s) * input`.
    /// This uses one external product:
    /// `output = input + (self - X^-exponent * negative) ⊠ ((X^exponent - 1) * input)`.
    /// Decomposition, control noise and Fourier rounding errors need not match
    /// two successive binary CMUXes. Both control encryptions contribute noise
    /// even for `s=0`.
    ///
    /// # Correctness
    ///
    /// Both controls, input, output, basis and engine must satisfy
    /// [`Self::external_product_to`] with `workspace.poly_length()`; each control
    /// has `workspace.level_count().get()` levels matching the native basis.
    /// Control bits must be mutually exclusive (unchecked), under the input's
    /// NTRU key. Independent control encryptions are required for the usual
    /// noise estimate. Controls use this exact FFT table instance and torus scale.
    ///
    /// `exponent` is already quantized into `0..2N`. Its negative is derived from
    /// that same exponent modulo `2N`. The monomial uses integer scale, so the
    /// control's torus scale is preserved. Output is overwritten in coefficient
    /// form without allocation or reset. A public zero exponent copies input.
    ///
    /// # Panics
    /// Zero-exponent copying panics if input and output lengths differ. For
    /// nonzero exponents, incompatible FFT/scratch lengths panic during the
    /// monomial transform, before output writes.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep controls, operands, basis, transform, and scratch explicit"
    )]
    pub fn cmux_ternary_monomial_to<T, Table, A, B, C>(
        &self,
        negative: &FourierNgsw<A>,
        input: &Ntru<B>,
        exponent: usize,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruCmuxWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = workspace.poly_length().get();
        let control_length = workspace.combined_control.len();
        debug_assert!(exponent < 2 * poly_length);
        debug_assert_eq!(basis.level_count().get(), workspace.level_count().get());
        debug_assert_eq!(self.as_ref().len(), control_length);
        debug_assert_eq!(negative.as_ref().len(), control_length);
        debug_assert_eq!(input.as_ref().len(), poly_length);
        debug_assert_eq!(output.as_ref().len(), poly_length);
        if exponent == 0 {
            output.as_mut().copy_from_slice(input.as_ref());
            return;
        }

        let inverse_exponent = 2 * poly_length - exponent;
        // Monomial preparation and decomposition are sequential, so both
        // coefficient and Fourier digit buffers can serve the control factor.
        let mut product = workspace.external_product.as_mut();
        self.sub_mul_monomial_to(
            negative,
            inverse_exponent,
            &mut FourierNgsw(workspace.combined_control.as_mut_slice()),
            fft,
            product.decomposed_poly,
            product.decomposed_fourier,
        );
        input.mul_monomial_sub_one_to(exponent, output, NativeModulus::new());
        product.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(
            workspace.combined_control.as_ref(),
            output.as_ref(),
            basis,
            fft,
            &mut product,
        );
        product.fourier_accumulator.write_torus_form(output, fft);
        output.add_assign(input, NativeModulus::new());
    }
}
