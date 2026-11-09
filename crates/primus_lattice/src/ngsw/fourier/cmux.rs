//! NGSW-controlled conditional multiplexers in the Fourier domain.
//!
//! The output buffer holds the coefficient difference during decomposition, so
//! these operations use the workspace-owned accumulator instead of borrowing output.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;

use crate::ntru::{Ntru, accumulate_fourier_gadget_product};
use crate::workspace::FourierNtruExternalProductWorkspace;

use super::FourierNgsw;

impl<S> FourierNgsw<S>
where
    S: Data<Elem = Complex64>,
{
    /// Computes `output = ct0 + self external_product (ct1 - ct0)`.
    ///
    /// `self` encrypts the control bit. Zero selects `ct0`, and one selects
    /// `ct1`. Inputs and output are coefficient-domain native-torus NTRU
    /// ciphertexts.
    ///
    /// # Correctness
    ///
    /// The control ciphertext, basis, transform table, and workspace must satisfy
    /// [`Self::external_product_to`]. Every coefficient-domain input and output
    /// has exactly `workspace.poly_length()` elements, with compatible keys,
    /// moduli, and encodings. Values must be canonical residues. The output
    /// is overwritten; no prior output initialization or workspace reset is needed.
    /// `self` must encrypt a bit; this is not checked.
    pub fn cmux_to<T, Table, B, C, D>(
        &self,
        ct0: &Ntru<B>,
        ct1: &Ntru<C>,
        output: &mut Ntru<D>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        let poly_length = workspace.poly_length().get();
        debug_assert_eq!(ct0.as_ref().len(), poly_length);
        debug_assert_eq!(ct1.as_ref().len(), poly_length);
        debug_assert_eq!(output.as_ref().len(), poly_length);

        ct1.sub_to(ct0, output, NativeModulus::new());
        let mut workspace = workspace.as_mut();
        workspace.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(
            self.as_ref(),
            output.as_ref(),
            basis,
            fft,
            &mut workspace,
        );
        workspace.fourier_accumulator.write_torus_form(output, fft);
        output.add_assign(ct0, NativeModulus::new());
    }

    /// Computes `output = input + self external_product (input * (X^exponent - 1))`.
    ///
    /// This is the CMux form used by blind rotation. `exponent` must belong to
    /// `[0, 2N)`.
    ///
    /// # Correctness
    ///
    /// The control, input, output, basis, table, and workspace must satisfy
    /// [`Self::cmux_to`]. Require `exponent < 2 * N`, where `N` is the
    /// workspace polynomial length. Bit zero selects `input`; bit one selects
    /// `input * X^exponent`. Output is overwritten; no reset is required.
    pub fn cmux_monomial_to<T, Table, B, C>(
        &self,
        input: &Ntru<B>,
        exponent: usize,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        input.mul_monomial_sub_one_to(exponent, output, NativeModulus::new());
        let mut workspace = workspace.as_mut();
        workspace.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(
            self.as_ref(),
            output.as_ref(),
            basis,
            fft,
            &mut workspace,
        );
        workspace.fourier_accumulator.write_torus_form(output, fft);
        output.add_assign(input, NativeModulus::new());
    }
}
