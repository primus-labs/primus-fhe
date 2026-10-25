//! Undecoded coefficient-phase extraction (`f * c`).

use super::{FourierNtruDecryptWorkspace, FourierNtruSecretKey};
use crate::FourierNtruCiphertext;
use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_poly::{FourierPolynomial, Polynomial};

impl FourierNtruSecretKey {
    /// Computes `f * c` in native coefficient form. For an encoded message `mu`,
    /// the phase is `mu + e` up to Fourier rounding.
    /// The output is an undecoded coefficient polynomial; no plaintext codec or
    /// noise distribution is needed. Output is overwritten, including old values.
    ///
    /// # Correctness
    ///
    /// The input and key must use this FFT table instance's Fourier representation.
    ///
    /// # Panics
    ///
    /// Panics before writes if transform, input, output or workspace lengths
    /// do not match the key.
    pub fn decrypt_phase_to<T, Table, A, B>(
        &self,
        input: &FourierNtruCiphertext<A>,
        output: &mut Polynomial<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruDecryptWorkspace,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            fft.poly_length().get(),
            self.poly_length(),
            "FFT polynomial length mismatch"
        );
        assert_eq!(input.as_ref().len(), fft.fourier_length());
        assert_eq!(output.as_ref().len(), self.poly_length());
        assert_eq!(workspace.phase.as_ref().len(), fft.fourier_length());

        FourierPolynomial(input.as_ref()).mul_to(&self.key, &mut workspace.phase);
        fft.backward_as_torus(workspace.phase.as_ref(), output.as_mut());
    }
}
