//! Fourier GLWE phase extraction without message decoding.

use super::{FourierGlweDecryptWorkspace, FourierGlweSecretKey};
use crate::FourierGlweCiphertext;
use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_poly::Polynomial;

impl FourierGlweSecretKey {
    /// Computes `b - sum(a_i * s_i)` and writes the encoded torus phase in
    /// coefficient form.
    ///
    /// # Correctness
    ///
    /// Input must use torus-scaled Fourier values. Input, key generation and
    /// evaluation must use the same FFT table instance.
    ///
    /// # Panics
    ///
    /// Panics if ciphertext/output, FFT, or workspace lengths do not match
    /// the key layout. Checks precede output writes.
    pub fn decrypt_phase_to<T, Table, A, B>(
        &self,
        input: &FourierGlweCiphertext<A>,
        output: &mut Polynomial<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweDecryptWorkspace,
    ) where
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = T>,
        T: TorusFftValue,
    {
        assert_eq!(
            fft.poly_length(),
            self.poly_length(),
            "FFT polynomial length mismatch"
        );
        assert_eq!(
            input.as_ref().len(),
            self.size.fourier_glwe_len(),
            "Fourier GLWE input layout mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.size.poly_length().get(),
            "GLWE phase output length mismatch"
        );

        let fourier_length = fft.fourier_length();
        let (mut mask, body) = input.a_b(fourier_length);

        assert_eq!(
            workspace.phase.len(),
            fourier_length,
            "Fourier phase workspace length mismatch"
        );
        let phase = &mut workspace.phase;

        let mut secret = self.iter();
        let si = secret.next().expect("GLWE dimension must be non-zero");
        let ai = mask.next().expect("GLWE ciphertext mask is missing");

        ai.mul_to(&si, phase);

        for (si, ai) in secret.zip(mask) {
            phase.add_mul_assign(&ai, &si);
        }

        body.sub_rev_assign(phase);

        fft.backward_as_torus(phase.as_ref(), output.as_mut());
    }
}
