//! Message decoding from Fourier GLWE ciphertexts.

use super::{FourierGlweDecryptWorkspace, FourierGlweSecretKey};
use crate::{FourierGlweCiphertext, GlweParameters};
use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_poly::{Polynomial, PolynomialOwned};

impl FourierGlweSecretKey {
    /// Decrypts a native-torus Fourier-domain GLWE ciphertext.
    /// Inherits [`Self::decrypt_phase_to`]'s representation requirements.
    ///
    /// # Panics
    ///
    /// Panics if the parameter layout differs from this key or the inputs
    /// violate [`Self::decrypt_phase_to`]'s compatibility checks.
    #[must_use]
    pub fn decrypt_message<T, Table, A>(
        &self,
        input: &FourierGlweCiphertext<A>,
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweDecryptWorkspace,
    ) -> PolynomialOwned<T>
    where
        Table: FftTable,
        A: Data<Elem = Complex64>,
        T: TorusFftValue,
    {
        let mut output = PolynomialOwned::zero(self.size.poly_length().get());
        self.decrypt_message_to(input, &mut output, params, fft, workspace);
        output
    }

    /// Decrypts into an existing plaintext polynomial.
    /// Inherits [`Self::decrypt_phase_to`]'s representation requirements.
    /// Returns canonical residues in `[0, t)` for either encryption embedding.
    /// Recovering the original message requires phase noise within the codec margin.
    ///
    /// # Panics
    ///
    /// Panics if the parameter layout differs from this key or the inputs
    /// violate [`Self::decrypt_phase_to`]'s compatibility checks.
    pub fn decrypt_message_to<T, Table, A, B>(
        &self,
        input: &FourierGlweCiphertext<A>,
        output: &mut Polynomial<B>,
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweDecryptWorkspace,
    ) where
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = T>,
        T: TorusFftValue,
    {
        assert_eq!(self.size, params.size(), "GLWE parameter layout mismatch");
        self.decrypt_phase_to(input, output, fft, workspace);
        params
            .plaintext_codec()
            .decode_slice_assign(output.as_mut());
    }
}
