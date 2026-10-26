//! Exact native coefficient encryption followed by canonical Fourier conversion.

use super::GlweSecretKey;
use crate::secret_key::exact::ExactSecretProduct;
use crate::{
    FourierGlweCiphertext, GlweCiphertext, GlweEncryptionParameters, GlweParameters, GlweSize,
    PlaintextEmbedding,
};
use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use zeroize::Zeroizing;

/// A coefficient secret is incompatible with the declared encryption support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FourierGlweEncryptorError {
    /// The secret's distribution label differs from the encryption parameters.
    #[error("GLWE secret distribution mismatch")]
    SecretDistributionMismatch,
    /// A coefficient exceeds the public sampler support bound.
    #[error("GLWE secret coefficient exceeds the declared magnitude bound")]
    SecretMagnitudeTooLarge,
}

/// Prepared exact native GLWE encryption under a borrowed coefficient secret.
///
/// Owns auxiliary NTT/CRT caches and one `(k+1)N` coefficient row, erased on
/// drop/unwind. The public support bound selects CRT or exact O(kN²) schoolbook
/// row computation; the observed secret support never selects a faster path. Row methods
/// reuse all buffers without allocation. Final native coefficients are transformed
/// only after all modular message/diagonal additions. Fourier conversion still
/// introduces numerical error and must fit the decoding margin. Generated
/// ciphertexts/keys must subsequently use the FFT table from their encryption
/// call. Each call takes its own noise/gadget parameters; preparation never
/// substitutes one material's noise distribution for another.
pub struct FourierGlweEncryptor<'key, T: TorusFftValue> {
    pub(super) secret: &'key GlweSecretKey<T>,
    product: ExactSecretProduct<'key, T>,
    pub(super) row: Zeroizing<Vec<T>>,
}

impl<'key, T: TorusFftValue> FourierGlweEncryptor<'key, T> {
    /// Prepares one target using the parameters' public, truncated sampler bound.
    /// Checks all coefficients before preparing secret transforms or consuming
    /// randomness. Does not certify fixed weight, distribution provenance,
    /// security or Fourier decoding precision.
    pub fn try_new(
        secret: &'key GlweSecretKey<T>,
        parameters: &GlweEncryptionParameters<T, NativeModulus<T>>,
    ) -> Result<Self, FourierGlweEncryptorError> {
        if secret.distr() != parameters.secret_key_distr() {
            return Err(FourierGlweEncryptorError::SecretDistributionMismatch);
        }
        let product = ExactSecretProduct::try_new(
            secret,
            parameters.secret_key_sampler().maximum_magnitude(),
        )
        .map_err(|_| FourierGlweEncryptorError::SecretMagnitudeTooLarge)?;
        Ok(Self::from_product(secret, product))
    }

    /// Prepares arbitrary imported signed coefficients using the full word range.
    /// Distribution metadata is not validated. u64 uses exact schoolbook, which
    /// is expensive at large N; bounded secrets should use [`Self::try_new`].
    /// u16/u32 fit the CRT range. This does not certify Fourier decoding precision.
    #[must_use]
    pub fn from_coeff_secret_key(secret: &'key GlweSecretKey<T>) -> Self {
        let product = ExactSecretProduct::try_new(secret, T::ONE << (T::BITS - 1))
            .expect("signed coefficients fit their native word magnitude");
        Self::from_product(secret, product)
    }

    fn from_product(secret: &'key GlweSecretKey<T>, product: ExactSecretProduct<'key, T>) -> Self {
        Self {
            secret,
            product,
            row: Zeroizing::new(vec![T::ZERO; secret.glwe_size().glwe_len()]),
        }
    }

    /// Returns the target coefficient GLWE layout.
    #[must_use]
    pub fn glwe_size(&self) -> GlweSize {
        self.secret.glwe_size()
    }

    /// Returns the coefficient polynomial length.
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.secret.poly_length()
    }

    /// Borrows the exact target for same-secret AK/SS messages, without exposing caches.
    pub(crate) fn coefficient_secret(&self) -> &'key GlweSecretKey<T> {
        self.secret
    }

    /// Encrypts an already encoded N-coefficient native polynomial, without
    /// plaintext/gadget scaling, overwriting the complete Fourier output.
    ///
    /// # Panics
    /// Layout/FFT checks precede sampling/writes. RNG panics modify scratch and
    /// consume randomness but leave output untouched; FFT may partly write output.
    pub fn encrypt_encoded_to<
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    >(
        &mut self,
        input: &Polynomial<A>,
        output: &mut FourierGlweCiphertext<B>,
        params: &GlweEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) {
        self.assert_fourier_output(output.as_ref().len(), fft);
        assert_eq!(
            input.as_ref().len(),
            self.poly_length().get(),
            "GLWE message length mismatch"
        );
        self.sample_row(params, rng, |body| {
            for (b, &m) in body.iter_mut().zip(input.as_ref()) {
                *b = b.wrapping_add(m);
            }
        });
        self.write_fourier_row(output.as_mut_view(), fft);
    }

    /// Allocates a Fourier encryption of zero; see [`Self::encrypt_zeros_to`].
    #[must_use]
    pub fn encrypt_zeros<Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        &mut self,
        params: &GlweEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> FourierGlweCiphertext<Vec<Complex64>> {
        let mut output = FourierGlweCiphertext::zero(self.glwe_size().fourier_glwe_len());
        self.encrypt_zeros_to(&mut output, params, fft, rng);
        output
    }

    /// Overwrites one complete Fourier GLWE with an encryption of zero.
    ///
    /// # Panics
    /// Output/FFT checks precede sampling/writes. RNG panics modify scratch and
    /// consume randomness but leave output untouched; FFT may partly write output.
    pub fn encrypt_zeros_to<
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = Complex64>,
    >(
        &mut self,
        output: &mut FourierGlweCiphertext<B>,
        params: &GlweEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) {
        self.assert_fourier_output(output.as_ref().len(), fft);
        self.sample_row(params, rng, |_| {});
        self.write_fourier_row(output.as_mut_view(), fft);
    }

    /// Allocates a Fourier message encryption; see [`Self::encrypt_message_to`].
    #[must_use]
    pub fn encrypt_message<Table: FftTable, R: rand::Rng + rand::CryptoRng, A: Data<Elem = T>>(
        &mut self,
        input: &Polynomial<A>,
        params: &GlweParameters<T, NativeModulus<T>>,
        embedding: PlaintextEmbedding,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> FourierGlweCiphertext<Vec<Complex64>> {
        let mut output = FourierGlweCiphertext::zero(self.glwe_size().fourier_glwe_len());
        self.encrypt_message_to(input, &mut output, params, embedding, fft, rng);
        output
    }

    /// Encrypts N canonical residues in `[0,t)` with the selected embedding.
    /// Encoding is added once to sampled coefficient noise before sampling masks.
    ///
    /// # Panics
    /// Layout/FFT checks precede sampling/writes. Plaintext-range/RNG panics may
    /// consume randomness and modify scratch while leaving output untouched;
    /// FFT may partly write output.
    #[allow(clippy::too_many_arguments)] // Message, encoding, output and transform resources.
    pub fn encrypt_message_to<
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    >(
        &mut self,
        input: &Polynomial<A>,
        output: &mut FourierGlweCiphertext<B>,
        params: &GlweParameters<T, NativeModulus<T>>,
        embedding: PlaintextEmbedding,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) {
        self.assert_message_layout(input.as_ref().len(), params);
        self.assert_fourier_output(output.as_ref().len(), fft);
        self.sample_row(params.encryption_parameters(), rng, |body| {
            params
                .plaintext_codec()
                .add_encode_slice_assign(body, input.as_ref(), embedding)
        });
        self.write_fourier_row(output.as_mut_view(), fft);
    }

    /// Encrypts N canonical message residues directly to native coefficients.
    /// No FFT/inverse conversion is performed; output is copied after the exact
    /// row is complete. Reuses the prepared row without allocating.
    ///
    /// # Panics
    /// Layout checks precede sampling/writes. Codec/RNG panics can consume
    /// randomness and modify scratch while leaving output untouched.
    pub fn encrypt_message_coeff_to<
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    >(
        &mut self,
        input: &Polynomial<A>,
        output: &mut GlweCiphertext<B>,
        params: &GlweParameters<T, NativeModulus<T>>,
        embedding: PlaintextEmbedding,
        rng: &mut R,
    ) {
        self.assert_message_layout(input.as_ref().len(), params);
        assert_eq!(
            output.as_ref().len(),
            self.glwe_size().glwe_len(),
            "coefficient GLWE output layout mismatch"
        );
        self.sample_row(params.encryption_parameters(), rng, |body| {
            params
                .plaintext_codec()
                .add_encode_slice_assign(body, input.as_ref(), embedding)
        });
        output.as_mut().copy_from_slice(&self.row);
    }

    fn assert_message_layout(
        &self,
        input_len: usize,
        params: &GlweParameters<T, NativeModulus<T>>,
    ) {
        assert_eq!(
            self.glwe_size(),
            params.size(),
            "GLWE parameter layout mismatch"
        );
        assert_eq!(
            input_len,
            self.poly_length().get(),
            "GLWE message length mismatch"
        );
    }

    pub(super) fn assert_fourier_output<Table: FftTable>(
        &self,
        output_len: usize,
        fft: &FftEngine<'_, Table>,
    ) {
        assert_eq!(
            fft.poly_length(),
            self.poly_length(),
            "FFT polynomial length mismatch"
        );
        assert_eq!(
            output_len,
            self.glwe_size().fourier_glwe_len(),
            "Fourier GLWE output layout mismatch"
        );
    }

    /// Preserves noise -> one message addition -> masks in component order.
    /// Only exact modular products enter the body. The caller validated all
    /// external buffers; this kernel does not allocate or convert through FFT.
    /// The returned complete native row borrows setup scratch until its next use;
    /// ordinary and split conversion consume the same canonical representation.
    pub(crate) fn sample_row<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        params: &GlweEncryptionParameters<T, NativeModulus<T>>,
        rng: &mut R,
        add_message: impl FnOnce(&mut [T]),
    ) -> GlweCiphertext<&[T]> {
        let n = self.poly_length().get();
        let (mask, body) = self.row.split_at_mut(self.secret.glwe_size().mask_len());
        primus_distr::sample_gaussian_values_to(body, params.noise_distribution(), rng);
        add_message(body);
        let uniform = params.cipher_modulus_uniform_distr();
        for (component, polynomial) in mask.chunks_exact_mut(n).enumerate() {
            primus_distr::sample_uniform_values_to(polynomial, &uniform, rng);
            self.product.add_product_assign(polynomial, component, body);
        }
        GlweCiphertext::new(self.row.as_slice())
    }

    /// Transforms final canonical native components after every diagonal addition.
    /// Exact lengths were established by the owning public boundary.
    pub(super) fn write_fourier_row<Table: FftTable>(
        &self,
        mut output: FourierGlweCiphertext<&mut [Complex64]>,
        fft: &mut FftEngine<'_, Table>,
    ) {
        let n = self.poly_length().get();
        for (input, mut out) in primus_lattice::glwe::Glwe::new(self.row.as_slice())
            .iter_poly(n)
            .zip(output.iter_fourier_poly_mut(n / 2))
        {
            fft.forward_as_torus(input.as_ref(), out.as_mut());
        }
    }

    /// Computes the body from original masks, then modifies the designated
    /// native diagonal. Recomputing the body afterwards would cancel its message.
    pub(super) fn sample_gadget_row<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        diagonal: usize,
        params: &GlweEncryptionParameters<T, NativeModulus<T>>,
        rng: &mut R,
        add_diagonal: impl FnOnce(&mut [T]),
    ) {
        self.sample_row(params, rng, |_| {});
        let n = self.poly_length().get();
        add_diagonal(&mut self.row[diagonal * n..(diagonal + 1) * n]);
    }
}
