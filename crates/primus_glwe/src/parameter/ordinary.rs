//! Ordinary GLWE layout and plaintext encoding.

use primus_distr::{DiscreteGaussian, SecretKeySampler};
use primus_integer::FheUint;
use primus_lattice::{GlweDimension, GlweSize};
use primus_reduce::RingContext;
use primus_shape::PolyLength;
use rand::distr::Uniform;
use std::sync::Arc;

use super::{GlweEncryptionParameters, GlweParameterError};
use crate::{ScaledCodec, SecretKeyDistr};

/// Ordinary GLWE layout, shared encryption state and plaintext encoding.
/// Clones and derived gadget parameters share immutable modulus and sampling state.
#[derive(Clone)]
pub struct GlweParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    size: GlweSize,
    pub(super) encryption_parameters: Arc<GlweEncryptionParameters<T, M>>,
    plaintext_codec: ScaledCodec<T, M>,
}

impl<T, M> GlweParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates a new [`GlweParameters<T, M>`].
    ///
    /// # Panics
    /// Panics on the layout, encoding or sampler errors of [`Self::try_new`],
    /// including fixed secret weights exceeding the complete `kN` key length.
    #[must_use]
    pub fn new(
        dimension: GlweDimension,
        poly_length: PolyLength,
        plain_modulus_value: T,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        Self::try_new(
            dimension,
            poly_length,
            plain_modulus_value,
            cipher_modulus,
            secret_key_distr,
            noise_standard_deviation,
        )
        .expect("invalid GLWE parameters")
    }

    /// Checks combined layout, fixed-scale encoding, secret support/weight and noise.
    /// The dimension and ring length have already been checked by their types.
    /// Noise standard deviation is in coefficient units at the ciphertext modulus.
    /// This validates construction, not transform availability or a noise/security budget.
    pub fn try_new(
        dimension: GlweDimension,
        poly_length: PolyLength,
        plain_modulus_value: T,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Result<Self, GlweParameterError> {
        let size = GlweSize::try_new(dimension, poly_length)?;
        let plaintext_codec = ScaledCodec::try_new(plain_modulus_value, cipher_modulus)?;

        let encryption_parameters = GlweEncryptionParameters::try_new(
            cipher_modulus,
            secret_key_distr,
            noise_standard_deviation,
        )?;
        encryption_parameters
            .secret_key_sampler()
            .validate_length(size.mask_len())?;
        Ok(Self::from_matching_parts(
            size,
            Arc::new(encryption_parameters),
            plaintext_codec,
        ))
    }

    /// Binds a GLWE layout and prepared sampling state to ordinary message encoding.
    ///
    /// The shared state can also be used by [`super::GlevParameters::try_from_parts`]
    /// without a codec. No sampler tables are copied or rebuilt here.
    ///
    /// # Errors
    ///
    /// Rejects a codec with a different ciphertext modulus or a fixed secret weight
    /// exceeding the complete `kN` key length. Layout, sampler support/noise and
    /// fixed-scale recovery were checked by the supplied parts' constructors.
    pub fn try_from_parts(
        size: GlweSize,
        encryption_parameters: Arc<GlweEncryptionParameters<T, M>>,
        plaintext_codec: ScaledCodec<T, M>,
    ) -> Result<Self, GlweParameterError> {
        if plaintext_codec.ciphertext_modulus() != encryption_parameters.cipher_modulus() {
            return Err(GlweParameterError::CodecModulusMismatch);
        }
        encryption_parameters
            .secret_key_sampler()
            .validate_length(size.mask_len())?;
        Ok(Self::from_matching_parts(
            size,
            encryption_parameters,
            plaintext_codec,
        ))
    }

    /// Binds an ordinary message codec to an existing gadget's GLWE domain.
    /// Shares prepared samplers; the gadget basis is neither copied nor retained.
    ///
    /// # Errors
    /// Rejects a codec with another ciphertext modulus.
    pub fn try_from_glev(
        gadget: &super::GlevParameters<T, M>,
        plaintext_codec: ScaledCodec<T, M>,
    ) -> Result<Self, GlweParameterError> {
        if plaintext_codec.ciphertext_modulus() != gadget.cipher_modulus() {
            return Err(GlweParameterError::CodecModulusMismatch);
        }
        // The gadget already checked fixed secret weights against this layout.
        Ok(Self::from_matching_parts(
            gadget.glwe_size(),
            Arc::clone(&gadget.encryption_parameters),
            plaintext_codec,
        ))
    }

    /// Assembles state after the caller establishes the codec modulus and
    /// secret weight/layout pairing, either by construction or by validation.
    fn from_matching_parts(
        size: GlweSize,
        encryption_parameters: Arc<GlweEncryptionParameters<T, M>>,
        plaintext_codec: ScaledCodec<T, M>,
    ) -> Self {
        Self {
            size,
            encryption_parameters,
            plaintext_codec,
        }
    }

    /// Returns the parameters shared by GLWE and its gadget ciphertexts.
    #[inline]
    pub fn encryption_parameters(&self) -> &GlweEncryptionParameters<T, M> {
        self.encryption_parameters.as_ref()
    }

    /// Returns the dimension of this [`GlweParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn dimension(&self) -> GlweDimension {
        self.size.dimension()
    }

    /// Returns the poly length of this [`GlweParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.size.poly_length()
    }

    /// Returns the pre-computed GLWE size constants.
    #[inline]
    pub fn size(&self) -> GlweSize {
        self.size
    }

    /// Returns the coefficient/NTT GLWE ciphertext length `(k + 1)N`.
    #[inline]
    pub fn glwe_len(&self) -> usize {
        self.size.glwe_len()
    }

    /// Returns the Fourier GLWE ciphertext length `(k + 1)N/2`.
    #[inline]
    pub fn fourier_glwe_len(&self) -> usize {
        self.size.fourier_glwe_len()
    }

    /// Returns the plain modulus value of this [`GlweParameters<T, M>`].
    pub fn plain_modulus_value(&self) -> T {
        self.plaintext_codec.plaintext_modulus()
    }

    /// Returns the preselected plaintext codec strategy.
    #[inline]
    pub fn plaintext_codec(&self) -> &ScaledCodec<T, M> {
        &self.plaintext_codec
    }

    /// Returns the cipher modulus of this [`GlweParameters<T, M>`].
    pub fn cipher_modulus(&self) -> M {
        self.encryption_parameters.cipher_modulus()
    }

    /// Returns the explicit ciphertext modulus, or `None` for the native modulus
    /// `2^T::BITS`, whose value cannot be represented in `T`.
    #[must_use]
    #[inline]
    pub fn cipher_modulus_value(&self) -> Option<T> {
        self.encryption_parameters.cipher_modulus_value()
    }

    /// Returns the cipher modulus minus one of this [`GlweParameters<T, M>`].
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.encryption_parameters.cipher_modulus_minus_one()
    }

    /// Returns the cipher modulus uniform distr of this [`GlweParameters<T, M>`].
    pub fn cipher_modulus_uniform_distr(&self) -> Uniform<T> {
        self.encryption_parameters.cipher_modulus_uniform_distr()
    }

    /// Returns the secret key type of this [`GlweParameters<T, M>`].
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.encryption_parameters.secret_key_distr()
    }

    /// Returns shared precomputation for signed and encoded secret coefficients.
    #[must_use]
    #[inline]
    pub fn secret_key_sampler(&self) -> &SecretKeySampler<T> {
        self.encryption_parameters.secret_key_sampler()
    }

    /// Returns a reference to the noise distribution of this [`GlweParameters<T, M>`].
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        self.encryption_parameters.noise_distribution()
    }
}
