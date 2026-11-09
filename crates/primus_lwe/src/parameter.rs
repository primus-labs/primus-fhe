use primus_distr::{DiscreteGaussian, SecretKeySampler};
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_reduce::RingContext;
use rand::distr::Uniform;

use crate::{RoundedCodec, SecretKeyDistr};

/// Invalid LWE encoding, sampling or key-switching parameter pairing.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum LweParameterError {
    /// Invalid message/ciphertext moduli.
    #[error(transparent)]
    Encoding(#[from] primus_encoding::CodecError),
    /// Invalid secret sampling configuration, weight or output modulus.
    #[error(transparent)]
    SecretKey(#[from] primus_distr::SecretKeySamplerError),
    /// Invalid coefficient-domain Gaussian noise.
    #[error("invalid LWE noise distribution")]
    Noise(#[from] primus_distr::GaussianError),
    /// The key-switching basis and target LWE ciphertext use different moduli.
    #[error("LWE key-switching basis must match the target ciphertext modulus")]
    BasisModulusMismatch,
}

/// Ciphertext domain and prepared LWE samplers, independent of message encoding.
/// The ciphertext length `dimension + 1` always fits in `usize`.
#[derive(Clone)]
pub struct LweEncryptionParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Nonzero **LWE** vector dimension, refers to **n** in the paper.
    dimension: LweDimension,
    /// **LWE** cipher modulus, refers to **q** in the paper.
    cipher_modulus: M,
    /// **LWE** cipher modulus minus one, refers to **q-1** in the paper.
    cipher_modulus_minus_one: T,
    cipher_modulus_uniform_distr: Uniform<T>,
    secret_key_sampler: SecretKeySampler<T>,
    /// The noise distribution.
    noise_distribution: DiscreteGaussian<T>,
}

impl<T, M> LweEncryptionParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates a new [`LweEncryptionParameters<T, M>`].
    ///
    /// # Panics
    ///
    /// Panics on the sampler errors of [`Self::try_new`],
    /// including fixed secret weights exceeding the dimension.
    #[must_use]
    #[inline]
    pub fn new(
        dimension: LweDimension,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        Self::try_new(
            dimension,
            cipher_modulus,
            secret_key_distr,
            noise_standard_deviation,
        )
        .expect("invalid LWE parameters")
    }

    /// Checks secret support/weight and the coefficient-noise sampler.
    /// The dimension has already been checked by [`LweDimension`].
    /// Noise standard deviation is measured in ciphertext coefficient units.
    /// Successful construction does not establish security or a decryption margin.
    pub fn try_new(
        dimension: LweDimension,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Result<Self, LweParameterError> {
        let cipher_modulus_minus_one = cipher_modulus.minus_one();

        let noise_distribution =
            DiscreteGaussian::new(noise_standard_deviation, cipher_modulus_minus_one)?;
        let secret_key_sampler = SecretKeySampler::try_new(secret_key_distr)?;
        secret_key_sampler.validate_length(dimension.get())?;
        secret_key_sampler.validate_modulus(cipher_modulus_minus_one)?;

        let cipher_modulus_uniform_distr = cipher_modulus.uniform_distribution();
        Ok(Self {
            dimension,
            cipher_modulus,
            cipher_modulus_minus_one,
            cipher_modulus_uniform_distr,
            secret_key_sampler,
            noise_distribution,
        })
    }

    /// Returns the dimension of this [`LweEncryptionParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn dimension(&self) -> LweDimension {
        self.dimension
    }

    /// Returns the cipher modulus of this [`LweEncryptionParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn cipher_modulus(&self) -> M {
        self.cipher_modulus
    }

    /// Returns the representable ciphertext modulus, or `None` for a native torus.
    #[must_use]
    #[inline]
    pub fn cipher_modulus_value(&self) -> Option<T> {
        self.cipher_modulus.explicit_value()
    }

    /// Returns the cipher modulus minus one of this [`LweEncryptionParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.cipher_modulus_minus_one
    }

    /// Returns the cipher modulus uniform distr of this [`LweEncryptionParameters<T, M>`].
    #[must_use]
    pub fn cipher_modulus_uniform_distr(&self) -> Uniform<T> {
        self.cipher_modulus_uniform_distr
    }

    /// Returns the secret key type of this [`LweEncryptionParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.secret_key_sampler.distr()
    }

    /// Returns the prepared sampler for the complete LWE secret.
    #[must_use]
    #[inline]
    pub fn secret_key_sampler(&self) -> &SecretKeySampler<T> {
        &self.secret_key_sampler
    }

    /// Returns the noise standard deviation of this [`LweEncryptionParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn noise_standard_deviation(&self) -> f64 {
        self.noise_distribution.standard_deviation()
    }

    /// Gets the discrete gaussian noise distribution.
    #[must_use]
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        &self.noise_distribution
    }
}

/// Ordinary LWE parameters combining checked sampling state with a Rounded codec.
/// Message operations use this type; key generation only needs [`LweEncryptionParameters`].
#[derive(Clone)]
pub struct LweParameters<T: FheUint, M: RingContext<T>> {
    encryption_parameters: LweEncryptionParameters<T, M>,
    plaintext_codec: RoundedCodec<T, M>,
}

impl<T: FheUint, M: RingContext<T>> LweParameters<T, M> {
    /// Creates a new [`LweParameters`].
    ///
    /// # Panics
    /// Panics on the encoding or sampler errors of [`Self::try_new`].
    #[must_use]
    pub fn new(
        dimension: LweDimension,
        plain_modulus_value: T,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        Self::try_new(
            dimension,
            plain_modulus_value,
            cipher_modulus,
            secret_key_distr,
            noise_standard_deviation,
        )
        .expect("invalid LWE parameters")
    }

    /// Checks message encoding, secret support/weight and coefficient noise.
    /// Successful construction does not establish security or a decryption margin.
    pub fn try_new(
        dimension: LweDimension,
        plain_modulus_value: T,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Result<Self, LweParameterError> {
        let plaintext_codec = RoundedCodec::try_new(plain_modulus_value, cipher_modulus)?;
        let encryption_parameters = LweEncryptionParameters::try_new(
            dimension,
            cipher_modulus,
            secret_key_distr,
            noise_standard_deviation,
        )?;
        Ok(Self {
            encryption_parameters,
            plaintext_codec,
        })
    }

    /// Returns the checked ciphertext domain and prepared samplers without a codec.
    #[must_use]
    #[inline]
    pub fn encryption_parameters(&self) -> &LweEncryptionParameters<T, M> {
        &self.encryption_parameters
    }

    /// Moves the sampling state out without cloning its tables.
    #[must_use]
    pub fn into_encryption_parameters(self) -> LweEncryptionParameters<T, M> {
        self.encryption_parameters
    }

    /// Returns the message modulus.
    #[must_use]
    #[inline]
    pub fn plain_modulus_value(&self) -> T {
        self.plaintext_codec.plaintext_modulus()
    }

    /// Returns the Rounded message codec.
    #[must_use]
    #[inline]
    pub fn plaintext_codec(&self) -> &RoundedCodec<T, M> {
        &self.plaintext_codec
    }

    /// Returns the dimension of this [`LweParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn dimension(&self) -> LweDimension {
        self.encryption_parameters.dimension()
    }

    /// Returns the cipher modulus of this [`LweParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn cipher_modulus(&self) -> M {
        self.encryption_parameters.cipher_modulus()
    }

    /// Returns the representable ciphertext modulus, or `None` for a native torus.
    #[must_use]
    #[inline]
    pub fn cipher_modulus_value(&self) -> Option<T> {
        self.encryption_parameters.cipher_modulus_value()
    }

    /// Returns the cipher modulus minus one of this [`LweParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.encryption_parameters.cipher_modulus_minus_one()
    }

    /// Returns the cipher modulus uniform distr of this [`LweParameters<T, M>`].
    #[must_use]
    pub fn cipher_modulus_uniform_distr(&self) -> Uniform<T> {
        self.encryption_parameters.cipher_modulus_uniform_distr()
    }

    /// Returns the secret key type of this [`LweParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.encryption_parameters.secret_key_distr()
    }

    /// Returns the noise standard deviation of this [`LweParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn noise_standard_deviation(&self) -> f64 {
        self.encryption_parameters.noise_standard_deviation()
    }

    /// Gets the discrete gaussian noise distribution.
    #[must_use]
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        self.encryption_parameters.noise_distribution()
    }
}
