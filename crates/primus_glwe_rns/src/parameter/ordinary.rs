//! Ordinary CRT GLWE parameters and BFV plaintext scaling/recovery.

use primus_distr::{SecretKeySampler, SignedDiscreteGaussian};
use primus_encoding::PlaintextEmbedding;
use primus_factor::ShoupFactor;
use primus_integer::{BigUint, FheUint};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_reduce::FieldContext;
use primus_rns::{RNSBase, ResidueFactors};
use primus_shape::PolyLength;
use rand::distr::Uniform;
use std::sync::Arc;

use super::{CrtGlweParametersError, core::CrtGlweEncryptionParameters};
use crate::{BfvRnsCodec, SecretKeyDistr};

/// Ordinary CRT GLWE parameters with a BFV plaintext codec.
///
/// Construction checks layout, ordered RNS moduli, encoding, fixed secret
/// weights and the supported secret/noise magnitudes. It also establishes a
/// sufficient recovery bound for fresh private-key plaintext encryption under
/// either embedding. The immutable sampling state is reused by gadget parameters;
/// the codec and its scaling stay here.
#[derive(Clone)]
pub struct CrtGlweParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    pub(super) encryption_parameters: Arc<CrtGlweEncryptionParameters<T>>,
    codec: BfvRnsCodec<T, M>,
}

impl<T, M> CrtGlweParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Creates a new [`CrtGlweParameters<T, M>`].
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_new`] rejects layout, RNS/encoding or sampling
    /// parameters, including fixed weights exceeding the complete kN key length
    /// or insufficient fresh private-key plaintext recovery margin.
    #[must_use]
    pub fn new(
        dimension: GlweDimension,
        poly_length: PolyLength,
        plain_modulus: M,
        gamma_modulus: M,
        cipher_moduli: &[M],
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        Self::try_new(
            dimension,
            poly_length,
            plain_modulus,
            gamma_modulus,
            cipher_moduli,
            secret_key_distr,
            noise_standard_deviation,
        )
        .expect("invalid CRT GLWE parameters")
    }

    /// Creates a [`CrtGlweParameters<T, M>`] with checked layout, encoding and sampling.
    ///
    /// Fixed weights apply to all kN signed secret coefficients, not per polynomial
    /// or RNS limb. Every supported secret and noise magnitude must be strictly
    /// smaller than each ciphertext modulus. Noise deviation is in coefficient units.
    /// The truncated noise support must satisfy [`BfvRnsCodec::validate_noise_bound`]
    /// for unsigned lifting, which also covers centered lifting. This guarantees
    /// recovery for fresh private-key plaintext encryption; public-key and
    /// homomorphic-operation noise need their own bounds. No NTT table or security
    /// level is established here.
    ///
    /// # Correctness
    ///
    /// Encoding inherits [`BfvRnsCodec::try_new`]'s arithmetic-context requirements.
    ///
    /// # Errors
    ///
    /// Returns [`CrtGlweParametersError`] for invalid layout, RNS/encoding or
    /// secret/noise sampling parameters, preserving the underlying reason.
    pub fn try_new(
        dimension: GlweDimension,
        poly_length: PolyLength,
        plain_modulus: M,
        gamma_modulus: M,
        cipher_moduli: &[M],
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Result<Self, CrtGlweParametersError<T>> {
        let glwe_size = GlweSize::try_new(dimension, poly_length)?;
        let base_q = RNSBase::new(cipher_moduli)?;
        let size = RnsGlweSize::try_new(glwe_size, base_q.moduli_count())?;
        let codec = BfvRnsCodec::try_new(plain_modulus, base_q, gamma_modulus)?;
        let encryption_parameters = CrtGlweEncryptionParameters::try_new(
            size,
            codec.base_q(),
            secret_key_distr,
            noise_standard_deviation,
        )?;
        Self::try_from_matching_parts(Arc::new(encryption_parameters), codec)
    }

    /// Binds prepared layout/samplers to ordinary BFV encoding without rebuilding them.
    /// The codec owns its ordered Q base and conversion precomputation.
    ///
    /// # Errors
    /// Rejects a different modulus count/order or insufficient recovery margin
    /// for the complete fresh private-key noise support. The unsigned bound also
    /// covers centered lifting; public-key and evaluation noise need their own bounds.
    pub fn try_from_parts(
        encryption_parameters: Arc<CrtGlweEncryptionParameters<T>>,
        codec: BfvRnsCodec<T, M>,
    ) -> Result<Self, CrtGlweParametersError<T>> {
        encryption_parameters.validate_base(codec.base_q())?;
        Self::try_from_matching_parts(encryption_parameters, codec)
    }

    /// The ordered base matches by construction or by the public parts check.
    /// Fresh BFV recovery is a new codec/noise condition and still needs checking.
    fn try_from_matching_parts(
        encryption_parameters: Arc<CrtGlweEncryptionParameters<T>>,
        codec: BfvRnsCodec<T, M>,
    ) -> Result<Self, CrtGlweParametersError<T>> {
        // Every modulus already contains the signed support, so the magnitude
        // fits T. For private-key plaintext encryption it bounds the phase noise.
        let maximum_noise_magnitude =
            T::as_from(encryption_parameters.noise_distribution.maximum_magnitude());
        codec.validate_noise_bound(maximum_noise_magnitude, PlaintextEmbedding::Unsigned)?;
        Ok(Self {
            encryption_parameters,
            codec,
        })
    }

    /// Returns the shared layout and sampling state, without BFV encoding.
    #[must_use]
    #[inline]
    pub fn encryption_parameters(&self) -> &CrtGlweEncryptionParameters<T> {
        &self.encryption_parameters
    }

    /// Returns the dimension of this [`CrtGlweParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn dimension(&self) -> GlweDimension {
        self.encryption_parameters.size.dimension()
    }

    /// Returns the poly length of this [`CrtGlweParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.encryption_parameters.size.poly_length()
    }

    /// Returns the plain modulus value of this [`CrtGlweParameters<T, M>`].
    pub fn plain_modulus_value(&self) -> T {
        self.codec.t()
    }

    /// Returns a reference to the cipher modulus of this [`CrtGlweParameters<T, M>`].
    pub fn cipher_modulus(&self) -> BigUint<&[T]> {
        self.codec.base_q().moduli_product()
    }

    /// Returns a reference to the modulus minus one of this [`CrtGlweParameters<T, M>`].
    pub fn cipher_modulus_minus_one(&self) -> BigUint<&[T]> {
        self.encryption_parameters.cipher_modulus_minus_one.view()
    }

    /// Returns a reference to the moduli of this [`CrtGlweParameters<T, M>`].
    #[inline]
    pub fn cipher_moduli(&self) -> &[M] {
        self.codec.base_q().moduli()
    }

    /// Returns a reference to the cipher moduli value of this [`CrtGlweParameters<T, M>`].
    pub fn cipher_moduli_value(&self) -> &[T] {
        self.codec.moduli_values()
    }

    /// Returns a reference to the cipher moduli minus one of this [`CrtGlweParameters<T, M>`].
    pub fn cipher_moduli_minus_one(&self) -> &[T] {
        &self.encryption_parameters.cipher_moduli_minus_one
    }

    /// Returns the moduli count of this [`CrtGlweParameters<T, M>`].
    pub fn cipher_moduli_count(&self) -> usize {
        self.codec.moduli_count()
    }

    /// Returns a reference to the cipher moduli uniform distr of this [`CrtGlweParameters<T, M>`].
    pub fn cipher_moduli_uniform_distr(&self) -> &[Uniform<T>] {
        &self.encryption_parameters.cipher_moduli_uniform_distr
    }

    /// Returns the big uint value len of this [`CrtGlweParameters<T, M>`].
    #[inline]
    pub fn big_uint_value_len(&self) -> usize {
        self.codec.base_q().big_uint_value_len()
    }

    /// Returns the secret key type of this [`CrtGlweParameters<T, M>`].
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.encryption_parameters.secret_key_sampler.distr()
    }

    /// Returns shared precomputation for coefficient secret-key generation.
    #[must_use]
    #[inline]
    pub fn secret_key_sampler(&self) -> &SecretKeySampler<T> {
        &self.encryption_parameters.secret_key_sampler
    }

    /// Returns a reference to the noise distribution of this [`CrtGlweParameters<T, M>`].
    pub fn noise_distribution(&self) -> &SignedDiscreteGaussian<T::SignedInteger> {
        &self.encryption_parameters.noise_distribution
    }

    /// Returns the noise standard deviation of this [`CrtGlweParameters<T, M>`].
    pub fn noise_standard_deviation(&self) -> f64 {
        self.encryption_parameters
            .noise_distribution
            .standard_deviation()
    }

    /// Returns a reference to the delta of this [`CrtGlweParameters<T, M>`].
    pub fn delta(&self) -> BigUint<&[T]> {
        self.codec.delta()
    }

    /// Returns a reference to the delta residues of this [`CrtGlweParameters<T, M>`].
    pub fn delta_factor_mod_q(&self) -> ResidueFactors<&[ShoupFactor<T>]> {
        self.codec.delta_factor_mod_q()
    }

    /// Returns the ordered ciphertext RNS basis Q.
    pub fn base_q(&self) -> &RNSBase<T, M> {
        self.codec.base_q()
    }

    /// Returns the plaintext coefficient codec bound to this RNS basis.
    pub fn codec(&self) -> &BfvRnsCodec<T, M> {
        &self.codec
    }

    /// Returns the cached RNS GLWE layout.
    pub fn size(&self) -> RnsGlweSize {
        self.encryption_parameters.size
    }

    /// Returns the limb length of one polynomial in big-integer representation.
    pub fn big_uint_poly_len(&self) -> usize {
        self.poly_length().get() * self.big_uint_value_len()
    }

    /// Returns the coefficient count of one RNS polynomial.
    pub fn rns_poly_len(&self) -> usize {
        self.encryption_parameters.size.rns_poly_len()
    }

    /// Returns the coefficient count of one RNS GLWE ciphertext.
    pub fn rns_glwe_len(&self) -> usize {
        self.encryption_parameters.size.rns_glwe_len()
    }

    /// Returns the coefficient count of the RNS secret-key mask.
    pub fn secret_key_len(&self) -> usize {
        self.encryption_parameters.size.rns_mask_len()
    }

    /// Returns the underlying single-modulus GLWE layout.
    pub fn glwe_size(&self) -> GlweSize {
        self.encryption_parameters.size.glwe_size()
    }
}
