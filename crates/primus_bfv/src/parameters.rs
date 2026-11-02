use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_distr::{ErrorDistribution, ErrorSampler, SecretKeySampler};
use primus_encoding::{BfvRnsCodec, BfvRnsCodecError, PlaintextEmbedding};
use primus_factor::ShoupFactor;
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlevParametersError, CrtGlweEncryptionParameters,
    CrtGlweEncryptionParametersError, RnsDomainError, SecretKeyDistr,
};
use primus_integer::BigUint;
use primus_lattice::{GlweDimension, GlweSize, GlweSizeError, RnsGlweSize};
use primus_modulus::BarrettModulus;
use primus_rns::{RNSBase, ResidueFactors, RnsError};
use primus_shape::PolyLength;
use rand::distr::Uniform;
use std::sync::Arc;

/// Invalid BFV geometry, codec, sampling state or fresh private recovery bound.
#[derive(Debug, thiserror::Error)]
pub enum BfvParametersError {
    /// A complete rank-one RNS storage length cannot be represented.
    #[error(transparent)]
    Layout(#[from] GlweSizeError),
    /// The supplied ciphertext moduli do not define a valid RNS basis.
    #[error("invalid BFV ciphertext RNS basis")]
    RnsBase(#[from] RnsError),
    /// Sampling state uses a different ordered basis or a rank other than one.
    #[error(transparent)]
    Domain(#[from] RnsDomainError<u64>),
    /// Invalid codec parameters or insufficient fresh private recovery margin.
    #[error(transparent)]
    Encoding(#[from] BfvRnsCodecError<u64>),
    /// Invalid secret/error sampling preparation.
    #[error(transparent)]
    Encryption(#[from] CrtGlweEncryptionParametersError<u64>),
}

/// BFV coefficient parameters with rank-one `u64` RNS storage.
///
/// Immutable layout/samplers are shared with derived gadget parameters. The
/// codec owns the ordered Q basis and its encoding/decoding constants. Total Q
/// may exceed 64 bits; `u64` describes each residue, not the product modulus.
#[derive(Clone)]
pub struct BfvParameters {
    encryption_parameters: Arc<CrtGlweEncryptionParameters<u64>>,
    codec: BfvRnsCodec<u64, BarrettModulus<u64>>,
}

impl BfvParameters {
    /// Prepares Gaussian BFV parameters, panicking on [`Self::try_new`]'s errors.
    #[must_use]
    pub fn new(
        poly_length: PolyLength,
        plain_modulus: BarrettModulus<u64>,
        gamma_modulus: BarrettModulus<u64>,
        cipher_moduli: &[BarrettModulus<u64>],
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        Self::try_new(
            poly_length,
            plain_modulus,
            gamma_modulus,
            cipher_moduli,
            secret_key_distr,
            noise_standard_deviation,
        )
        .expect("invalid BFV parameters")
    }

    /// Prepares rank-one geometry, Gaussian error sampling and the BFV codec.
    ///
    /// Checks the sufficient unsigned fresh private-key recovery bound, which
    /// also covers centered embedding. Public-key/evaluated noise requires its
    /// own complete bound. NTT tables and a security level are not established.
    ///
    /// # Errors
    /// Rejects invalid layout, RNS/codec parameters, sampling laws or insufficient
    /// recovery margin, preserving the underlying source error.
    pub fn try_new(
        poly_length: PolyLength,
        plain_modulus: BarrettModulus<u64>,
        gamma_modulus: BarrettModulus<u64>,
        cipher_moduli: &[BarrettModulus<u64>],
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Result<Self, BfvParametersError> {
        Self::try_with_error_distribution(
            poly_length,
            plain_modulus,
            gamma_modulus,
            cipher_moduli,
            secret_key_distr,
            ErrorDistribution::Gaussian {
                standard_deviation: noise_standard_deviation,
            },
        )
    }

    /// Prepares BFV parameters with an explicit Gaussian or exact CBD error law.
    /// The same fresh private recovery condition as [`Self::try_new`] applies.
    ///
    /// # Errors
    /// Returns the corresponding layout, basis, codec, sampler or recovery error.
    pub fn try_with_error_distribution(
        poly_length: PolyLength,
        plain_modulus: BarrettModulus<u64>,
        gamma_modulus: BarrettModulus<u64>,
        cipher_moduli: &[BarrettModulus<u64>],
        secret_key_distr: SecretKeyDistr,
        error_distribution: ErrorDistribution,
    ) -> Result<Self, BfvParametersError> {
        let glwe_size = GlweSize::try_new(GlweDimension::new(1), poly_length)?;
        let base_q = RNSBase::new(cipher_moduli)?;
        let size = RnsGlweSize::try_new(glwe_size, base_q.moduli_count())?;
        let codec = BfvRnsCodec::try_new(plain_modulus, base_q, gamma_modulus)?;
        let sampling = CrtGlweEncryptionParameters::try_with_error_distribution(
            size,
            codec.base_q(),
            secret_key_distr,
            error_distribution,
        )?;
        Self::from_matching_parts(Arc::new(sampling), codec)
    }

    /// Combines independently prepared codec-free state and the unique codec.
    ///
    /// # Errors
    /// Rejects non-rank-one geometry, a different ordered Q basis or insufficient
    /// fresh private recovery margin. No samplers or base tables are rebuilt.
    pub fn try_from_parts(
        encryption_parameters: Arc<CrtGlweEncryptionParameters<u64>>,
        codec: BfvRnsCodec<u64, BarrettModulus<u64>>,
    ) -> Result<Self, BfvParametersError> {
        let rank = encryption_parameters.size().dimension().get();
        if rank != 1 {
            return Err(RnsDomainError::DimensionMismatch {
                expected: 1,
                actual: rank,
            }
            .into());
        }
        encryption_parameters.validate_base(codec.base_q())?;
        Self::from_matching_parts(encryption_parameters, codec)
    }

    fn from_matching_parts(
        encryption_parameters: Arc<CrtGlweEncryptionParameters<u64>>,
        codec: BfvRnsCodec<u64, BarrettModulus<u64>>,
    ) -> Result<Self, BfvParametersError> {
        codec.validate_noise_bound(
            encryption_parameters
                .noise_distribution()
                .maximum_magnitude(),
            PlaintextEmbedding::Unsigned,
        )?;
        Ok(Self {
            encryption_parameters,
            codec,
        })
    }

    /// Derives codec-free gadget parameters sharing these immutable samplers.
    ///
    /// # Panics
    /// Panics if [`Self::try_gadget_parameters`] rejects the decomposition.
    #[must_use]
    pub fn gadget_parameters(
        &self,
        log_basis: DecompositionBaseLog,
        level_count: Option<DecompositionLevelCount>,
    ) -> CrtGlevParameters<u64, BarrettModulus<u64>> {
        self.try_gadget_parameters(log_basis, level_count)
            .expect("invalid BFV gadget parameters")
    }

    /// Derives gadget layout and weights without cloning codec/sampling tables.
    ///
    /// # Errors
    /// Rejects invalid decomposition or radix/size conditions of
    /// [`CrtGlevParameters::try_new`].
    pub fn try_gadget_parameters(
        &self,
        log_basis: DecompositionBaseLog,
        level_count: Option<DecompositionLevelCount>,
    ) -> Result<CrtGlevParameters<u64, BarrettModulus<u64>>, CrtGlevParametersError<u64>> {
        CrtGlevParameters::try_new(
            Arc::clone(&self.encryption_parameters),
            self.base_q().clone(),
            log_basis,
            level_count,
        )
    }

    /// Returns shared codec-free layout and sampling state.
    #[must_use]
    pub fn encryption_parameters(&self) -> &CrtGlweEncryptionParameters<u64> {
        &self.encryption_parameters
    }

    /// Returns the fixed rank-one GLWE dimension.
    #[must_use]
    pub fn dimension(&self) -> GlweDimension {
        self.size().dimension()
    }

    /// Returns N.
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.size().poly_length()
    }

    /// Returns t.
    #[must_use]
    pub fn plain_modulus_value(&self) -> u64 {
        self.codec.t()
    }

    /// Returns the multi-limb product Q.
    #[must_use]
    pub fn cipher_modulus(&self) -> BigUint<&[u64]> {
        self.base_q().moduli_product()
    }

    /// Returns the ordered Q arithmetic contexts.
    #[must_use]
    pub fn cipher_moduli(&self) -> &[BarrettModulus<u64>] {
        self.base_q().moduli()
    }

    /// Returns the ordered q_i values.
    #[must_use]
    pub fn cipher_moduli_value(&self) -> &[u64] {
        self.codec.moduli_values()
    }

    /// Returns q_i-1 in sampler order.
    #[must_use]
    pub fn cipher_moduli_minus_one(&self) -> &[u64] {
        self.encryption_parameters.cipher_moduli_minus_one()
    }

    /// Returns the number of RNS limbs.
    #[must_use]
    pub fn cipher_moduli_count(&self) -> usize {
        self.codec.moduli_count()
    }

    /// Returns prepared uniform mask samplers in Q order.
    #[must_use]
    pub fn cipher_moduli_uniform_distr(&self) -> &[Uniform<u64>] {
        self.encryption_parameters.cipher_moduli_uniform_distr()
    }

    /// Returns the fixed-width limb count used for big-integer coefficients.
    #[must_use]
    pub fn big_uint_value_len(&self) -> usize {
        self.base_q().big_uint_value_len()
    }

    /// Returns the configured coefficient secret law.
    #[must_use]
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.encryption_parameters.secret_key_distr()
    }

    /// Returns prepared coefficient secret sampling state.
    #[must_use]
    pub fn secret_key_sampler(&self) -> &SecretKeySampler<u64> {
        self.encryption_parameters.secret_key_sampler()
    }

    /// Returns the actual error law and its complete support bound.
    #[must_use]
    pub fn noise_distribution(&self) -> &ErrorSampler<u64> {
        self.encryption_parameters.noise_distribution()
    }

    /// Returns Gaussian scale or the exact CBD standard deviation sqrt(eta/2).
    #[must_use]
    pub fn noise_standard_deviation(&self) -> f64 {
        self.noise_distribution().standard_deviation()
    }

    /// Returns delta=floor(Q/t).
    #[must_use]
    pub fn delta(&self) -> BigUint<&[u64]> {
        self.codec.delta()
    }

    /// Returns prepared delta multiplication factors in Q order.
    #[must_use]
    pub fn delta_factor_mod_q(&self) -> ResidueFactors<&[ShoupFactor<u64>]> {
        self.codec.delta_factor_mod_q()
    }

    /// Returns the immutable ordered Q basis.
    #[must_use]
    pub fn base_q(&self) -> &RNSBase<u64, BarrettModulus<u64>> {
        self.codec.base_q()
    }

    /// Returns the unique coefficient codec, including advanced CRT operations.
    #[must_use]
    pub fn codec(&self) -> &BfvRnsCodec<u64, BarrettModulus<u64>> {
        &self.codec
    }

    /// Returns complete rank-one RNS geometry.
    #[must_use]
    pub fn size(&self) -> RnsGlweSize {
        self.encryption_parameters.size()
    }

    /// Returns the number of limbs in a big-integer polynomial.
    #[must_use]
    pub fn big_uint_poly_len(&self) -> usize {
        self.poly_length().get() * self.big_uint_value_len()
    }

    /// Returns N times the Q limb count.
    #[must_use]
    pub fn rns_poly_len(&self) -> usize {
        self.size().rns_poly_len()
    }

    /// Returns the complete DCRT ciphertext length.
    #[must_use]
    pub fn rns_glwe_len(&self) -> usize {
        self.size().rns_glwe_len()
    }

    /// Returns the DCRT secret storage length.
    #[must_use]
    pub fn secret_key_len(&self) -> usize {
        self.size().rns_mask_len()
    }

    /// Returns the rank-one single-modulus geometry.
    #[must_use]
    pub fn glwe_size(&self) -> GlweSize {
        self.size().glwe_size()
    }
}
