use primus_distr::ErrorDistribution;
use primus_encoding::{BfvRnsCodec, BfvRnsCodecError, PlaintextEmbedding};
use primus_glwe_rns::{
    CrtGlweEncryptionParameters, CrtGlweEncryptionParametersError, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, GlweSize, GlweSizeError, RnsGlweSize};
use primus_modulus::BarrettModulus;
use primus_rns::{RNSBase, RnsError};
use primus_shape::PolyLength;
use std::sync::Arc;

pub(crate) const DEFAULT_DECODER_MODULUS: u64 = (1 << 61) - 1;

/// Invalid BFV geometry, codec, sampling state or fresh private recovery bound.
#[derive(Debug, thiserror::Error)]
pub enum BfvParametersError {
    /// A complete rank-one RNS storage length cannot be represented.
    #[error(transparent)]
    Layout(#[from] GlweSizeError),
    /// The supplied ciphertext moduli do not define a valid RNS basis.
    #[error("invalid BFV ciphertext RNS basis")]
    RnsBase(#[from] RnsError),
    /// Invalid codec parameters or insufficient fresh private recovery margin.
    #[error(transparent)]
    Encoding(#[from] BfvRnsCodecError<u64>),
    /// Invalid secret/error sampling preparation.
    #[error(transparent)]
    Encryption(#[from] CrtGlweEncryptionParametersError<u64>),
}

/// BFV coefficient parameters with rank-one `u64` RNS storage.
///
/// Clones share the prepared sampling state. The
/// codec owns the ordered Q basis and its encoding/decoding constants. Total Q
/// may exceed 64 bits; `u64` describes each residue, not the product modulus.
#[derive(Clone)]
pub struct BfvParameters {
    encryption_parameters: Arc<CrtGlweEncryptionParameters<u64>>,
    codec: BfvRnsCodec<u64, BarrettModulus<u64>>,
}

impl BfvParameters {
    /// Prepares coefficient parameters with the default decoder modulus.
    ///
    /// Uses the prime `gamma = 2^61 - 1`, so the ordinary coefficient workflow
    /// does not require an auxiliary-modulus choice. This requires `t < gamma`
    /// and the usual codec coprimality and recovery conditions. Use
    /// [`Self::try_with_decoder_modulus`] to choose a different modulus.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::try_with_decoder_modulus`].
    pub fn try_coefficients(
        poly_length: PolyLength,
        plain_modulus: BarrettModulus<u64>,
        cipher_moduli: &[BarrettModulus<u64>],
        secret_key_distr: SecretKeyDistr,
        error_distribution: ErrorDistribution,
    ) -> Result<Self, BfvParametersError> {
        Self::try_with_decoder_modulus(
            poly_length,
            plain_modulus,
            BarrettModulus::new(DEFAULT_DECODER_MODULUS),
            cipher_moduli,
            secret_key_distr,
            error_distribution,
        )
    }

    /// Prepares rank-one geometry, error sampling and the BFV codec with an explicit gamma.
    ///
    /// Checks the sufficient unsigned fresh private-key recovery bound, which
    /// also covers centered embedding. Public-key/evaluated noise requires its
    /// own complete bound. NTT tables and a security level are not established.
    ///
    /// # Errors
    /// Rejects invalid layout, RNS/codec parameters, sampling laws or insufficient
    /// recovery margin, preserving the underlying source error.
    pub fn try_with_decoder_modulus(
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
        codec.validate_noise_bound(
            sampling.noise_distribution().maximum_magnitude(),
            PlaintextEmbedding::Unsigned,
        )?;
        Ok(Self {
            encryption_parameters: Arc::new(sampling),
            codec,
        })
    }

    /// Returns prepared secret/error/uniform sampling state for explicit advanced use.
    #[must_use]
    pub fn encryption_parameters(&self) -> &CrtGlweEncryptionParameters<u64> {
        &self.encryption_parameters
    }

    /// Returns N.
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.size().poly_length()
    }

    /// Returns the unique ordered Q basis, including its arithmetic and size metadata.
    #[must_use]
    pub fn base_q(&self) -> &RNSBase<u64, BarrettModulus<u64>> {
        self.codec.base_q()
    }

    /// Returns the unique coefficient codec and its scaling/recovery constants.
    #[must_use]
    pub fn codec(&self) -> &BfvRnsCodec<u64, BarrettModulus<u64>> {
        &self.codec
    }

    /// Returns complete rank-one RNS geometry and derived storage lengths.
    #[must_use]
    pub fn size(&self) -> RnsGlweSize {
        self.encryption_parameters.size()
    }
}
