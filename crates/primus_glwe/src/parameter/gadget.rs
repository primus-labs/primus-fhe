//! GLev/GGSW layouts and signed-decomposition basis.

use primus_decompose::{
    DecompositionConfig, DecompositionLevelCount, primitive::ApproxSignedBasis,
};
use primus_distr::DiscreteGaussian;
use primus_integer::FheUint;
use primus_lattice::{GadgetSize, GlweDimension, GlweSize};
use primus_reduce::RingContext;
use primus_shape::PolyLength;
use std::sync::Arc;

use super::{GlevParameterError, GlweEncryptionParameters, GlweParameters};

use crate::SecretKeyDistr;

/// GLWE parameters and decomposition basis shared by GLev and GGSW operations.
/// Owns the gadget layout and decomposition basis, and shares immutable modulus
/// and sampling state through `Arc`. No plaintext codec is needed. Ordinary and
/// gadget parameters may share that state when their encryption roles agree.
#[derive(Clone)]
pub struct GlevParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    size: GadgetSize,
    pub(super) encryption_parameters: Arc<GlweEncryptionParameters<T, M>>,
    /// Decompose basis for `Q`.
    basis: ApproxSignedBasis<T>,
}

impl<T, M> GlevParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates [`GlevParameters`] / [`GgswParameters`] in one ciphertext modulus domain.
    ///
    /// Prepares fresh sampling state and a signed decomposition basis, without a
    /// plaintext codec. Noise standard deviation is in coefficient units at
    /// `cipher_modulus`. The validated `glwe_size` supplies the complete secret length `kN`.
    /// This checks construction, not transform availability or a noise/security budget.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid noise or secret support, invalid decomposition,
    /// fixed secret weight exceeding `kN`, or gadget layout overflow.
    pub fn try_new(
        glwe_size: GlweSize,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        decomposition: DecompositionConfig,
        noise_standard_deviation: f64,
    ) -> Result<Self, GlevParameterError> {
        let encryption_parameters = GlweEncryptionParameters::try_new(
            cipher_modulus,
            secret_key_distr,
            noise_standard_deviation,
        )?;
        let basis = ApproxSignedBasis::try_from((decomposition, cipher_modulus.explicit_value()))?;
        encryption_parameters
            .secret_key_sampler()
            .validate_length(glwe_size.mask_len())?;
        // The basis was built in this encryption domain; only its combined
        // gadget layout remains to be checked after validating the secret length.
        Self::try_from_matching_parts(glwe_size, Arc::new(encryption_parameters), basis)
    }

    /// Binds a GLWE layout and prepared sampling state to a gadget basis.
    ///
    /// Takes ownership of the shared state and basis without rebuilding sampler
    /// tables or basis precomputation. The noise in `encryption_parameters` encrypts each gadget
    /// row; callers choose it for the intended evaluation-key role.
    ///
    /// # Errors
    ///
    /// Rejects a fixed secret weight exceeding the complete `kN` key length,
    /// a basis modulus mismatch (including native versus explicit), or gadget
    /// layout overflow. Modulus support and noise were checked by `encryption_parameters`.
    pub fn try_from_parts(
        glwe_size: GlweSize,
        encryption_parameters: Arc<GlweEncryptionParameters<T, M>>,
        basis: ApproxSignedBasis<T>,
    ) -> Result<Self, GlevParameterError> {
        if basis.modulus() != encryption_parameters.cipher_modulus_value() {
            return Err(GlevParameterError::BasisModulusMismatch);
        }
        encryption_parameters
            .secret_key_sampler()
            .validate_length(glwe_size.mask_len())?;
        Self::try_from_matching_parts(glwe_size, encryption_parameters, basis)
    }

    /// Derives only the new gadget layout. The caller has established matching
    /// basis/modulus and secret weight/layout pairs; sampler state is unchanged.
    fn try_from_matching_parts(
        glwe_size: GlweSize,
        encryption_parameters: Arc<GlweEncryptionParameters<T, M>>,
        basis: ApproxSignedBasis<T>,
    ) -> Result<Self, GlevParameterError> {
        Ok(Self {
            size: GadgetSize::try_new(glwe_size, basis.level_count())?,
            encryption_parameters,
            basis,
        })
    }

    /// Reuses a precomputed decomposition basis with matching GLWE parameters.
    ///
    /// Takes ownership of the basis, preserving its levels and precomputation,
    /// and shares the source parameters' prepared samplers without copying them.
    /// Both native (`None`) and explicit modulus representations must match.
    /// The unchanged secret weight/layout pairing is inherited from `glwe_params`.
    ///
    /// # Errors
    ///
    /// Returns an error on a basis modulus mismatch or gadget layout overflow.
    pub fn try_with_basis(
        glwe_params: &GlweParameters<T, M>,
        basis: ApproxSignedBasis<T>,
    ) -> Result<Self, GlevParameterError> {
        if basis.modulus() != glwe_params.cipher_modulus().explicit_value() {
            return Err(GlevParameterError::BasisModulusMismatch);
        }
        Self::try_from_matching_parts(
            glwe_params.size(),
            Arc::clone(&glwe_params.encryption_parameters),
            basis,
        )
    }

    /// Derives gadget parameters with a new basis, preserving the GLWE layout.
    ///
    /// Shares the existing immutable modulus and sampler state through `Arc`;
    /// does not copy sampler tables or the old basis, or convert ciphertexts.
    /// Each encryption still draws fresh randomness from its supplied RNG.
    ///
    /// # Errors
    /// Rejects a basis modulus mismatch or gadget layout overflow.
    pub fn try_with_new_basis(
        &self,
        basis: ApproxSignedBasis<T>,
    ) -> Result<Self, GlevParameterError> {
        if basis.modulus() != self.basis.modulus() {
            return Err(GlevParameterError::BasisModulusMismatch);
        }
        // Only the basis changes: secret weight was already checked against
        // this unchanged GLWE layout when the source parameters were built.
        Self::try_from_matching_parts(
            self.glwe_size(),
            Arc::clone(&self.encryption_parameters),
            basis,
        )
    }

    /// Creates GLev/GGSW parameters from matching GLWE parameters.
    ///
    /// # Panics
    ///
    /// Panics on invalid basis parameters or gadget layout overflow.
    #[must_use]
    #[inline]
    pub fn with_glwe_params(
        glwe_params: &GlweParameters<T, M>,
        decomposition: DecompositionConfig,
    ) -> Self {
        Self::try_with_glwe_params(glwe_params, decomposition)
            .unwrap_or_else(|message| panic!("failed to construct GLev parameters: {message}"))
    }

    /// Tries to create GLev/GGSW parameters and their decomposition basis from
    /// one GLWE modulus domain.
    /// Reuses the checked secret weight/layout pairing; only the new basis and
    /// gadget layout are validated.
    ///
    /// # Errors
    ///
    /// Returns an error on invalid basis parameters or gadget layout overflow.
    #[inline]
    pub fn try_with_glwe_params(
        glwe_params: &GlweParameters<T, M>,
        decomposition: DecompositionConfig,
    ) -> Result<Self, GlevParameterError> {
        let basis =
            ApproxSignedBasis::try_from((decomposition, glwe_params.cipher_modulus_value()))?;
        Self::try_from_matching_parts(
            glwe_params.size(),
            Arc::clone(&glwe_params.encryption_parameters),
            basis,
        )
    }

    /// Returns the parameters shared by GLWE and its gadget ciphertexts.
    #[inline]
    pub fn encryption_parameters(&self) -> &GlweEncryptionParameters<T, M> {
        self.encryption_parameters.as_ref()
    }

    /// Returns the pre-computed GLev/GGSW size constants.
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.size
    }

    /// Returns the underlying GLWE size constants.
    #[inline]
    pub fn glwe_size(&self) -> GlweSize {
        self.size.glwe_size()
    }

    /// Returns the dimension of this [`GlevParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn dimension(&self) -> GlweDimension {
        self.size.glwe_size().dimension()
    }

    /// Returns the poly length of this [`GlevParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.size.glwe_size().poly_length()
    }

    /// Returns the cipher modulus minus one of this [`GlevParameters<T, M>`].
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.encryption_parameters.cipher_modulus_minus_one()
    }

    /// Returns the modulus of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn cipher_modulus(&self) -> M {
        self.encryption_parameters.cipher_modulus()
    }

    /// Returns the secret key type of this [`GlevParameters<T, M>`].
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.encryption_parameters.secret_key_distr()
    }

    /// Returns a reference to the noise distribution of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        self.encryption_parameters.noise_distribution()
    }

    /// Returns the noise standard deviation of this [`GlevParameters<T, M>`].
    pub fn noise_standard_deviation(&self) -> f64 {
        self.encryption_parameters
            .noise_distribution()
            .standard_deviation()
    }

    /// Returns a reference to the basis of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the number of retained decomposition levels.
    #[must_use]
    #[inline]
    pub fn level_count(&self) -> DecompositionLevelCount {
        self.size.level_count()
    }

    /// Returns the number of values in one coefficient/NTT-domain GLWE ciphertext.
    #[inline]
    pub fn glwe_len(&self) -> usize {
        self.size.glwe_size().glwe_len()
    }

    /// Returns the number of values in one coefficient/NTT-domain GLev ciphertext.
    #[inline]
    pub fn glev_len(&self) -> usize {
        self.size.glev_len()
    }

    /// Returns the number of values in one coefficient/NTT-domain GGSW ciphertext.
    #[inline]
    pub fn ggsw_len(&self) -> usize {
        self.size.ggsw_len()
    }

    /// Returns the number of complex values in one Fourier-domain GLWE ciphertext.
    #[inline]
    pub fn fourier_glwe_len(&self) -> usize {
        self.size.glwe_size().fourier_glwe_len()
    }

    /// Returns the number of complex values in one Fourier-domain GLev ciphertext.
    #[inline]
    pub fn fourier_glev_len(&self) -> usize {
        self.size.fourier_glev_len()
    }

    /// Returns the number of complex values in one Fourier-domain GGSW ciphertext.
    #[inline]
    pub fn fourier_ggsw_len(&self) -> usize {
        self.size.fourier_ggsw_len()
    }
}

/// GGSW parameters share the GLWE domain and gadget layout of [`GlevParameters`].
pub type GgswParameters<T, M> = GlevParameters<T, M>;
