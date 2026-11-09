//! NLev/NGSW layouts and approximate signed-decomposition basis.

use super::{NlevParameterError, NtruEncryptionParameters, NtruParameters};
use primus_decompose::{
    DecompositionConfig, DecompositionLevelCount, primitive::ApproxSignedBasis,
};
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_shape::PolyLength;
use std::sync::Arc;

/// Parameters for NLev and NGSW ciphertexts in one NTRU modulus domain.
///
/// This type binds shared ring/sampling state, without a plaintext codec, to the
/// approximate signed decomposition basis used by a gadget operation. Create
/// separate values when key switching, bootstrapping, or another operation
/// uses different decomposition parameters.
#[derive(Clone)]
pub struct NlevParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    pub(super) encryption_parameters: Arc<NtruEncryptionParameters<T, M>>,
    basis: ApproxSignedBasis<T>,
    nlev_len: usize,
}

impl<T, M> NlevParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Binds shared NTRU ring/sampling state to an owned gadget basis, without a codec.
    /// The state's noise encrypts gadget rows. Different noise distributions need
    /// their own prepared state; identical ring/sampling parameters can share it
    /// through Arc across key roles, without sharing random draws.
    ///
    /// # Errors
    /// Rejects a different explicit/native basis modulus or an overflowing N*L
    /// ciphertext length. Secret support/weight and noise are already validated.
    pub fn try_from_parts(
        encryption_parameters: Arc<NtruEncryptionParameters<T, M>>,
        basis: ApproxSignedBasis<T>,
    ) -> Result<Self, NlevParameterError> {
        if basis.modulus() != encryption_parameters.cipher_modulus_value() {
            return Err(NlevParameterError::BasisModulusMismatch);
        }
        Self::try_from_matching_parts(encryption_parameters, basis)
    }

    /// Derives N*L after the caller establishes the basis modulus, either from
    /// the same ring's basis constructor or by checking an independent basis.
    fn try_from_matching_parts(
        encryption_parameters: Arc<NtruEncryptionParameters<T, M>>,
        basis: ApproxSignedBasis<T>,
    ) -> Result<Self, NlevParameterError> {
        let nlev_len = basis
            .level_count()
            .get()
            .checked_mul(encryption_parameters.poly_length().get())
            .ok_or(NlevParameterError::CiphertextLengthOverflow)?;
        Ok(Self {
            encryption_parameters,
            basis,
            nlev_len,
        })
    }

    /// Reuses an owned basis and shares the ordinary parameters' sampler tables.
    /// Does not inspect or retain their plaintext codec.
    ///
    /// # Errors
    /// Inherits [`Self::try_from_parts`]'s modulus and layout errors.
    pub fn try_with_basis(
        ntru: &NtruParameters<T, M>,
        basis: ApproxSignedBasis<T>,
    ) -> Result<Self, NlevParameterError> {
        Self::try_from_parts(Arc::clone(&ntru.encryption_parameters), basis)
    }

    /// Derives gadget parameters with a new basis, preserving the NTRU ring.
    ///
    /// Shares the existing immutable ring and sampler state through `Arc`;
    /// does not copy sampler tables or the old basis, or convert ciphertexts.
    /// Each encryption still draws fresh randomness from its supplied RNG.
    ///
    /// # Errors
    /// Rejects a basis modulus mismatch or an overflowing N*L ciphertext length.
    pub fn try_with_new_basis(
        &self,
        basis: ApproxSignedBasis<T>,
    ) -> Result<Self, NlevParameterError> {
        Self::try_from_parts(Arc::clone(&self.encryption_parameters), basis)
    }

    /// Creates NLev/NGSW parameters from matching NTRU parameters.
    ///
    /// Shares the ordinary parameters' sampler tables; only the new decomposition
    /// and gadget layout are validated. No plaintext codec is retained.
    ///
    /// # Panics
    ///
    /// Panics if the decomposition parameters are invalid for the NTRU
    /// ciphertext modulus, or the ciphertext layout overflows usize.
    #[must_use]
    #[inline]
    pub fn with_ntru_params(
        ntru: &NtruParameters<T, M>,
        decomposition: DecompositionConfig,
    ) -> Self {
        Self::try_with_ntru_params(ntru, decomposition)
            .unwrap_or_else(|error| panic!("failed to construct NLev parameters: {error}"))
    }

    /// Tries to create NLev/NGSW parameters and their decomposition basis in
    /// the modulus domain of `ntru`.
    ///
    /// # Errors
    /// Rejects invalid decomposition parameters or an overflowing N*L layout.
    pub fn try_with_ntru_params(
        ntru: &NtruParameters<T, M>,
        decomposition: DecompositionConfig,
    ) -> Result<Self, NlevParameterError> {
        let basis = ApproxSignedBasis::try_from((decomposition, ntru.cipher_modulus_value()))?;
        Self::try_from_matching_parts(Arc::clone(&ntru.encryption_parameters), basis)
    }

    /// Returns the shared ring and sampling state, without ordinary message encoding.
    #[must_use]
    #[inline]
    pub fn encryption_parameters(&self) -> &NtruEncryptionParameters<T, M> {
        &self.encryption_parameters
    }

    /// Returns the approximate signed decomposition basis.
    #[must_use]
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the polynomial length `N`.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.encryption_parameters.poly_length()
    }

    /// Returns the number of retained decomposition levels.
    #[must_use]
    #[inline]
    pub fn level_count(&self) -> DecompositionLevelCount {
        self.basis.level_count()
    }

    /// Returns the number of coefficient or NTT values in an NLev/NGSW
    /// ciphertext.
    #[must_use]
    #[inline]
    pub fn nlev_len(&self) -> usize {
        self.nlev_len
    }

    /// Returns the number of complex values in a Fourier NLev/NGSW
    /// ciphertext.
    #[must_use]
    #[inline]
    pub fn fourier_nlev_len(&self) -> usize {
        self.nlev_len >> 1
    }
}
