use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_reduce::RingContext;

use crate::{LweEncryptionParameters, LweParameterError};

/// Target LWE encryption state and decomposition for key switching at one modulus.
///
/// The target dimension, modulus and row-noise sampler come from `output`.
/// No message codec or source modulus is stored here. Ordinary LWE key switching
/// uses this modulus for both input and output; a caller such as NTRU return
/// performs any source-modulus conversion separately.
///
/// The input dimension comes from the actual input secret at key generation,
/// where the complete key storage length is checked.
#[derive(Clone)]
pub struct LweKeySwitchingParameters<T: FheUint, M: RingContext<T>> {
    output: LweEncryptionParameters<T, M>,
    basis: ApproxSignedBasis<T>,
}

impl<T: FheUint, M: RingContext<T>> LweKeySwitchingParameters<T, M> {
    /// Creates [`LweKeySwitchingParameters`] from prepared target state and basis.
    ///
    /// # Panics
    /// Panics if the basis and target ciphertext moduli differ.
    #[must_use]
    pub fn new(output: LweEncryptionParameters<T, M>, basis: ApproxSignedBasis<T>) -> Self {
        Self::try_new(output, basis).expect("invalid LWE key-switching parameters")
    }

    /// Moves prepared target state and basis without rebuilding sampler tables.
    /// Existing dimension, secret-support and sampling checks are not repeated.
    ///
    /// # Errors
    /// Returns [`LweParameterError::BasisModulusMismatch`] if the basis and target
    /// moduli differ, including native versus explicit representations.
    pub fn try_new(
        output: LweEncryptionParameters<T, M>,
        basis: ApproxSignedBasis<T>,
    ) -> Result<Self, LweParameterError> {
        if basis.modulus() != output.cipher_modulus_value() {
            return Err(LweParameterError::BasisModulusMismatch);
        }
        Ok(Self { output, basis })
    }

    /// Returns the target domain and sampler for encrypting each key entry.
    #[must_use]
    #[inline]
    pub fn output(&self) -> &LweEncryptionParameters<T, M> {
        &self.output
    }

    /// Returns the decomposition at the target ciphertext modulus.
    #[must_use]
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }
}
