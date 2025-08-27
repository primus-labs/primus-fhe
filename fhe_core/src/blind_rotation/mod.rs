mod binary;
mod ternary;

use std::sync::Arc;

use algebra::{
    decompose::NonPowOf2ApproxSignedBasis, integer::UnsignedInteger, polynomial::FieldPolynomial,
    random::DiscreteGaussian, utils::Size, Field, NttField,
};
pub use binary::BinaryBlindRotationKey;
use rand::{CryptoRng, Rng};
pub use ternary::TernaryBlindRotationKey;

use crate::{LweCiphertext, LweSecretKey, LweSecretKeyType, NttRlweSecretKey, RlweCiphertext};

/// Blind rotation key.
///
/// In FHE, bootstrapping is a technique used to refresh the ciphertexts
/// during the homomorphic computation. As homomorphic operations are
/// performed on encrypted data, the noise in the ciphertext increases,
/// and if left unchecked, it can eventually lead to decryption errors.
/// Bootstrapping is a method to reduce the noise and refresh the
/// ciphertexts, allowing the computation to continue.
#[derive(Clone)]
pub enum BlindRotationKey<F: NttField> {
    /// FHE binary blind rotation key
    Binary(BinaryBlindRotationKey<F>),
    /// FHE ternary blind rotation key
    Ternary(TernaryBlindRotationKey<F>),
}

impl<F: NttField> Size for BlindRotationKey<F> {
    #[inline]
    fn size(&self) -> usize {
        match self {
            BlindRotationKey::Binary(key) => key.size(),
            BlindRotationKey::Ternary(key) => key.size(),
        }
    }
}

impl<F: NttField> BlindRotationKey<F> {
    /// Creates the binary blind rotation key.
    #[inline]
    pub fn binary(key: BinaryBlindRotationKey<F>) -> Self {
        Self::Binary(key)
    }

    /// Creates the ternary blind rotation key.
    #[inline]
    pub fn ternary(key: TernaryBlindRotationKey<F>) -> Self {
        Self::Ternary(key)
    }

    /// Returns the NTT table.
    #[inline]
    pub fn ntt_table(&self) -> &<F as NttField>::Table {
        match self {
            BlindRotationKey::Binary(key) => key.ntt_table(),
            BlindRotationKey::Ternary(key) => key.ntt_table(),
        }
    }

    /// Performs the blind rotation operation.
    pub fn blind_rotate<C: UnsignedInteger>(
        &self,
        lut: FieldPolynomial<F>,
        lwe: &LweCiphertext<C>,
    ) -> RlweCiphertext<F> {
        match self {
            BlindRotationKey::Binary(bootstrapping_key) => bootstrapping_key.blind_rotate(lut, lwe),
            BlindRotationKey::Ternary(bootstrapping_key) => {
                bootstrapping_key.blind_rotate(lut, lwe)
            }
        }
    }

    /// Generates the [`BlindRotationKey<F>`].
    pub fn generate<C, R>(
        lwe_secret_key: &LweSecretKey<C>,
        rlwe_secret_key: &NttRlweSecretKey<F>,
        blind_rotation_basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: &DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: Arc<<F as NttField>::Table>,
        rng: &mut R,
    ) -> Self
    where
        C: UnsignedInteger,
        R: Rng + CryptoRng,
    {
        match lwe_secret_key.distr() {
            LweSecretKeyType::Binary => BlindRotationKey::Binary(BinaryBlindRotationKey::generate(
                lwe_secret_key,
                rlwe_secret_key,
                blind_rotation_basis,
                gaussian,
                ntt_table,
                rng,
            )),
            LweSecretKeyType::Ternary => {
                BlindRotationKey::Ternary(TernaryBlindRotationKey::generate(
                    lwe_secret_key,
                    rlwe_secret_key,
                    blind_rotation_basis,
                    gaussian,
                    ntt_table,
                    rng,
                ))
            }
        }
    }
}
