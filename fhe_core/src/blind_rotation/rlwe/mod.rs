use algebra::{Basis, NTTField, Polynomial};
use lattice::{LWE, RLWE};

use crate::{LWEModulusType, LWESecretKeyType, SecretKeyPack};

mod binary;
mod ternary;

use binary::BinaryBlindRotationKey;
use ternary::TernaryBlindRotationKey;

/// Blind rotation key.
///
/// In FHE, bootstrapping is a technique used to refresh the ciphertexts
/// during the homomorphic computation. As homomorphic operations are
/// performed on encrypted data, the noise in the ciphertext increases,
/// and if left unchecked, it can eventually lead to decryption errors.
/// Bootstrapping is a method to reduce the noise and refresh the
/// ciphertexts, allowing the computation to continue.
#[derive(Debug, Clone)]
pub enum BlindRotationKey<F: NTTField> {
    /// FHE binary blind rotation key
    Binary(BinaryBlindRotationKey<F>),
    /// FHE ternary blind rotation key
    Ternary(TernaryBlindRotationKey<F>),
}

impl<F: NTTField> BlindRotationKey<F> {
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

    /// Performs the blind rotation operation.
    pub fn blind_rotate<C: LWEModulusType>(
        &self,
        lut: Polynomial<F>,
        lwe: &LWE<C>,
        blind_rotation_basis: Basis<F>,
    ) -> RLWE<F> {
        match self {
            BlindRotationKey::Binary(bootstrapping_key) => bootstrapping_key.blind_rotate(lut, lwe),
            BlindRotationKey::Ternary(bootstrapping_key) => {
                bootstrapping_key.blind_rotate(lut, lwe, blind_rotation_basis)
            }
        }
    }

    /// Generates the [`BlindRotationKey<F>`].
    pub fn generate<C>(secret_key_pack: &SecretKeyPack<C, F>) -> Self
    where
        C: LWEModulusType,
    {
        let parameters = secret_key_pack.parameters();
        let chi = parameters.ring_noise_distribution();
        let mut csrng = secret_key_pack.csrng_mut();

        match parameters.lwe_secret_key_type() {
            LWESecretKeyType::Binary => BlindRotationKey::Binary(BinaryBlindRotationKey::generate(
                secret_key_pack.lwe_secret_key(),
                secret_key_pack.ntt_ring_secret_key(),
                parameters.blind_rotation_basis(),
                chi,
                &mut *csrng,
            )),
            LWESecretKeyType::Ternary => {
                BlindRotationKey::Ternary(TernaryBlindRotationKey::generate(
                    secret_key_pack.lwe_secret_key(),
                    secret_key_pack.ntt_ring_secret_key(),
                    parameters.blind_rotation_basis(),
                    chi,
                    &mut *csrng,
                ))
            }
        }
    }
}
