//! Blind Rotation

mod binary;
mod ternary;

use algebra::{modulus::PowOf2Modulus, Basis, FieldDiscreteGaussianSampler, NTTField};
pub use binary::{NTRUBinaryBlindRotationKey, RLWEBinaryBlindRotationKey};
use lattice::{NTRU, RLWE};
use rand::{CryptoRng, Rng};
pub use ternary::{NTRUTernaryBlindRotationKey, RLWETernaryBlindRotationKey};

use crate::{LWEModulusType, NTRUSecretKeyPack, SecretKeyPack, SecretKeyType};

/// Blind rotation key
#[derive(Debug, Clone)]
pub enum RLWEBlindRotationKey<F: NTTField> {
    /// FHE binary bootstrapping key
    Binary(RLWEBinaryBlindRotationKey<F>),
    /// FHE ternary bootstrapping key
    Ternary(RLWETernaryBlindRotationKey<F>),
}

impl<F: NTTField> RLWEBlindRotationKey<F> {
    /// Creates the binary bootstrapping key
    #[inline]
    pub fn binary(key: RLWEBinaryBlindRotationKey<F>) -> Self {
        Self::Binary(key)
    }

    /// Creates the ternary bootstrapping key
    #[inline]
    pub fn ternary(key: RLWETernaryBlindRotationKey<F>) -> Self {
        Self::Ternary(key)
    }

    /// Performs the blind rotation operation
    pub fn blind_rotate(
        &self,
        init_acc: RLWE<F>,
        lwe_a: &[LWEModulusType],
        rlwe_dimension: usize,
        twice_rlwe_dimension_div_lwe_modulus: usize,
        lwe_modulus: PowOf2Modulus<LWEModulusType>,
        bootstrapping_basis: Basis<F>,
    ) -> RLWE<F> {
        match self {
            RLWEBlindRotationKey::Binary(br_key) => br_key.blind_rotate(
                init_acc,
                lwe_a,
                rlwe_dimension,
                twice_rlwe_dimension_div_lwe_modulus,
                lwe_modulus,
            ),
            RLWEBlindRotationKey::Ternary(br_key) => br_key.blind_rotate(
                init_acc,
                lwe_a,
                rlwe_dimension,
                twice_rlwe_dimension_div_lwe_modulus,
                lwe_modulus,
                bootstrapping_basis,
            ),
        }
    }

    /// Generates the [`BootstrappingKey<F>`].
    pub fn generate<R>(
        secret_key_pack: &SecretKeyPack<F>,
        chi: FieldDiscreteGaussianSampler,
        rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let parameters = secret_key_pack.parameters();
        match parameters.secret_key_type() {
            SecretKeyType::Binary => {
                RLWEBlindRotationKey::Binary(RLWEBinaryBlindRotationKey::generate(
                    parameters.blind_rotation_basis(),
                    secret_key_pack.lwe_secret_key(),
                    chi,
                    secret_key_pack.ntt_rlwe_secret_key(),
                    rng,
                ))
            }
            SecretKeyType::Ternary => {
                RLWEBlindRotationKey::Ternary(RLWETernaryBlindRotationKey::generate(
                    parameters.blind_rotation_basis(),
                    secret_key_pack.lwe_secret_key(),
                    chi,
                    secret_key_pack.ntt_rlwe_secret_key(),
                    rng,
                ))
            }
        }
    }
}

/// Blind rotation key based on NTRU.
#[derive(Debug, Clone)]
pub enum NTRUBlindRotationKey<F: NTTField> {
    /// FHE binary blind rotation key
    Binary(NTRUBinaryBlindRotationKey<F>),
    /// FHE ternary blind rotation key
    Ternary(NTRUTernaryBlindRotationKey<F>),
}

impl<F: NTTField> NTRUBlindRotationKey<F> {
    /// Creates the binary bootstrapping key
    #[inline]
    pub fn binary(key: NTRUBinaryBlindRotationKey<F>) -> Self {
        Self::Binary(key)
    }

    /// Creates the ternary bootstrapping key
    #[inline]
    pub fn ternary(key: NTRUTernaryBlindRotationKey<F>) -> Self {
        Self::Ternary(key)
    }

    /// Performs the bootstrapping operation
    pub fn blind_rotate(
        &self,
        init_acc: NTRU<F>,
        lwe_a: &[LWEModulusType],
        ntru_dimension: usize,
        twice_ntru_dimension_div_lwe_modulus: usize,
        lwe_modulus: PowOf2Modulus<LWEModulusType>,
        bootstrapping_basis: Basis<F>,
    ) -> NTRU<F> {
        match self {
            NTRUBlindRotationKey::Binary(br_key) => br_key.blind_rotate(
                init_acc,
                lwe_a,
                ntru_dimension,
                twice_ntru_dimension_div_lwe_modulus,
                lwe_modulus,
            ),
            NTRUBlindRotationKey::Ternary(br_key) => br_key.blind_rotate(
                init_acc,
                lwe_a,
                ntru_dimension,
                twice_ntru_dimension_div_lwe_modulus,
                lwe_modulus,
                bootstrapping_basis,
            ),
        }
    }

    /// Generates the [`BootstrappingKey<F>`].
    pub fn generate<R>(
        secret_key_pack: &NTRUSecretKeyPack<F>,
        chi: FieldDiscreteGaussianSampler,
        rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let parameters = secret_key_pack.parameters();
        match parameters.secret_key_type() {
            SecretKeyType::Binary => {
                NTRUBlindRotationKey::Binary(NTRUBinaryBlindRotationKey::generate(
                    parameters.blind_rotation_basis(),
                    secret_key_pack.lwe_secret_key(),
                    chi,
                    secret_key_pack.ntt_inv_ring_secret_key(),
                    rng,
                ))
            }
            SecretKeyType::Ternary => {
                NTRUBlindRotationKey::Ternary(NTRUTernaryBlindRotationKey::generate(
                    parameters.blind_rotation_basis(),
                    secret_key_pack.lwe_secret_key(),
                    chi,
                    secret_key_pack.ntt_inv_ring_secret_key(),
                    rng,
                ))
            }
        }
    }
}
