use algebra::{
    modulus::PowOf2Modulus, Basis, FieldDiscreteGaussianSampler, NTTField, RandomNTTField,
};
use lattice::RLWE;
use rand::{CryptoRng, Rng};
use rand_distr::Distribution;

use crate::{LWEType, SecretKeyPack, SecretKeyType};

mod binary;
mod ternary;

use binary::BinaryBootstrappingKey;
use ternary::TernaryBootstrappingKey;

/// Bootstrapping key.
///
/// In FHE, bootstrapping is a technique used to refresh the ciphertexts
/// during the homomorphic computation. As homomorphic operations are
/// performed on encrypted data, the noise in the ciphertext increases,
/// and if left unchecked, it can eventually lead to decryption errors.
/// Bootstrapping is a method to reduce the noise and refresh the
/// ciphertexts, allowing the computation to continue.
#[derive(Debug, Clone)]
pub enum BootstrappingKey<F: NTTField> {
    /// FHE binary bootstrapping key
    Binary(BinaryBootstrappingKey<F>),
    /// FHE ternary bootstrapping key
    Ternary(TernaryBootstrappingKey<F>),
}

impl<F: NTTField> BootstrappingKey<F> {
    /// Creates the binary bootstrapping key
    #[inline]
    pub fn binary(key: BinaryBootstrappingKey<F>) -> Self {
        Self::Binary(key)
    }

    /// Creates the ternary bootstrapping key
    #[inline]
    pub fn ternary(key: TernaryBootstrappingKey<F>) -> Self {
        Self::Ternary(key)
    }

    /// Performs the bootstrapping operation
    pub fn bootstrapping(
        &self,
        init_acc: RLWE<F>,
        lwe_a: &[LWEType],
        rlwe_dimension: usize,
        twice_rlwe_dimension_div_lwe_modulus: usize,
        lwe_modulus: PowOf2Modulus<LWEType>,
        bootstrapping_basis: Basis<F>,
    ) -> RLWE<F> {
        match self {
            BootstrappingKey::Binary(bootstrapping_key) => bootstrapping_key.bootstrapping(
                init_acc,
                lwe_a,
                rlwe_dimension,
                twice_rlwe_dimension_div_lwe_modulus,
                lwe_modulus,
            ),
            BootstrappingKey::Ternary(bootstrapping_key) => bootstrapping_key.bootstrapping(
                init_acc,
                lwe_a,
                rlwe_dimension,
                twice_rlwe_dimension_div_lwe_modulus,
                lwe_modulus,
                bootstrapping_basis,
            ),
        }
    }
}

impl<F: RandomNTTField> BootstrappingKey<F> {
    /// Generates the [`BootstrappingKey<F>`].
    pub fn generate<R>(
        secret_key_pack: &SecretKeyPack<F>,
        chi: FieldDiscreteGaussianSampler,
        rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
        FieldDiscreteGaussianSampler: Distribution<F>,
    {
        let parameters = secret_key_pack.parameters();
        match parameters.secret_key_type() {
            SecretKeyType::Binary => BootstrappingKey::Binary(BinaryBootstrappingKey::generate(
                parameters.bootstrapping_basis(),
                secret_key_pack.lwe_secret_key(),
                chi,
                secret_key_pack.ntt_rlwe_secret_key(),
                rng,
            )),
            SecretKeyType::Ternary => BootstrappingKey::Ternary(TernaryBootstrappingKey::generate(
                parameters.bootstrapping_basis(),
                secret_key_pack.lwe_secret_key(),
                chi,
                secret_key_pack.ntt_rlwe_secret_key(),
                rng,
            )),
        }
    }
}
