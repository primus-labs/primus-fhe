use algebra::{modulus::PowOf2Modulus, Basis, FieldDiscreteGaussianSampler, NTTField};
use lattice::NTRU;
use rand::{CryptoRng, Rng};

use crate::{LWEPlaintext, SecretKeyPack, SecretKeyType};

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
        init_acc: NTRU<F>,
        lwe_a: &[LWEPlaintext],
        ntru_dimension: usize,
        twice_ntru_dimension_div_lwe_modulus: usize,
        lwe_modulus: PowOf2Modulus<LWEPlaintext>,
        bootstrapping_basis: Basis<F>,
    ) -> NTRU<F> {
        match self {
            BootstrappingKey::Binary(bootstrapping_key) => bootstrapping_key.bootstrapping(
                init_acc,
                lwe_a,
                ntru_dimension,
                twice_ntru_dimension_div_lwe_modulus,
                lwe_modulus,
            ),
            BootstrappingKey::Ternary(bootstrapping_key) => bootstrapping_key.bootstrapping(
                init_acc,
                lwe_a,
                ntru_dimension,
                twice_ntru_dimension_div_lwe_modulus,
                lwe_modulus,
                bootstrapping_basis,
            ),
        }
    }
}

impl<F: NTTField> BootstrappingKey<F> {
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
            SecretKeyType::Binary => BootstrappingKey::Binary(BinaryBootstrappingKey::generate(
                parameters.bootstrapping_basis(),
                secret_key_pack.lwe_secret_key(),
                chi,
                secret_key_pack.ntt_inv_ring_secret_key(),
                rng,
            )),
            SecretKeyType::Ternary => BootstrappingKey::Ternary(TernaryBootstrappingKey::generate(
                parameters.bootstrapping_basis(),
                secret_key_pack.lwe_secret_key(),
                chi,
                secret_key_pack.ntt_inv_ring_secret_key(),
                rng,
            )),
        }
    }
}
