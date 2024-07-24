use algebra::{modulus::PowOf2Modulus, Basis, FieldDiscreteGaussianSampler, NTTField};
use lattice::NTRU;
use rand::{CryptoRng, Rng};

use crate::{LWEModulusType, LWEMsgType, SecretKeyPack, SecretKeyType};

mod binary;
mod ternary;

use binary::BinaryBlindRotationKey;
use ternary::TernaryBlindRotationKey;

/// Bootstrapping key.
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
    /// Creates the binary bootstrapping key
    #[inline]
    pub fn binary(key: BinaryBlindRotationKey<F>) -> Self {
        Self::Binary(key)
    }

    /// Creates the ternary bootstrapping key
    #[inline]
    pub fn ternary(key: TernaryBlindRotationKey<F>) -> Self {
        Self::Ternary(key)
    }

    /// Performs the bootstrapping operation
    pub fn blind_rotate<C: LWEModulusType>(
        &self,
        init_acc: NTRU<F>,
        lwe_a: &[C],
        ntru_dimension: usize,
        twice_ntru_dimension_div_lwe_modulus: usize,
        lwe_modulus: PowOf2Modulus<C>,
        blind_rotation_basis: Basis<F>,
    ) -> NTRU<F> {
        match self {
            BlindRotationKey::Binary(bootstrapping_key) => bootstrapping_key.blind_rotate(
                init_acc,
                lwe_a,
                ntru_dimension,
                twice_ntru_dimension_div_lwe_modulus,
                lwe_modulus,
            ),
            BlindRotationKey::Ternary(bootstrapping_key) => bootstrapping_key.blind_rotate(
                init_acc,
                lwe_a,
                ntru_dimension,
                twice_ntru_dimension_div_lwe_modulus,
                lwe_modulus,
                blind_rotation_basis,
            ),
        }
    }

    /// Generates the [`BlindRotationKey<F>`].
    pub fn generate<R, M, C>(
        secret_key_pack: &SecretKeyPack<M, C, F>,
        chi: FieldDiscreteGaussianSampler,
        rng: R,
    ) -> Self
    where
        R: Rng + CryptoRng,
        M: LWEMsgType,
        C: LWEModulusType,
    {
        let parameters = secret_key_pack.parameters();
        match parameters.secret_key_type() {
            SecretKeyType::Binary => BlindRotationKey::Binary(BinaryBlindRotationKey::generate(
                parameters.blind_rotation_basis(),
                secret_key_pack.lwe_secret_key(),
                chi,
                secret_key_pack.ntt_inv_ring_secret_key().unwrap(),
                rng,
            )),
            SecretKeyType::Ternary => BlindRotationKey::Ternary(TernaryBlindRotationKey::generate(
                parameters.blind_rotation_basis(),
                secret_key_pack.lwe_secret_key(),
                chi,
                secret_key_pack.ntt_inv_ring_secret_key().unwrap(),
                rng,
            )),
        }
    }
}
