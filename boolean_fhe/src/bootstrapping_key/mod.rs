use algebra::{
    modulus::PowOf2Modulus, ntt_add_mul_assign, Basis, FieldDiscreteGaussianSampler, NTTField,
    NTTPolynomial, Polynomial, RandomNTTField,
};
use lattice::{NTTGadgetRLWE, NTTRGSW, RLWE};
use rand::{CryptoRng, Rng};
use rand_distr::Distribution;

use crate::{
    ciphertext::NTTRLWECiphertext, secret_key::NTTRLWESecretKey, LWEType, SecretKeyPack,
    SecretKeyType,
};

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
        gadget_basis: Basis<F>,
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
                gadget_basis,
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
                parameters.gadget_basis(),
                parameters.gadget_basis_powers(),
                secret_key_pack.lwe_secret_key(),
                chi,
                parameters.rlwe_dimension(),
                secret_key_pack.ntt_rlwe_secret_key(),
                rng,
            )),
            SecretKeyType::Ternary => BootstrappingKey::Ternary(TernaryBootstrappingKey::generate(
                parameters.gadget_basis(),
                parameters.gadget_basis_powers(),
                secret_key_pack.lwe_secret_key(),
                chi,
                parameters.rlwe_dimension(),
                secret_key_pack.ntt_rlwe_secret_key(),
                rng,
            )),
        }
    }
}

/// Generates a ntt version `RGSW(0)`.
pub(crate) fn ntt_rgsw_zero<F, R>(
    rlwe_dimension: usize,
    rlwe_secret_key: &NTTRLWESecretKey<F>,
    basis: Basis<F>,
    chi: FieldDiscreteGaussianSampler,
    mut rng: R,
) -> NTTRGSW<F>
where
    F: RandomNTTField,
    R: Rng + CryptoRng,
    FieldDiscreteGaussianSampler: Distribution<F>,
{
    let decompose_len = basis.decompose_len();
    let neg_sm = ntt_rlwe_zeros(
        rlwe_dimension,
        rlwe_secret_key,
        decompose_len,
        chi,
        &mut rng,
    );
    let m = ntt_rlwe_zeros(
        rlwe_dimension,
        rlwe_secret_key,
        decompose_len,
        chi,
        &mut rng,
    );

    NTTRGSW::new(
        NTTGadgetRLWE::new(neg_sm, basis),
        NTTGadgetRLWE::new(m, basis),
    )
}

/// Generates a ntt version `RGSW(1)`.
pub(crate) fn ntt_rgsw_one<F, R>(
    rlwe_dimension: usize,
    rlwe_secret_key: &NTTRLWESecretKey<F>,
    basis: Basis<F>,
    basis_powers: &[F],
    chi: FieldDiscreteGaussianSampler,
    mut rng: R,
) -> NTTRGSW<F>
where
    F: RandomNTTField,
    R: Rng + CryptoRng,
    FieldDiscreteGaussianSampler: Distribution<F>,
{
    let one = ntt_gadget_rlwe_one(rlwe_dimension, rlwe_secret_key, basis_powers, chi, &mut rng);
    let neg_secret = ntt_gadget_rlwe_neg_secret_mul_one(
        rlwe_dimension,
        rlwe_secret_key,
        basis_powers,
        chi,
        &mut rng,
    );
    NTTRGSW::new(
        NTTGadgetRLWE::new(neg_secret, basis),
        NTTGadgetRLWE::new(one, basis),
    )
}

/// Generates a [`Vec`], which has `n` ntt version `RLWE(0)`.
fn ntt_rlwe_zeros<F, R>(
    rlwe_dimension: usize,
    rlwe_secret_key: &NTTRLWESecretKey<F>,
    n: usize,
    chi: FieldDiscreteGaussianSampler,
    mut rng: R,
) -> Vec<NTTRLWECiphertext<F>>
where
    F: RandomNTTField,
    R: Rng + CryptoRng,
    FieldDiscreteGaussianSampler: Distribution<F>,
{
    (0..n)
        .map(|_| {
            let a = NTTPolynomial::random(rlwe_dimension, &mut rng);
            let mut b = Polynomial::random_with_gaussian(rlwe_dimension, &mut rng, chi)
                .into_ntt_polynomial();

            ntt_add_mul_assign(&mut b, &a, rlwe_secret_key);
            NTTRLWECiphertext::new(a, b)
        })
        .collect()
}

/// Generates a [`Vec`], which is a ntt version `GadgetRLWE(1)`.
fn ntt_gadget_rlwe_one<F, R>(
    rlwe_dimension: usize,
    rlwe_secret_key: &NTTRLWESecretKey<F>,
    basis_powers: &[F],
    chi: FieldDiscreteGaussianSampler,
    mut rng: R,
) -> Vec<NTTRLWECiphertext<F>>
where
    F: RandomNTTField,
    R: Rng + CryptoRng,
    FieldDiscreteGaussianSampler: Distribution<F>,
{
    basis_powers
        .iter()
        .map(|&basis_power| {
            let a = NTTPolynomial::random(rlwe_dimension, &mut rng);
            let mut b = Polynomial::random_with_gaussian(rlwe_dimension, &mut rng, chi)
                .into_ntt_polynomial();

            ntt_add_mul_assign(&mut b, &a, rlwe_secret_key);
            b.iter_mut().for_each(|v| *v += basis_power);
            NTTRLWECiphertext::new(a, b)
        })
        .collect()
}

/// Generates a [`Vec`], which is a ntt version `GadgetRLWE(-s)`.
///
/// `s` is the secret key of the RLWE.
fn ntt_gadget_rlwe_neg_secret_mul_one<F, R>(
    rlwe_dimension: usize,
    rlwe_secret_key: &NTTRLWESecretKey<F>,
    basis_powers: &[F],
    chi: FieldDiscreteGaussianSampler,
    mut rng: R,
) -> Vec<NTTRLWECiphertext<F>>
where
    F: RandomNTTField,
    R: Rng + CryptoRng,
    FieldDiscreteGaussianSampler: Distribution<F>,
{
    basis_powers
        .iter()
        .map(|&basis_power| {
            let mut a = NTTPolynomial::random(rlwe_dimension, &mut rng);
            let mut b = Polynomial::random_with_gaussian(rlwe_dimension, &mut rng, chi)
                .into_ntt_polynomial();

            ntt_add_mul_assign(&mut b, &a, rlwe_secret_key);
            a.iter_mut().for_each(|v| *v += basis_power);
            NTTRLWECiphertext::new(a, b)
        })
        .collect()
}
