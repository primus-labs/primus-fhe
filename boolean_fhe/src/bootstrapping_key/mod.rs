use algebra::{
    ntt_add_mul_assign_ref, Basis, NTTField, NTTPolynomial, Polynomial, Random, RandomNTTField,
    Ring,
};
use lattice::{NTTGadgetRLWE, NTTRGSW, RLWE};

use crate::{
    ciphertext::NTTRLWECiphertext, secret_key::NTTRLWESecretKey, SecretKeyPack, SecretKeyType,
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
    pub fn bootstrapping<R: Ring>(
        &self,
        init_acc: RLWE<F>,
        lwe_a: &[R],
        rlwe_dimension: usize,
        twice_rlwe_dimension_div_lwe_modulus: usize,
    ) -> RLWE<F> {
        match self {
            BootstrappingKey::Binary(bootstrapping_key) => bootstrapping_key.bootstrapping(
                init_acc,
                lwe_a,
                rlwe_dimension,
                twice_rlwe_dimension_div_lwe_modulus,
            ),
            BootstrappingKey::Ternary(bootstrapping_key) => bootstrapping_key.bootstrapping(
                init_acc,
                lwe_a,
                rlwe_dimension,
                twice_rlwe_dimension_div_lwe_modulus,
            ),
        }
    }
}

impl<F: RandomNTTField> BootstrappingKey<F> {
    /// Generates the [`BootstrappingKey<F>`].
    pub fn generate<R: Ring, Rng>(
        secret_key_pack: &SecretKeyPack<R, F>,
        chi: <F as Random>::NormalDistribution,
        rng: Rng,
    ) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
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
pub(crate) fn ntt_rgsw_zero<F, Rng>(
    rlwe_dimension: usize,
    rlwe_secret_key: &NTTRLWESecretKey<F>,
    basis: Basis<F>,
    chi: <F as Random>::NormalDistribution,
    mut rng: Rng,
) -> NTTRGSW<F>
where
    F: RandomNTTField,
    Rng: rand::Rng + rand::CryptoRng,
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
pub(crate) fn ntt_rgsw_one<F, Rng>(
    rlwe_dimension: usize,
    rlwe_secret_key: &NTTRLWESecretKey<F>,
    basis: Basis<F>,
    basis_powers: &[F],
    chi: <F as Random>::NormalDistribution,
    mut rng: Rng,
) -> NTTRGSW<F>
where
    F: RandomNTTField,
    Rng: rand::Rng + rand::CryptoRng,
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
fn ntt_rlwe_zeros<F, Rng>(
    rlwe_dimension: usize,
    rlwe_secret_key: &NTTRLWESecretKey<F>,
    n: usize,
    chi: <F as Random>::NormalDistribution,
    mut rng: Rng,
) -> Vec<NTTRLWECiphertext<F>>
where
    F: RandomNTTField,
    Rng: rand::Rng + rand::CryptoRng,
{
    (0..n)
        .map(|_| {
            let a = <NTTPolynomial<F>>::random(rlwe_dimension, &mut rng);
            let mut b = <Polynomial<F>>::random_with_dis(rlwe_dimension, &mut rng, chi)
                .into_ntt_polynomial();
            ntt_add_mul_assign_ref(b.as_mut_slice(), &a, rlwe_secret_key);
            <NTTRLWECiphertext<F>>::new(a, b)
        })
        .collect()
}

/// Generates a [`Vec`], which is a ntt version `GadgetRLWE(1)`.
fn ntt_gadget_rlwe_one<F, Rng>(
    rlwe_dimension: usize,
    rlwe_secret_key: &NTTRLWESecretKey<F>,
    basis_powers: &[F],
    chi: <F as Random>::NormalDistribution,
    mut rng: Rng,
) -> Vec<NTTRLWECiphertext<F>>
where
    F: RandomNTTField,
    Rng: rand::Rng + rand::CryptoRng,
{
    basis_powers
        .iter()
        .map(|&basis_power| {
            let a = <NTTPolynomial<F>>::random(rlwe_dimension, &mut rng);
            let mut b = <Polynomial<F>>::random_with_dis(rlwe_dimension, &mut rng, chi)
                .into_ntt_polynomial();
            ntt_add_mul_assign_ref(b.as_mut_slice(), &a, rlwe_secret_key);
            b.iter_mut().for_each(|v| *v += basis_power);
            <NTTRLWECiphertext<F>>::new(a, b)
        })
        .collect()
}

/// Generates a [`Vec`], which is a ntt version `GadgetRLWE(-s)`.
///
/// `s` is the secret key of the RLWE.
fn ntt_gadget_rlwe_neg_secret_mul_one<F, Rng>(
    rlwe_dimension: usize,
    rlwe_secret_key: &NTTRLWESecretKey<F>,
    basis_powers: &[F],
    chi: <F as Random>::NormalDistribution,
    mut rng: Rng,
) -> Vec<NTTRLWECiphertext<F>>
where
    F: RandomNTTField,
    Rng: rand::Rng + rand::CryptoRng,
{
    basis_powers
        .iter()
        .map(|&basis_power| {
            let mut a = <NTTPolynomial<F>>::random(rlwe_dimension, &mut rng);
            let mut b = <Polynomial<F>>::random_with_dis(rlwe_dimension, &mut rng, chi)
                .into_ntt_polynomial();
            ntt_add_mul_assign_ref(b.as_mut_slice(), &a, rlwe_secret_key);
            a.iter_mut().for_each(|v| *v += basis_power);
            <NTTRLWECiphertext<F>>::new(a, b)
        })
        .collect()
}
