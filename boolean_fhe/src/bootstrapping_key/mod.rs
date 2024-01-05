use algebra::{Basis, NTTField, NTTPolynomial, Polynomial, Random, RandomNTTField, Ring};
use lattice::{NTTGadgetRLWE, NTTRGSW, RLWE};

use crate::{ciphertext::NTTRLWECiphertext, secret_key::NTTRLWESecretKey, SecretKeyType};

mod binary;
mod ternary;

use binary::BinaryBootstrappingKey;
use ternary::TernaryBootstrappingKey;

/// Bootstrapping key
#[derive(Debug, Clone)]
pub enum BootstrappingKey<F: NTTField> {
    /// TFHE binary bootstrapping key
    Binary(BinaryBootstrappingKey<F>),
    /// TFHE ternary bootstrapping key
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
            BootstrappingKey::Binary(bk) => bk.bootstrapping(
                init_acc,
                lwe_a,
                rlwe_dimension,
                twice_rlwe_dimension_div_lwe_modulus,
            ),
            BootstrappingKey::Ternary(bk) => bk.bootstrapping(
                init_acc,
                lwe_a,
                rlwe_dimension,
                twice_rlwe_dimension_div_lwe_modulus,
            ),
        }
    }
}

impl<F: RandomNTTField> BootstrappingKey<F> {
    pub(crate) fn generate<R: Ring, Rng>(
        secret_key_type: SecretKeyType,
        lwe_secret_key: &[R],
        rlwe_secret_key: &NTTRLWESecretKey<F>,
        rlwe_dimension: usize,
        basis: Basis<F>,
        basis_powers: &[F],
        chi: <F as Random>::NormalDistribution,
        rng: Rng,
    ) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        match secret_key_type {
            SecretKeyType::Binary => BootstrappingKey::Binary(BinaryBootstrappingKey::generate(
                basis,
                basis_powers,
                lwe_secret_key,
                chi,
                rlwe_dimension,
                rlwe_secret_key,
                rng,
            )),
            SecretKeyType::Ternary => BootstrappingKey::Ternary(TernaryBootstrappingKey::generate(
                basis,
                basis_powers,
                lwe_secret_key,
                chi,
                rlwe_dimension,
                rlwe_secret_key,
                rng,
            )),
        }
    }
}

/// .
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
    let m = ntt_rlwe_zeros(
        rlwe_dimension,
        rlwe_secret_key,
        decompose_len,
        chi,
        &mut rng,
    );
    let neg_sm = ntt_rlwe_zeros(
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

/// .
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

///
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
            let b = &a * rlwe_secret_key
                + <Polynomial<F>>::random_with_dis(rlwe_dimension, &mut rng, chi)
                    .to_ntt_polynomial();
            <NTTRLWECiphertext<F>>::new(a, b)
        })
        .collect()
}

///
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
            let mut b = &a * rlwe_secret_key
                + <Polynomial<F>>::random_with_dis(rlwe_dimension, &mut rng, chi)
                    .to_ntt_polynomial();
            b.iter_mut().for_each(|v| *v += basis_power);
            <NTTRLWECiphertext<F>>::new(a, b)
        })
        .collect()
}

///
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
            let b = &a * rlwe_secret_key
                + <Polynomial<F>>::random_with_dis(rlwe_dimension, &mut rng, chi)
                    .to_ntt_polynomial();
            a.iter_mut().for_each(|v| *v += basis_power);
            <NTTRLWECiphertext<F>>::new(a, b)
        })
        .collect()
}
