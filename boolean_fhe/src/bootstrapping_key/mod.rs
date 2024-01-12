use algebra::{
    ntt_add_mul_assign_ref, Basis, NTTField, NTTPolynomial, Polynomial, Random, RandomNTTField,
    Ring,
};
use lattice::{NTTGadgetRLWE, NTTRGSW, NTTRLWE, RLWE};

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
        gadget_basis: Basis<F>,
    ) -> RLWE<F> {
        let mut pre_allocate = BootstrappingPreAllocator::<F>::new(rlwe_dimension, gadget_basis);
        match self {
            BootstrappingKey::Binary(bootstrapping_key) => bootstrapping_key.bootstrapping(
                init_acc,
                lwe_a,
                rlwe_dimension,
                twice_rlwe_dimension_div_lwe_modulus,
                &mut pre_allocate,
            ),
            BootstrappingKey::Ternary(bootstrapping_key) => bootstrapping_key.bootstrapping(
                init_acc,
                lwe_a,
                rlwe_dimension,
                twice_rlwe_dimension_div_lwe_modulus,
                &mut pre_allocate,
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

/// Pre allocated space for the bootstrapping
/// to reduce the `allocate` or `free` in the
/// bootstrapping procedure.
#[derive(Debug)]
pub struct BootstrappingPreAllocator<F: NTTField> {
    decomposed_space: Vec<Polynomial<F>>,
    ntt_rlwe: NTTRLWE<F>,
    rlwe_0: RLWE<F>,
    rlwe_1: RLWE<F>,
}

impl<F: NTTField> BootstrappingPreAllocator<F> {
    /// Creates a new [`BootstrappingPreAllocator<F>`].
    pub fn new(rlwe_dimension: usize, gadget_basis: Basis<F>) -> Self {
        let decompose_len = gadget_basis.decompose_len();

        let mut decomposed_space = Vec::new();
        decomposed_space.resize_with(decompose_len, || {
            <Polynomial<F>>::zero_with_coeff_count(rlwe_dimension)
        });

        Self {
            decomposed_space,
            ntt_rlwe: NTTRLWE::zero(rlwe_dimension),
            rlwe_0: RLWE::zero(rlwe_dimension),
            rlwe_1: RLWE::zero(rlwe_dimension),
        }
    }

    /// Gets all space's mut reference
    #[inline]
    #[allow(clippy::type_complexity)]
    pub fn get_all_mut(
        &mut self,
    ) -> (
        &mut [Polynomial<F>],
        &mut NTTRLWE<F>,
        &mut RLWE<F>,
        &mut RLWE<F>,
    ) {
        (
            self.decomposed_space.as_mut_slice(),
            &mut self.ntt_rlwe,
            &mut self.rlwe_0,
            &mut self.rlwe_1,
        )
    }

    /// Returns a reference to the decompose space of this [`BootstrappingPreAllocator<F>`].
    #[inline]
    pub fn decomposed_space(&self) -> &[Polynomial<F>] {
        self.decomposed_space.as_ref()
    }

    /// Returns a mutable reference to the decompose space of this [`BootstrappingPreAllocator<F>`].
    #[inline]
    pub fn decomposed_space_mut(&mut self) -> &mut [Polynomial<F>] {
        &mut self.decomposed_space
    }

    /// Returns a reference to the ntt rlwe of this [`BootstrappingPreAllocator<F>`].
    #[inline]
    pub fn ntt_rlwe(&self) -> &NTTRLWE<F> {
        &self.ntt_rlwe
    }

    /// Returns a mutable reference to the ntt rlwe of this [`BootstrappingPreAllocator<F>`].
    #[inline]
    pub fn ntt_rlwe_mut(&mut self) -> &mut NTTRLWE<F> {
        &mut self.ntt_rlwe
    }

    /// Returns a reference to the rlwe 0 of this [`BootstrappingPreAllocator<F>`].
    #[inline]
    pub fn rlwe_0(&self) -> &RLWE<F> {
        &self.rlwe_0
    }

    /// Returns a mutable reference to the rlwe 0 of this [`BootstrappingPreAllocator<F>`].
    #[inline]
    pub fn rlwe_0_mut(&mut self) -> &mut RLWE<F> {
        &mut self.rlwe_0
    }

    /// Returns a reference to the rlwe 1 of this [`BootstrappingPreAllocator<F>`].
    #[inline]
    pub fn rlwe_1(&self) -> &RLWE<F> {
        &self.rlwe_1
    }

    /// Returns a mutable reference to the rlwe 1 of this [`BootstrappingPreAllocator<F>`].
    #[inline]
    pub fn rlwe_1_mut(&mut self) -> &mut RLWE<F> {
        &mut self.rlwe_1
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
