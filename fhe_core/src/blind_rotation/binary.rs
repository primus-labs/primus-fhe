use algebra::{
    modulus::PowOf2Modulus, reduce::NegReduce, Basis, FieldDiscreteGaussianSampler, NTTField,
    NTTPolynomial,
};
use lattice::{
    DecompositionSpace, NTRUSpace, NTTGadgetNTRU, NTTNTRUSpace, NTTRLWESpace, PolynomialSpace,
    RLWESpace, NTRU, NTTRGSW, RLWE,
};

use crate::LWEModulusType;

/// Binary blind rotation key based on RLWE
#[derive(Debug, Clone)]
pub struct RLWEBinaryBlindRotationKey<F: NTTField> {
    key: Vec<NTTRGSW<F>>,
}

impl<F: NTTField> RLWEBinaryBlindRotationKey<F> {
    /// Creates a new [`RLWEBinaryBlindRotationKey<F>`].
    #[inline]
    pub fn new(key: Vec<NTTRGSW<F>>) -> Self {
        Self { key }
    }

    /// Performs the bootstrapping operation
    pub fn blind_rotate(
        &self,
        init_acc: RLWE<F>,
        lwe_a: &[LWEModulusType],
        rlwe_dimension: usize,
        twice_rlwe_dimension_div_lwe_modulus: usize,
        lwe_modulus: PowOf2Modulus<LWEModulusType>,
    ) -> RLWE<F> {
        let decompose_space = &mut DecompositionSpace::new(rlwe_dimension);
        let polynomial_space = &mut PolynomialSpace::new(rlwe_dimension);
        let ntt_rlwe_space = &mut NTTRLWESpace::new(rlwe_dimension);
        let acc_mul_rgsw = &mut RLWESpace::new(rlwe_dimension);

        self.key
            .iter()
            .zip(lwe_a)
            .fold(init_acc, |mut acc, (s_i, &a_i)| {
                // acc_mul_rgsw = ACC * RGSW(s_i)
                acc.mul_small_ntt_rgsw_inplace(
                    s_i,
                    decompose_space,
                    polynomial_space,
                    ntt_rlwe_space,
                    acc_mul_rgsw,
                );
                // ACC = ACC - ACC * RGSW(s_i)
                acc.sub_assign_element_wise(acc_mul_rgsw);
                // ACC = ACC - ACC * RGSW(s_i) + Y^{-a_i} * ACC * RGSW(s_i)
                //     = ACC + (Y^{-a_i} - 1) * ACC * RGSW(s_i)
                acc.add_assign_rhs_mul_monic_monomial(
                    acc_mul_rgsw,
                    rlwe_dimension,
                    twice_rlwe_dimension_div_lwe_modulus,
                    a_i.neg_reduce(lwe_modulus),
                );
                acc
            })
    }

    /// Generates the [`RLWEBinaryBlindRotationKey<F>`].
    pub(crate) fn generate<Rng>(
        blind_rotation_basis: Basis<F>,
        lwe_secret_key: &[LWEModulusType],
        chi: FieldDiscreteGaussianSampler,
        rlwe_secret_key: &NTTPolynomial<F>,
        mut rng: Rng,
    ) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let key = lwe_secret_key
            .iter()
            .map(|&s| {
                if s == 0 {
                    <NTTRGSW<F>>::generate_random_zero_sample(
                        rlwe_secret_key,
                        blind_rotation_basis,
                        chi,
                        &mut rng,
                    )
                } else {
                    <NTTRGSW<F>>::generate_random_one_sample(
                        rlwe_secret_key,
                        blind_rotation_basis,
                        chi,
                        &mut rng,
                    )
                }
            })
            .collect();
        Self { key }
    }
}

/// Binary blind rotation key based on NTRU
#[derive(Debug, Clone)]
pub struct NTRUBinaryBlindRotationKey<F: NTTField> {
    key: Vec<NTTGadgetNTRU<F>>,
}

impl<F: NTTField> NTRUBinaryBlindRotationKey<F> {
    /// Creates a new [`NTRUBinaryBlindRotationKey<F>`].
    #[inline]
    pub fn new(key: Vec<NTTGadgetNTRU<F>>) -> Self {
        Self { key }
    }

    /// Performs the bootstrapping operation
    pub fn blind_rotate(
        &self,
        init_acc: NTRU<F>,
        lwe_a: &[LWEModulusType],
        ntru_dimension: usize,
        twice_ntru_dimension_div_lwe_modulus: usize,
        lwe_modulus: PowOf2Modulus<LWEModulusType>,
    ) -> NTRU<F> {
        let decompose_space = &mut DecompositionSpace::new(ntru_dimension);
        let polynomial_space = &mut PolynomialSpace::new(ntru_dimension);
        let ntt_ntru_space = &mut NTTNTRUSpace::new(ntru_dimension);
        let acc_mul_gadget_ntru = &mut NTRUSpace::new(ntru_dimension);

        self.key
            .iter()
            .zip(lwe_a)
            .fold(init_acc, |mut acc, (s_i, &a_i)| {
                // acc_mul_gadget_ntru = ACC * NTRU'(s_i)
                acc.mul_small_ntt_gadget_ntru_inplace(
                    s_i,
                    decompose_space,
                    polynomial_space,
                    ntt_ntru_space,
                    acc_mul_gadget_ntru,
                );
                // ACC = ACC - ACC * NTRU'(s_i)
                acc.sub_assign_element_wise(acc_mul_gadget_ntru);
                // ACC = ACC - ACC * NTRU'(s_i) + Y^{-a_i} * ACC * NTRU'(s_i)
                //     = ACC + (Y^{-a_i} - 1) * ACC * NTRU'(s_i)
                acc.add_assign_rhs_mul_monic_monomial(
                    acc_mul_gadget_ntru,
                    ntru_dimension,
                    twice_ntru_dimension_div_lwe_modulus,
                    a_i.neg_reduce(lwe_modulus),
                );
                acc
            })
    }

    /// Generates the [`NTRUBinaryBlindRotationKey<F>`].
    pub(crate) fn generate<Rng>(
        blind_rotation_basis: Basis<F>,
        lwe_secret_key: &[LWEModulusType],
        chi: FieldDiscreteGaussianSampler,
        inv_secret_key: &NTTPolynomial<F>,
        mut rng: Rng,
    ) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let key = lwe_secret_key
            .iter()
            .map(|&s| {
                if s == 0 {
                    <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                        inv_secret_key,
                        blind_rotation_basis,
                        chi,
                        &mut rng,
                    )
                } else {
                    <NTTGadgetNTRU<F>>::generate_random_one_sample(
                        inv_secret_key,
                        blind_rotation_basis,
                        chi,
                        &mut rng,
                    )
                }
            })
            .collect();
        Self { key }
    }
}
