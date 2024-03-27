use algebra::{
    modulus::PowOf2Modulus, reduce::NegReduce, Basis, FieldDiscreteGaussianSampler, NTTField,
    RandomNTTField,
};
use lattice::{DecompositionSpace, NTTRLWESpace, PolynomialSpace, RLWESpace, NTTRGSW, RLWE};
use rand_distr::Distribution;

use crate::{LWEType, NTTRLWESecretKey};

#[derive(Debug, Clone)]
pub struct BinaryBootstrappingKey<F: NTTField> {
    key: Vec<NTTRGSW<F>>,
}

impl<F: NTTField> BinaryBootstrappingKey<F> {
    /// Creates a new [`BinaryBootstrappingKey<F>`].
    #[inline]
    pub fn new(key: Vec<NTTRGSW<F>>) -> Self {
        Self { key }
    }

    /// Performs the bootstrapping operation
    pub fn bootstrapping(
        &self,
        init_acc: RLWE<F>,
        lwe_a: &[LWEType],
        rlwe_dimension: usize,
        twice_rlwe_dimension_div_lwe_modulus: usize,
        lwe_modulus: PowOf2Modulus<LWEType>,
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
}

impl<F: RandomNTTField> BinaryBootstrappingKey<F> {
    /// Generates the [`BinaryBootstrappingKey<F>`].
    pub(crate) fn generate<Rng>(
        bootstrapping_basis: Basis<F>,
        lwe_secret_key: &[LWEType],
        chi: FieldDiscreteGaussianSampler,
        rlwe_dimension: usize,
        rlwe_secret_key: &NTTRLWESecretKey<F>,
        mut rng: Rng,
    ) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
        FieldDiscreteGaussianSampler: Distribution<F>,
    {
        let key = lwe_secret_key
            .iter()
            .map(|&s| {
                if s == 0 {
                    <NTTRGSW<F>>::generate_zero_sample(
                        rlwe_dimension,
                        rlwe_secret_key,
                        bootstrapping_basis,
                        chi,
                        &mut rng,
                    )
                } else {
                    <NTTRGSW<F>>::generate_one_sample(
                        rlwe_dimension,
                        rlwe_secret_key,
                        bootstrapping_basis,
                        chi,
                        &mut rng,
                    )
                }
            })
            .collect();
        BinaryBootstrappingKey::new(key)
    }
}
