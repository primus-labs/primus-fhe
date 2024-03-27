use algebra::{
    modulus::PowOf2Modulus, reduce::NegReduce, transformation::MonomialNTT, Basis,
    FieldDiscreteGaussianSampler, NTTField, RandomNTTField,
};
use lattice::{
    DecompositionSpace, NTTPolynomialSpace, NTTRGSWSpace, NTTRLWESpace, PolynomialSpace, RLWESpace,
    NTTRGSW, RLWE,
};
use rand_distr::Distribution;

use crate::{LWEType, NTTRLWESecretKey};

#[derive(Debug, Clone)]
pub struct TernaryBootstrappingKey<F: NTTField> {
    key: Vec<(NTTRGSW<F>, NTTRGSW<F>)>,
}

impl<F: NTTField> TernaryBootstrappingKey<F> {
    /// Creates a new [`TernaryBootstrappingKey<F>`].
    #[inline]
    pub fn new(key: Vec<(NTTRGSW<F>, NTTRGSW<F>)>) -> Self {
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
        gadget_basis: Basis<F>,
    ) -> RLWE<F> {
        let decompose_space = &mut DecompositionSpace::new(rlwe_dimension);
        let ntt_polynomial = &mut NTTPolynomialSpace::new(rlwe_dimension);
        let polynomial_space = &mut PolynomialSpace::new(rlwe_dimension);
        let median = &mut NTTRLWESpace::new(rlwe_dimension);
        let external_product = &mut RLWESpace::new(rlwe_dimension);
        let evaluation_key = &mut NTTRGSWSpace::new(rlwe_dimension, gadget_basis);

        let ntt_table = F::get_ntt_table(rlwe_dimension.trailing_zeros()).unwrap();

        self.key
            .iter()
            .zip(lwe_a)
            .fold(init_acc, |mut acc, (s_i, &a_i)| {
                let degree = (a_i as usize) * twice_rlwe_dimension_div_lwe_modulus;

                // ntt_polynomial = -Y^{a_i}
                ntt_table.transform_coeff_one_monomial(degree, ntt_polynomial.as_mut_slice());
                ntt_polynomial.neg_assign();

                // evaluation_key = RGSW(s_i_0) - RGSW(s_i_1)*Y^{a_i}
                s_i.0.add_ntt_rgsw_mul_ntt_polynomial_inplace(
                    &s_i.1,
                    ntt_polynomial,
                    evaluation_key,
                );

                // external_product = ACC * evaluation_key
                //                  = ACC * (RGSW(s_i_0) - RGSW(s_i_1)*Y^{a_i})
                acc.mul_small_ntt_rgsw_inplace(
                    evaluation_key,
                    decompose_space,
                    polynomial_space,
                    median,
                    external_product,
                );

                // ACC = ACC - external_product
                //     = ACC - ACC * (RGSW(s_i_0) - RGSW(s_i_1)*Y^{a_i})
                acc.sub_assign_element_wise(external_product);
                // ACC = ACC - ACC * (RGSW(s_i_0) - RGSW(s_i_1)*Y^{a_i}) + Y^{-a_i} * ACC * (RGSW(s_i_0) - RGSW(s_i_1)*Y^{a_i})
                //     = ACC + (Y^{-a_i} - 1) * ACC * (RGSW(s_i_0) - RGSW(s_i_1)*Y^{a_i})
                acc.add_assign_rhs_mul_monic_monomial(
                    external_product,
                    rlwe_dimension,
                    twice_rlwe_dimension_div_lwe_modulus,
                    a_i.neg_reduce(lwe_modulus),
                );

                acc
            })
    }
}

impl<F: RandomNTTField> TernaryBootstrappingKey<F> {
    /// Generates the [`TernaryBootstrappingKey<F>`].
    pub(crate) fn generate<Rng>(
        basis: Basis<F>,
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
                if s == 1 {
                    (
                        <NTTRGSW<F>>::generate_one_sample(
                            rlwe_dimension,
                            rlwe_secret_key,
                            basis,
                            chi,
                            &mut rng,
                        ),
                        <NTTRGSW<F>>::generate_zero_sample(
                            rlwe_dimension,
                            rlwe_secret_key,
                            basis,
                            chi,
                            &mut rng,
                        ),
                    )
                } else if s == 0 {
                    (
                        <NTTRGSW<F>>::generate_zero_sample(
                            rlwe_dimension,
                            rlwe_secret_key,
                            basis,
                            chi,
                            &mut rng,
                        ),
                        <NTTRGSW<F>>::generate_zero_sample(
                            rlwe_dimension,
                            rlwe_secret_key,
                            basis,
                            chi,
                            &mut rng,
                        ),
                    )
                } else {
                    (
                        <NTTRGSW<F>>::generate_zero_sample(
                            rlwe_dimension,
                            rlwe_secret_key,
                            basis,
                            chi,
                            &mut rng,
                        ),
                        <NTTRGSW<F>>::generate_one_sample(
                            rlwe_dimension,
                            rlwe_secret_key,
                            basis,
                            chi,
                            &mut rng,
                        ),
                    )
                }
            })
            .collect();
        Self { key }
    }
}
