use algebra::{
    modulus::PowOf2Modulus, reduce::NegReduce, transformation::MonomialNTT, Basis,
    FieldDiscreteGaussianSampler, NTTField, NTTPolynomial,
};
use lattice::{
    DecompositionSpace, NTTPolynomialSpace, NTTRGSWSpace, NTTRLWESpace, PolynomialSpace, RLWESpace,
    NTTRGSW, RLWE,
};

use crate::LWEModulusType;

#[derive(Debug, Clone)]
pub struct TernaryBlindRotationKey<F: NTTField> {
    key: Vec<(NTTRGSW<F>, NTTRGSW<F>)>,
}

impl<F: NTTField> TernaryBlindRotationKey<F> {
    /// Creates a new [`TernaryBlindRotationKey<F>`].
    #[inline]
    pub fn new(key: Vec<(NTTRGSW<F>, NTTRGSW<F>)>) -> Self {
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
        blind_rotation_basis: Basis<F>,
    ) -> RLWE<F> {
        let decompose_space = &mut DecompositionSpace::new(rlwe_dimension);
        let ntt_polynomial = &mut NTTPolynomialSpace::new(rlwe_dimension);
        let polynomial_space = &mut PolynomialSpace::new(rlwe_dimension);
        let median = &mut NTTRLWESpace::new(rlwe_dimension);
        let external_product = &mut RLWESpace::new(rlwe_dimension);
        let evaluation_key = &mut NTTRGSWSpace::new(rlwe_dimension, blind_rotation_basis);

        let ntt_table = F::get_ntt_table(rlwe_dimension.trailing_zeros()).unwrap();

        self.key
            .iter()
            .zip(lwe_a)
            .fold(init_acc, |mut acc, (s_i, &a_i)| {
                let degree = (a_i as usize) * twice_rlwe_dimension_div_lwe_modulus;

                // ntt_polynomial = -Y^{a_i}
                ntt_table.transform_coeff_neg_one_monomial(degree, ntt_polynomial.as_mut_slice());

                // evaluation_key = RGSW(s_i_0) - RGSW(s_i_1)*Y^{a_i}
                s_i.0.add_ntt_rgsw_mul_ntt_polynomial_inplace(
                    &s_i.1,
                    ntt_polynomial,
                    evaluation_key,
                );

                // external_product = (Y^{-a_i} - 1) * ACC
                acc.mul_monic_monomial_sub_one_inplace(
                    rlwe_dimension,
                    twice_rlwe_dimension_div_lwe_modulus,
                    a_i.neg_reduce(lwe_modulus),
                    external_product,
                );

                // external_product = (Y^{-a_i} - 1) * ACC * (RGSW(s_i_0) - RGSW(s_i_1)*Y^{a_i})
                external_product.mul_assign_ntt_rgsw(
                    evaluation_key,
                    decompose_space,
                    polynomial_space,
                    median,
                );

                // ACC = ACC + (Y^{-a_i} - 1) * ACC * (RGSW(s_i_0) - RGSW(s_i_1)*Y^{a_i})
                acc.add_assign_element_wise(external_product);

                acc
            })
    }

    /// Generates the [`TernaryBlindRotationKey<F>`].
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
                if s == 1 {
                    (
                        <NTTRGSW<F>>::generate_random_one_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            chi,
                            &mut rng,
                        ),
                        <NTTRGSW<F>>::generate_random_zero_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            chi,
                            &mut rng,
                        ),
                    )
                } else if s == 0 {
                    (
                        <NTTRGSW<F>>::generate_random_zero_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            chi,
                            &mut rng,
                        ),
                        <NTTRGSW<F>>::generate_random_zero_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            chi,
                            &mut rng,
                        ),
                    )
                } else {
                    (
                        <NTTRGSW<F>>::generate_random_zero_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            chi,
                            &mut rng,
                        ),
                        <NTTRGSW<F>>::generate_random_one_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
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
