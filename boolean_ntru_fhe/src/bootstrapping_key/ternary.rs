use algebra::{
    modulus::PowOf2Modulus, reduce::NegReduce, transformation::MonomialNTT, Basis,
    FieldDiscreteGaussianSampler, NTTField,
};
use lattice::{
    DecompositionSpace, NTRUSpace, NTTGadgetNTRU, NTTGadgetNTRUSpace, NTTNTRUSpace,
    NTTPolynomialSpace, PolynomialSpace, NTRU,
};

use crate::{LWEPlaintext, NTTRingSecretKey};

#[derive(Debug, Clone)]
pub struct TernaryBootstrappingKey<F: NTTField> {
    key: Vec<(NTTGadgetNTRU<F>, NTTGadgetNTRU<F>)>,
}

impl<F: NTTField> TernaryBootstrappingKey<F> {
    /// Creates a new [`TernaryBootstrappingKey<F>`].
    #[inline]
    pub fn new(key: Vec<(NTTGadgetNTRU<F>, NTTGadgetNTRU<F>)>) -> Self {
        Self { key }
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
        let decompose_space = &mut DecompositionSpace::new(ntru_dimension);
        let ntt_polynomial = &mut NTTPolynomialSpace::new(ntru_dimension);
        let polynomial_space = &mut PolynomialSpace::new(ntru_dimension);
        let median = &mut NTTNTRUSpace::new(ntru_dimension);
        let external_product = &mut NTRUSpace::new(ntru_dimension);
        let evaluation_key = &mut NTTGadgetNTRUSpace::new(ntru_dimension, bootstrapping_basis);

        let ntt_table = F::get_ntt_table(ntru_dimension.trailing_zeros()).unwrap();

        self.key
            .iter()
            .zip(lwe_a)
            .fold(init_acc, |mut acc, (s_i, &a_i)| {
                let degree = (a_i as usize) * twice_ntru_dimension_div_lwe_modulus;

                // ntt_polynomial = -Y^{a_i}
                ntt_table.transform_coeff_one_monomial(degree, ntt_polynomial.as_mut_slice());
                ntt_polynomial.neg_assign();

                // evaluation_key = NTRU'(s_i_0) - NTRU'(s_i_1)*Y^{a_i}
                s_i.0.add_ntt_gadget_ntru_mul_ntt_polynomial_inplace(
                    &s_i.1,
                    ntt_polynomial,
                    evaluation_key,
                );

                // external_product = ACC * evaluation_key
                //                  = ACC * (NTRU'(s_i_0) - NTRU'(s_i_1)*Y^{a_i})
                acc.mul_small_ntt_gadget_ntru_inplace(
                    evaluation_key,
                    decompose_space,
                    polynomial_space,
                    median,
                    external_product,
                );

                // ACC = ACC - external_product
                //     = ACC - ACC * (NTRU'(s_i_0) - NTRU'(s_i_1)*Y^{a_i})
                acc.sub_assign_element_wise(external_product);
                // ACC = ACC - ACC * (NTRU'(s_i_0) - NTRU'(s_i_1)*Y^{a_i}) + Y^{-a_i} * ACC * (NTRU'(s_i_0) - NTRU'(s_i_1)*Y^{a_i})
                //     = ACC + (Y^{-a_i} - 1) * ACC * (NTRU'(s_i_0) - NTRU'(s_i_1)*Y^{a_i})
                acc.add_assign_rhs_mul_monic_monomial(
                    external_product,
                    ntru_dimension,
                    twice_ntru_dimension_div_lwe_modulus,
                    a_i.neg_reduce(lwe_modulus),
                );

                acc
            })
    }
}

impl<F: NTTField> TernaryBootstrappingKey<F> {
    /// Generates the [`TernaryBootstrappingKey<F>`].
    pub(crate) fn generate<Rng>(
        bootstrapping_basis: Basis<F>,
        lwe_secret_key: &[LWEPlaintext],
        chi: FieldDiscreteGaussianSampler,
        inv_secret_key: &NTTRingSecretKey<F>,
        mut rng: Rng,
    ) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let key = lwe_secret_key
            .iter()
            .map(|&s| {
                if s == 0 {
                    (
                        <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                            inv_secret_key,
                            bootstrapping_basis,
                            chi,
                            &mut rng,
                        ),
                        <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                            inv_secret_key,
                            bootstrapping_basis,
                            chi,
                            &mut rng,
                        ),
                    )
                } else if s == 1 {
                    (
                        <NTTGadgetNTRU<F>>::generate_random_one_sample(
                            inv_secret_key,
                            bootstrapping_basis,
                            chi,
                            &mut rng,
                        ),
                        <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                            inv_secret_key,
                            bootstrapping_basis,
                            chi,
                            &mut rng,
                        ),
                    )
                } else {
                    (
                        <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                            inv_secret_key,
                            bootstrapping_basis,
                            chi,
                            &mut rng,
                        ),
                        <NTTGadgetNTRU<F>>::generate_random_one_sample(
                            inv_secret_key,
                            bootstrapping_basis,
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
