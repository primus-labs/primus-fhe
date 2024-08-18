use algebra::{
    modulus::PowOf2Modulus, transformation::MonomialNTT, AsInto, Basis,
    FieldDiscreteGaussianSampler, NTTField, NTTPolynomial,
};
use lattice::{
    DecompositionSpace, NTRUSpace, NTTGadgetNTRU, NTTGadgetNTRUSpace, NTTNTRUSpace,
    NTTPolynomialSpace, PolynomialSpace, NTRU,
};

use crate::LWEModulusType;

#[derive(Debug, Clone)]
pub struct TernaryBlindRotationKey<F: NTTField> {
    key: Vec<(NTTGadgetNTRU<F>, NTTGadgetNTRU<F>)>,
}

impl<F: NTTField> TernaryBlindRotationKey<F> {
    /// Creates a new [`TernaryBlindRotationKey<F>`].
    #[inline]
    pub fn new(key: Vec<(NTTGadgetNTRU<F>, NTTGadgetNTRU<F>)>) -> Self {
        Self { key }
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
        let decompose_space = &mut DecompositionSpace::new(ntru_dimension);
        let ntt_polynomial = &mut NTTPolynomialSpace::new(ntru_dimension);
        let polynomial_space = &mut PolynomialSpace::new(ntru_dimension);
        let median = &mut NTTNTRUSpace::new(ntru_dimension);
        let external_product = &mut NTRUSpace::new(ntru_dimension);
        let evaluation_key = &mut NTTGadgetNTRUSpace::new(ntru_dimension, blind_rotation_basis);

        let ntt_table = F::get_ntt_table(ntru_dimension.trailing_zeros()).unwrap();

        self.key
            .iter()
            .zip(lwe_a)
            .fold(init_acc, |mut acc, (s_i, &a_i)| {
                let degree = AsInto::<usize>::as_into(a_i) * twice_ntru_dimension_div_lwe_modulus;

                // ntt_polynomial = -Y^{a_i}
                ntt_table.transform_coeff_neg_one_monomial(degree, ntt_polynomial.as_mut_slice());

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

    /// Generates the [`TernaryBlindRotationKey<F>`].
    pub(crate) fn generate<Rng, C>(
        bootstrapping_basis: Basis<F>,
        lwe_secret_key: &[C],
        chi: FieldDiscreteGaussianSampler,
        inv_secret_key: &NTTPolynomial<F>,
        rng: &mut Rng,
    ) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
        C: LWEModulusType,
    {
        let key = lwe_secret_key
            .iter()
            .map(|&s| {
                if s == C::ZERO {
                    (
                        <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                            inv_secret_key,
                            bootstrapping_basis,
                            chi,
                            rng,
                        ),
                        <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                            inv_secret_key,
                            bootstrapping_basis,
                            chi,
                            rng,
                        ),
                    )
                } else if s == C::ONE {
                    (
                        <NTTGadgetNTRU<F>>::generate_random_one_sample(
                            inv_secret_key,
                            bootstrapping_basis,
                            chi,
                            rng,
                        ),
                        <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                            inv_secret_key,
                            bootstrapping_basis,
                            chi,
                            rng,
                        ),
                    )
                } else {
                    (
                        <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                            inv_secret_key,
                            bootstrapping_basis,
                            chi,
                            rng,
                        ),
                        <NTTGadgetNTRU<F>>::generate_random_one_sample(
                            inv_secret_key,
                            bootstrapping_basis,
                            chi,
                            rng,
                        ),
                    )
                }
            })
            .collect();
        Self { key }
    }
}
