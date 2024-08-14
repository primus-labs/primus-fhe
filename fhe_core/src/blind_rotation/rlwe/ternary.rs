use algebra::{
    modulus::PowOf2Modulus, transformation::MonomialNTT, AsInto, Basis,
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

    /// Performs the blind rotation operation.
    pub fn blind_rotate<C: LWEModulusType>(
        &self,
        init_acc: RLWE<F>,
        lwe_a: &[C],
        rlwe_dimension: usize,
        twice_rlwe_dimension_div_lwe_cipher_modulus: usize,
        lwe_cipher_modulus: PowOf2Modulus<C>,
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
                let degree =
                    AsInto::<usize>::as_into(a_i) * twice_rlwe_dimension_div_lwe_cipher_modulus;

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
                    twice_rlwe_dimension_div_lwe_cipher_modulus,
                    a_i.neg_reduce(lwe_cipher_modulus),
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
    pub(crate) fn generate<Rng, C>(
        lwe_secret_key: &[C],
        rlwe_secret_key: &NTTPolynomial<F>,
        blind_rotation_basis: Basis<F>,
        chi: FieldDiscreteGaussianSampler,
        rng: &mut Rng,
    ) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
        C: LWEModulusType,
    {
        let key = lwe_secret_key
            .iter()
            .map(|&s| {
                if s.is_one() {
                    (
                        <NTTRGSW<F>>::generate_random_one_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            chi,
                            rng,
                        ),
                        <NTTRGSW<F>>::generate_random_zero_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            chi,
                            rng,
                        ),
                    )
                } else if s.is_zero() {
                    (
                        <NTTRGSW<F>>::generate_random_zero_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            chi,
                            rng,
                        ),
                        <NTTRGSW<F>>::generate_random_zero_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            chi,
                            rng,
                        ),
                    )
                } else {
                    (
                        <NTTRGSW<F>>::generate_random_zero_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            chi,
                            rng,
                        ),
                        <NTTRGSW<F>>::generate_random_one_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
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
