use algebra::{Basis, NTTField, Random, RandomNTTField, Ring};
use lattice::{DecompositionSpace, NTTRLWESpace, PolynomialSpace, RLWESpace, NTTRGSW, RLWE};

use crate::secret_key::NTTRLWESecretKey;

use super::{ntt_rgsw_one, ntt_rgsw_zero};

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
    pub fn bootstrapping<R: Ring>(
        &self,
        init_acc: RLWE<F>,
        lwe_a: &[R],
        rlwe_dimension: usize,
        twice_rlwe_dimension_div_lwe_modulus: usize,
    ) -> RLWE<F> {
        let decompose_space = &mut DecompositionSpace::new(rlwe_dimension);
        let polynomial_space = &mut PolynomialSpace::new(rlwe_dimension);
        let ntt_rlwe_space = &mut NTTRLWESpace::new(rlwe_dimension);
        let acc_mul_rgsw = &mut RLWESpace::new(rlwe_dimension);
        let median = &mut RLWESpace::new(rlwe_dimension);

        self.key
            .iter()
            .zip(lwe_a)
            .fold(init_acc, |acc, (s_i, &a_i)| {
                // u = 1
                // acc_mul_rgsw = ACC * RGSW(s_i_u)
                acc.mul_small_ntt_rgsw_inplace(
                    &s_i.0,
                    decompose_space,
                    polynomial_space,
                    ntt_rlwe_space,
                    acc_mul_rgsw,
                );
                // median = (Y^{-a_i} - 1) * ACC * RGSW(s_i_u)
                acc_mul_rgsw.mul_monic_monomial_sub_one_inplace(
                    rlwe_dimension,
                    twice_rlwe_dimension_div_lwe_modulus,
                    -a_i,
                    median,
                );
                // ACC = ACC + (Y^{-a_i} - 1) * ACC * RGSW(s_i_u)
                let acc = acc.add_element_wise(median);

                // u = -1
                // acc_mul_rgsw = ACC * RGSW(s_i_u)
                acc.mul_small_ntt_rgsw_inplace(
                    &s_i.1,
                    decompose_space,
                    polynomial_space,
                    ntt_rlwe_space,
                    acc_mul_rgsw,
                );
                // median = (Y^{-a_i} - 1) * ACC * RGSW(s_i_u)
                acc_mul_rgsw.mul_monic_monomial_sub_one_inplace(
                    rlwe_dimension,
                    twice_rlwe_dimension_div_lwe_modulus,
                    a_i,
                    median,
                );
                // ACC = ACC + (Y^{a_i} - 1) * ACC * RGSW(s_i_u)
                acc.add_element_wise(median)
            })
    }
}

impl<F: RandomNTTField> TernaryBootstrappingKey<F> {
    /// Generates the [`TernaryBootstrappingKey<F>`].
    pub(crate) fn generate<R: Ring, Rng>(
        basis: Basis<F>,
        basis_powers: &[F],
        lwe_secret_key: &[R],
        chi: <F as Random>::NormalDistribution,
        rlwe_dimension: usize,
        rlwe_secret_key: &NTTRLWESecretKey<F>,
        mut rng: Rng,
    ) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let key = lwe_secret_key
            .iter()
            .map(|&s| {
                if s.is_one() {
                    (
                        ntt_rgsw_one(
                            rlwe_dimension,
                            rlwe_secret_key,
                            basis,
                            basis_powers,
                            chi,
                            &mut rng,
                        ),
                        ntt_rgsw_zero(rlwe_dimension, rlwe_secret_key, basis, chi, &mut rng),
                    )
                } else if s.is_zero() {
                    (
                        ntt_rgsw_zero(rlwe_dimension, rlwe_secret_key, basis, chi, &mut rng),
                        ntt_rgsw_zero(rlwe_dimension, rlwe_secret_key, basis, chi, &mut rng),
                    )
                } else {
                    (
                        ntt_rgsw_zero(rlwe_dimension, rlwe_secret_key, basis, chi, &mut rng),
                        ntt_rgsw_one(
                            rlwe_dimension,
                            rlwe_secret_key,
                            basis,
                            basis_powers,
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
