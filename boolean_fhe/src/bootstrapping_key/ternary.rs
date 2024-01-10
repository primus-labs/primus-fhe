use algebra::{Basis, NTTField, Random, RandomNTTField, Ring};
use lattice::{NTTRGSW, RLWE};

use crate::secret_key::NTTRLWESecretKey;

use super::{ntt_rgsw_one, ntt_rgsw_zero, BootstrappingPreAllocator};

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
        pre_allocate: &mut BootstrappingPreAllocator<F>,
    ) -> RLWE<F> {
        let (decompose, ntt_rlwe, rlwe0, rlwe1) = pre_allocate.get_all_mut();
        self.key
            .iter()
            .zip(lwe_a)
            .fold(init_acc, |acc, (s_i, &a_i)| {
                // u = 1
                // ACC = ACC + (Y^{-a_i} - 1) * ACC * RGSW(s_i_u)
                acc.mul_small_ntt_rgsw_inplace(&s_i.0, (decompose, ntt_rlwe, rlwe0));
                rlwe0.mul_monic_monomial_sub_one_inplace(
                    rlwe_dimension,
                    twice_rlwe_dimension_div_lwe_modulus,
                    -a_i,
                    rlwe1,
                );
                let acc = acc.add_element_wise(rlwe1);

                // u = -1
                // ACC = ACC + (Y^{a_i} - 1) * ACC * RGSW(s_i_u)
                acc.mul_small_ntt_rgsw_inplace(&s_i.1, (decompose, ntt_rlwe, rlwe0));
                rlwe0.mul_monic_monomial_sub_one_inplace(
                    rlwe_dimension,
                    twice_rlwe_dimension_div_lwe_modulus,
                    a_i,
                    rlwe1,
                );
                acc.add_element_wise(rlwe1)
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
