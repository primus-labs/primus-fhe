use algebra::{
    modulus::PowOf2Modulus, Basis, FieldDiscreteGaussianSampler, NTTField, NTTPolynomial,
};
use lattice::{DecompositionSpace, NTTRLWESpace, PolynomialSpace, RLWESpace, NTTRGSW, RLWE};

use crate::LWEModulusType;

#[derive(Debug, Clone)]
pub struct BinaryBlindRotationKey<F: NTTField> {
    key: Vec<NTTRGSW<F>>,
}

impl<F: NTTField> BinaryBlindRotationKey<F> {
    /// Creates a new [`BinaryBlindRotationKey<F>`].
    #[inline]
    pub fn new(key: Vec<NTTRGSW<F>>) -> Self {
        Self { key }
    }

    /// Performs the bootstrapping operation
    pub fn blind_rotate<C: LWEModulusType>(
        &self,
        init_acc: RLWE<F>,
        lwe_a: &[C],
        rlwe_dimension: usize,
        twice_rlwe_dimension_div_lwe_modulus: usize,
        lwe_modulus: PowOf2Modulus<C>,
    ) -> RLWE<F> {
        let decompose_space = &mut DecompositionSpace::new(rlwe_dimension);
        let polynomial_space = &mut PolynomialSpace::new(rlwe_dimension);
        let ntt_rlwe_space = &mut NTTRLWESpace::new(rlwe_dimension);
        let rlwe_space = &mut RLWESpace::new(rlwe_dimension);

        self.key
            .iter()
            .zip(lwe_a)
            .fold(init_acc, |mut acc, (s_i, &a_i)| {
                // rlwe_space = (Y^{-a_i} - 1) * ACC
                acc.mul_monic_monomial_sub_one_inplace(
                    rlwe_dimension,
                    twice_rlwe_dimension_div_lwe_modulus,
                    a_i.neg_reduce(lwe_modulus),
                    rlwe_space,
                );
                // rlwe_space = (Y^{-a_i} - 1) * ACC * RGSW(s_i)
                rlwe_space.mul_assign_ntt_rgsw(
                    s_i,
                    decompose_space,
                    polynomial_space,
                    ntt_rlwe_space,
                );
                // ACC = ACC + (Y^{-a_i} - 1) * ACC * RGSW(s_i)
                acc.add_assign_element_wise(rlwe_space);
                acc
            })
    }

    /// Generates the [`BinaryBlindRotationKey<F>`].
    pub(crate) fn generate<Rng, C>(
        blind_rotation_basis: Basis<F>,
        lwe_secret_key: &[C],
        chi: FieldDiscreteGaussianSampler,
        rlwe_secret_key: &NTTPolynomial<F>,
        mut rng: Rng,
    ) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
        C: LWEModulusType,
    {
        let key = lwe_secret_key
            .iter()
            .map(|&s| {
                if s == C::ZERO {
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
        BinaryBlindRotationKey::new(key)
    }
}
