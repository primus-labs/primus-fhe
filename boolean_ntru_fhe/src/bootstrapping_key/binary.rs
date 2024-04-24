use algebra::{
    modulus::PowOf2Modulus, reduce::NegReduce, Basis, FieldDiscreteGaussianSampler, NTTField,
};
use lattice::{DecompositionSpace, NTRUSpace, NTTGadgetNTRU, NTTNTRUSpace, PolynomialSpace, NTRU};

use crate::{LWEPlaintext, NTTRingSecretKey};

#[derive(Debug, Clone)]
pub struct BinaryBootstrappingKey<F: NTTField> {
    key: Vec<NTTGadgetNTRU<F>>,
}

impl<F: NTTField> BinaryBootstrappingKey<F> {
    /// Creates a new [`BinaryBootstrappingKey<F>`].
    #[inline]
    pub fn new(key: Vec<NTTGadgetNTRU<F>>) -> Self {
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
}

impl<F: NTTField> BinaryBootstrappingKey<F> {
    /// Generates the [`BinaryBootstrappingKey<F>`].
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
                    <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                        inv_secret_key,
                        bootstrapping_basis,
                        chi,
                        &mut rng,
                    )
                } else {
                    <NTTGadgetNTRU<F>>::generate_random_one_sample(
                        inv_secret_key,
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
