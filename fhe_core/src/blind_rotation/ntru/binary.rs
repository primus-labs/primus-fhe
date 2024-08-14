use algebra::{
    modulus::PowOf2Modulus, Basis, FieldDiscreteGaussianSampler, NTTField, NTTPolynomial,
};
use lattice::{DecompositionSpace, NTRUSpace, NTTGadgetNTRU, NTTNTRUSpace, PolynomialSpace, NTRU};

use crate::LWEModulusType;

#[derive(Debug, Clone)]
pub struct BinaryBlindRotationKey<F: NTTField> {
    key: Vec<NTTGadgetNTRU<F>>,
}

impl<F: NTTField> BinaryBlindRotationKey<F> {
    /// Creates a new [`BinaryBlindRotationKey<F>`].
    #[inline]
    pub fn new(key: Vec<NTTGadgetNTRU<F>>) -> Self {
        Self { key }
    }

    /// Performs the blind rotation operation.
    pub fn blind_rotate<C: LWEModulusType>(
        &self,
        init_acc: NTRU<F>,
        lwe_a: &[C],
        ntru_dimension: usize,
        twice_ntru_dimension_div_lwe_cipher_modulus: usize,
        lwe_cipher_modulus: PowOf2Modulus<C>,
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
                    twice_ntru_dimension_div_lwe_cipher_modulus,
                    a_i.neg_reduce(lwe_cipher_modulus),
                );
                acc
            })
    }

    /// Generates the [`BinaryBlindRotationKey<F>`].
    pub(crate) fn generate<Rng, C>(
        lwe_secret_key: &[C],
        ntru_inv_secret_key: &NTTPolynomial<F>,
        blind_rotation_basis: Basis<F>,
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
                if s.is_zero() {
                    <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                        ntru_inv_secret_key,
                        blind_rotation_basis,
                        chi,
                        rng,
                    )
                } else {
                    <NTTGadgetNTRU<F>>::generate_random_one_sample(
                        ntru_inv_secret_key,
                        blind_rotation_basis,
                        chi,
                        rng,
                    )
                }
            })
            .collect();
        BinaryBlindRotationKey::new(key)
    }
}
