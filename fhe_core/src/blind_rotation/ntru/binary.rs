use algebra::{AsInto, Basis, FieldDiscreteGaussianSampler, NTTField, NTTPolynomial, Polynomial};
use lattice::{
    DecompositionSpace, NTRUSpace, NTTGadgetNTRU, NTTNTRUSpace, PolynomialSpace, LWE, NTRU,
};

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
    pub fn blind_rotate<C: LWEModulusType>(&self, mut lut: Polynomial<F>, lwe: &LWE<C>) -> NTRU<F> {
        let ntru_dimension = lut.coeff_count();

        let decompose_space = &mut DecompositionSpace::new(ntru_dimension);
        let polynomial_space = &mut PolynomialSpace::new(ntru_dimension);
        let ntt_ntru_space = &mut NTTNTRUSpace::new(ntru_dimension);
        let external_product = &mut NTRUSpace::new(ntru_dimension);

        // lut * X^{-b}
        if !lwe.b().is_zero() {
            let neg_b = (ntru_dimension << 1) - AsInto::<usize>::as_into(lwe.b());
            if neg_b <= ntru_dimension {
                lut.as_mut_slice().rotate_right(neg_b);
                lut[..neg_b].iter_mut().for_each(|v| *v = v.neg());
            } else {
                let r = neg_b - ntru_dimension;
                lut.as_mut_slice().rotate_right(r);
                lut[r..].iter_mut().for_each(|v| *v = v.neg());
            }
        }

        let acc = NTRU::new(lut);

        self.key
            .iter()
            .zip(lwe.a())
            .fold(acc, |mut acc, (s_i, &a_i)| {
                if !a_i.is_zero() {
                    // external_product = ACC * NTRU'(s_i)
                    acc.mul_small_ntt_gadget_ntru_inplace(
                        s_i,
                        decompose_space,
                        polynomial_space,
                        ntt_ntru_space,
                        external_product,
                    );
                    // ACC = ACC - ACC * NTRU'(s_i)
                    acc.sub_assign_element_wise(external_product);
                    // ACC = ACC - ACC * NTRU'(s_i) + X^{a_i} * ACC * NTRU'(s_i)
                    //     = ACC + (X^{a_i} - 1) * ACC * NTRU'(s_i)
                    acc.add_assign_rhs_mul_monic_monomial(
                        external_product,
                        ntru_dimension,
                        a_i.as_into(),
                    );
                }

                acc
            })
    }

    /// Generates the [`BinaryBlindRotationKey<F>`].
    pub(crate) fn generate<Rng, C>(
        lwe_secret_key: &[C],
        ntru_inv_secret_key: &NTTPolynomial<F>,
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
