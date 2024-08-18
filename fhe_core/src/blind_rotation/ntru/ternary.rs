use algebra::{
    transformation::MonomialNTT, AsInto, Basis, FieldDiscreteGaussianSampler, NTTField,
    NTTPolynomial, Polynomial,
};
use lattice::{
    DecompositionSpace, NTRUSpace, NTTGadgetNTRU, NTTGadgetNTRUSpace, NTTNTRUSpace,
    PolynomialSpace, LWE, NTRU,
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

    /// Performs the blind rotation operation.
    pub fn blind_rotate<C: LWEModulusType>(
        &self,
        mut lut: Polynomial<F>,
        lwe: &LWE<C>,
        blind_rotation_basis: Basis<F>,
    ) -> NTRU<F> {
        let ntru_dimension = lut.coeff_count();

        let decompose_space = &mut DecompositionSpace::new(ntru_dimension);
        let polynomial_space = &mut PolynomialSpace::new(ntru_dimension);
        let ntt_ntru_space = &mut NTTNTRUSpace::new(ntru_dimension);
        let external_product = &mut NTRUSpace::new(ntru_dimension);
        let evaluation_key = &mut NTTGadgetNTRUSpace::new(ntru_dimension, blind_rotation_basis);

        let ntt_table = F::get_ntt_table(ntru_dimension.trailing_zeros()).unwrap();

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
                    let a_i: usize = a_i.as_into();

                    let neg_a_i = (ntru_dimension << 1) - a_i;

                    // decompose_space = -X^{-a_i}
                    ntt_table
                        .transform_coeff_neg_one_monomial(neg_a_i, decompose_space.as_mut_slice());

                    // evaluation_key = NTRU'(s_i_0) - NTRU'(s_i_1)*X^{-a_i}
                    s_i.0.add_ntt_gadget_ntru_mul_ntt_polynomial_inplace(
                        &s_i.1,
                        decompose_space,
                        evaluation_key,
                    );

                    // external_product = ACC * evaluation_key
                    //                  = ACC * (NTRU'(s_i_0) - NTRU'(s_i_1)*X^{-a_i})
                    acc.mul_small_ntt_gadget_ntru_inplace(
                        evaluation_key,
                        decompose_space,
                        polynomial_space,
                        ntt_ntru_space,
                        external_product,
                    );

                    // ACC = ACC - external_product
                    //     = ACC - ACC * (NTRU'(s_i_0) - NTRU'(s_i_1)*X^{-a_i})
                    acc.sub_assign_element_wise(external_product);
                    // ACC = ACC - ACC * (NTRU'(s_i_0) - NTRU'(s_i_1)*X^{-a_i}) + X^{a_i} * ACC * (NTRU'(s_i_0) - NTRU'(s_i_1)*X^{-a_i})
                    //     = ACC + (X^{a_i} - 1) * ACC * (NTRU'(s_i_0) - NTRU'(s_i_1)*X^{-a_i})
                    acc.add_assign_rhs_mul_monic_monomial(external_product, ntru_dimension, a_i);
                }
                acc
            })
    }

    /// Generates the [`TernaryBlindRotationKey<F>`].
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
                    (
                        <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                            ntru_inv_secret_key,
                            blind_rotation_basis,
                            chi,
                            rng,
                        ),
                        <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                            ntru_inv_secret_key,
                            blind_rotation_basis,
                            chi,
                            rng,
                        ),
                    )
                } else if s.is_one() {
                    (
                        <NTTGadgetNTRU<F>>::generate_random_one_sample(
                            ntru_inv_secret_key,
                            blind_rotation_basis,
                            chi,
                            rng,
                        ),
                        <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                            ntru_inv_secret_key,
                            blind_rotation_basis,
                            chi,
                            rng,
                        ),
                    )
                } else {
                    (
                        <NTTGadgetNTRU<F>>::generate_random_zero_sample(
                            ntru_inv_secret_key,
                            blind_rotation_basis,
                            chi,
                            rng,
                        ),
                        <NTTGadgetNTRU<F>>::generate_random_one_sample(
                            ntru_inv_secret_key,
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
