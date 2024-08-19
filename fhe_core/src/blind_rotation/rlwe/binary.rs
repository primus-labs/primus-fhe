use algebra::{AsInto, Basis, FieldDiscreteGaussianSampler, NTTField, NTTPolynomial, Polynomial};
use lattice::{DecompositionSpace, NTTRLWESpace, PolynomialSpace, RLWESpace, LWE, NTTRGSW, RLWE};

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

    /// Performs the blind rotation operation.
    pub fn blind_rotate<C>(&self, mut lut: Polynomial<F>, lwe: &LWE<C>) -> RLWE<F>
    where
        C: LWEModulusType,
    {
        let rlwe_dimension = lut.coeff_count();

        let decompose_space = &mut DecompositionSpace::new(rlwe_dimension);
        let polynomial_space = &mut PolynomialSpace::new(rlwe_dimension);
        let ntt_rlwe_space = &mut NTTRLWESpace::new(rlwe_dimension);
        let external_product = &mut RLWESpace::new(rlwe_dimension);

        // lut * X^{-b}
        if !lwe.b().is_zero() {
            let neg_b = (rlwe_dimension << 1) - AsInto::<usize>::as_into(lwe.b());
            if neg_b <= rlwe_dimension {
                lut.as_mut_slice().rotate_right(neg_b);
                lut[..neg_b].iter_mut().for_each(|v| *v = v.neg());
            } else {
                let r = neg_b - rlwe_dimension;
                lut.as_mut_slice().rotate_right(r);
                lut[r..].iter_mut().for_each(|v| *v = v.neg());
            }
        }

        let acc = RLWE::new(Polynomial::zero(rlwe_dimension), lut);

        self.key
            .iter()
            .zip(lwe.a())
            .fold(acc, |mut acc, (s_i, &a_i)| {
                if !a_i.is_zero() {
                    // external_product = (X^{a_i} - 1) * ACC
                    acc.mul_monic_monomial_sub_one_inplace(
                        rlwe_dimension,
                        a_i.as_into(),
                        external_product,
                    );
                    // external_product = (X^{a_i} - 1) * ACC * RGSW(s_i)
                    external_product.mul_assign_ntt_rgsw(
                        s_i,
                        decompose_space,
                        polynomial_space,
                        ntt_rlwe_space,
                    );
                    // ACC = ACC + (X^{a_i} - 1) * ACC * RGSW(s_i)
                    acc.add_assign_element_wise(external_product);
                }

                acc
            })
    }

    /// Generates the [`BinaryBlindRotationKey<F>`].
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
                if s.is_zero() {
                    <NTTRGSW<F>>::generate_random_zero_sample(
                        rlwe_secret_key,
                        blind_rotation_basis,
                        chi,
                        rng,
                    )
                } else {
                    <NTTRGSW<F>>::generate_random_one_sample(
                        rlwe_secret_key,
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
