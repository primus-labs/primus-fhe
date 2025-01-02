use std::sync::Arc;

use algebra::{
    decompose::NonPowOf2ApproxSignedBasis,
    integer::{AsInto, UnsignedInteger},
    ntt::{NttTable, NumberTheoryTransform},
    polynomial::FieldPolynomial,
    random::DiscreteGaussian,
    reduce::ReduceNegAssign,
    Field, NttField,
};
use lattice::{
    utils::{NttRgswSpace, NttRlweSpace, PolyDecomposeSpace, RlweSpace},
    NttRgsw, Rlwe,
};
use rand::{CryptoRng, Rng};

use crate::{utils::Pool, LweCiphertext, LweSecretKey, NttRlweSecretKey, RlweCiphertext};

pub struct TernaryBlindRotationKey<F: NttField> {
    key: Vec<(NttRgsw<F>, NttRgsw<F>)>,
    ntt_table: Arc<<F as NttField>::Table>,
    blind_rotation_basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
    space: Pool<BlindRotateSpace<F>>,
}

impl<F: NttField> Clone for TernaryBlindRotationKey<F> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            ntt_table: Arc::clone(&self.ntt_table),
            blind_rotation_basis: self.blind_rotation_basis,
            space: self.space.clone(),
        }
    }
}

struct BlindRotateSpace<F: NttField> {
    decompose_space: PolyDecomposeSpace<F>,
    ntt_rlwe_space: NttRlweSpace<F>,
    rlwe_space: RlweSpace<F>,
    ntt_rgsw: NttRgswSpace<F>,
}

impl<F: NttField> BlindRotateSpace<F> {
    #[inline]
    pub fn new(dimension: usize, basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>) -> Self {
        Self {
            decompose_space: PolyDecomposeSpace::new(dimension),
            ntt_rlwe_space: NttRlweSpace::new(dimension),
            rlwe_space: RlweSpace::new(dimension),
            ntt_rgsw: NttRgswSpace::new(dimension, basis),
        }
    }
}

impl<F: NttField> TernaryBlindRotationKey<F> {
    /// Creates a new [`TernaryBlindRotationKey<F>`].
    #[inline]
    pub fn new(
        key: Vec<(NttRgsw<F>, NttRgsw<F>)>,
        ntt_table: Arc<<F as NttField>::Table>,
        blind_rotation_basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
    ) -> Self {
        Self {
            key,
            ntt_table,
            blind_rotation_basis,
            space: Pool::new(),
        }
    }

    /// Returns a reference to the ntt table of this [`TernaryBlindRotationKey<F>`].
    #[inline]
    pub fn ntt_table(&self) -> &<F as NttField>::Table {
        &self.ntt_table
    }

    /// Returns a reference to the blind rotation basis of this [`TernaryBlindRotationKey<F>`].
    #[inline]
    pub fn blind_rotation_basis(&self) -> &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT> {
        &self.blind_rotation_basis
    }

    /// Performs the blind rotation operation.
    pub fn blind_rotate<C: UnsignedInteger>(
        &self,
        mut lut: FieldPolynomial<F>,
        lwe: &LweCiphertext<C>,
    ) -> RlweCiphertext<F> {
        let ntt_table = self.ntt_table();
        let dimension = ntt_table.dimension();
        assert_eq!(dimension, lut.coeff_count());

        let mut blind_rotate_space = match self.space.get() {
            Some(sp) => sp,
            None => BlindRotateSpace::new(dimension, self.blind_rotation_basis),
        };

        let decompose_space = &mut blind_rotate_space.decompose_space;
        let ntt_rlwe_space = &mut blind_rotate_space.ntt_rlwe_space;
        let external_product = &mut blind_rotate_space.rlwe_space;
        let evaluation_key = &mut blind_rotate_space.ntt_rgsw;

        // lut * X^{-b}
        if !lwe.b().is_zero() {
            let minus_b = (dimension << 1) - AsInto::<usize>::as_into(lwe.b());
            let neg = |v| <F as Field>::MODULUS.reduce_neg_assign(v);
            if minus_b <= dimension {
                lut.as_mut_slice().rotate_right(minus_b);
                lut[..minus_b].iter_mut().for_each(neg);
            } else {
                let r = minus_b - dimension;
                lut.as_mut_slice().rotate_right(r);
                lut[r..].iter_mut().for_each(neg);
            }
        }

        let acc = Rlwe::new(FieldPolynomial::zero(dimension), lut);

        let result = self.key.iter().zip(lwe.a()).fold(
            acc,
            |mut acc: Rlwe<F>, (si, &ai): (&(NttRgsw<F>, NttRgsw<F>), &C)| {
                if !ai.is_zero() {
                    let ai: usize = ai.as_into();

                    let minus_ai: usize = (dimension << 1) - ai;

                    let monomial = &mut decompose_space.decomposed_poly;
                    // monomial = -X^{-a_i}
                    ntt_table.transform_coeff_minus_one_monomial(minus_ai, monomial.as_mut_slice());

                    // evaluation_key = RGSW(s_i_0) - RGSW(s_i_1)*X^{-a_i}
                    si.0.add_rhs_mul_scalar_inplace(&si.1, monomial, evaluation_key);

                    // external_product = (X^{a_i} - 1) * ACC
                    acc.mul_monic_monomial_sub_one_inplace(dimension, ai, external_product);

                    // external_product = (X^{a_i} - 1) * ACC * (RGSW(s_i_0) - RGSW(s_i_1)*X^{-a_i})
                    external_product.mul_assign_ntt_rgsw(
                        evaluation_key,
                        ntt_table,
                        decompose_space,
                        ntt_rlwe_space,
                    );

                    // ACC = ACC + (X^{a_i} - 1) * ACC * (RGSW(s_i_0) - RGSW(s_i_1)*X^{-a_i})
                    acc.add_assign_element_wise(external_product);
                }

                acc
            },
        );

        self.space.store(blind_rotate_space);

        result
    }

    /// Generates the [`TernaryBlindRotationKey<F>`].
    pub(crate) fn generate<R, C>(
        lwe_secret_key: &LweSecretKey<C>,
        rlwe_secret_key: &NttRlweSecretKey<F>,
        blind_rotation_basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: Arc<<F as NttField>::Table>,
        rng: &mut R,
    ) -> Self
    where
        C: UnsignedInteger,
        R: Rng + CryptoRng,
    {
        let key = lwe_secret_key
            .as_ref()
            .iter()
            .map(|&s| {
                if s.is_one() {
                    (
                        <NttRgsw<F>>::generate_random_one_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            gaussian,
                            &ntt_table,
                            rng,
                        ),
                        <NttRgsw<F>>::generate_random_zero_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            gaussian,
                            &ntt_table,
                            rng,
                        ),
                    )
                } else if s.is_zero() {
                    (
                        <NttRgsw<F>>::generate_random_zero_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            gaussian,
                            &ntt_table,
                            rng,
                        ),
                        <NttRgsw<F>>::generate_random_zero_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            gaussian,
                            &ntt_table,
                            rng,
                        ),
                    )
                } else {
                    (
                        <NttRgsw<F>>::generate_random_zero_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            gaussian,
                            &ntt_table,
                            rng,
                        ),
                        <NttRgsw<F>>::generate_random_one_sample(
                            rlwe_secret_key,
                            blind_rotation_basis,
                            gaussian,
                            &ntt_table,
                            rng,
                        ),
                    )
                }
            })
            .collect();

        Self::new(key, Arc::clone(&ntt_table), *blind_rotation_basis)
    }
}
