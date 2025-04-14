use std::sync::Arc;

use algebra::{
    decompose::NonPowOf2ApproxSignedBasis,
    integer::{AsInto, UnsignedInteger},
    ntt::NttTable,
    polynomial::FieldPolynomial,
    random::DiscreteGaussian,
    reduce::ReduceNegAssign,
    utils::Size,
    Field, NttField,
};
use lattice::{
    utils::{NttRlweSpace, PolyDecomposeSpace, RlweSpace},
    NttRgsw, Rlwe,
};
use rand::{CryptoRng, Rng};

use crate::{utils::Pool, LweCiphertext, LweSecretKey, NttRlweSecretKey, RlweCiphertext};

/// The binary blind rotation key.
pub struct BinaryBlindRotationKey<F: NttField> {
    key: Vec<NttRgsw<F>>,
    ntt_table: Arc<<F as NttField>::Table>,
    space: Pool<BlindRotateSpace<F>>,
}

impl<F: NttField> Clone for BinaryBlindRotationKey<F> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            ntt_table: Arc::clone(&self.ntt_table),
            space: self.space.clone(),
        }
    }
}

impl<F: NttField> Size for BinaryBlindRotationKey<F> {
    #[inline]
    fn size(&self) -> usize {
        if self.key.is_empty() {
            return 0;
        }
        self.key.len() * self.key[0].size()
    }
}

/// Preallocated space for blind rotation
struct BlindRotateSpace<F: NttField> {
    decompose_space: PolyDecomposeSpace<F>,
    ntt_rlwe_space: NttRlweSpace<F>,
    rlwe_space: RlweSpace<F>,
}

impl<F: NttField> BlindRotateSpace<F> {
    #[inline]
    pub fn new(dimension: usize) -> Self {
        Self {
            decompose_space: PolyDecomposeSpace::new(dimension),
            ntt_rlwe_space: NttRlweSpace::new(dimension),
            rlwe_space: RlweSpace::new(dimension),
        }
    }
}

impl<F: NttField> BinaryBlindRotationKey<F> {
    /// Creates a new [`BinaryBlindRotationKey<F>`].
    #[inline]
    pub fn new(key: Vec<NttRgsw<F>>, ntt_table: Arc<<F as NttField>::Table>) -> Self {
        Self {
            key,
            ntt_table,
            space: Pool::new(),
        }
    }

    /// Returns a reference to the ntt table of this [`BinaryBlindRotationKey<F>`].
    #[inline]
    pub fn ntt_table(&self) -> &<F as NttField>::Table {
        &self.ntt_table
    }

    /// Performs the blind rotation operation.
    pub fn blind_rotate<C: UnsignedInteger>(
        &self,
        mut lut: FieldPolynomial<F>,
        ciphertext: &LweCiphertext<C>,
    ) -> RlweCiphertext<F> {
        let ntt_table = self.ntt_table();
        let dimension = ntt_table.dimension();
        assert_eq!(dimension, lut.coeff_count());

        let mut blind_rotate_space = match self.space.get() {
            Some(sp) => sp,
            None => BlindRotateSpace::new(dimension),
        };

        let decompose_space = &mut blind_rotate_space.decompose_space;
        let ntt_rlwe_space = &mut blind_rotate_space.ntt_rlwe_space;
        let external_product = &mut blind_rotate_space.rlwe_space;

        // lut * X^{-b}
        if !ciphertext.b().is_zero() {
            let minus_b = (dimension << 1) - AsInto::<usize>::as_into(ciphertext.b());
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

        let acc = RlweCiphertext::new(FieldPolynomial::zero(dimension), lut);

        let result = self.key.iter().zip(ciphertext.a()).fold(
            acc,
            |mut acc: Rlwe<F>, (si, &ai): (&NttRgsw<F>, &C)| {
                if !ai.is_zero() {
                    // external_product = (X^{a_i} - 1) * ACC
                    acc.mul_monic_monomial_sub_one_inplace(
                        dimension,
                        ai.as_into(),
                        external_product,
                    );
                    // external_product = (X^{a_i} - 1) * ACC * RGSW(s_i)
                    external_product.mul_assign_ntt_rgsw(
                        si,
                        ntt_table,
                        decompose_space,
                        ntt_rlwe_space,
                    );
                    // ACC = ACC + (X^{a_i} - 1) * ACC * RGSW(s_i)
                    acc.add_assign_element_wise(external_product);
                }

                acc
            },
        );

        self.space.store(blind_rotate_space);

        result
    }

    /// Generates the [`BinaryBlindRotationKey<F>`].
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
                if s.is_zero() {
                    <NttRgsw<F>>::generate_random_zero_sample(
                        rlwe_secret_key,
                        blind_rotation_basis,
                        gaussian,
                        &ntt_table,
                        rng,
                    )
                } else {
                    <NttRgsw<F>>::generate_random_one_sample(
                        rlwe_secret_key,
                        blind_rotation_basis,
                        gaussian,
                        &ntt_table,
                        rng,
                    )
                }
            })
            .collect();
        BinaryBlindRotationKey::new(key, Arc::clone(&ntt_table))
    }
}
