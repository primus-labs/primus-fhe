use algebra::{
    decompose::{NonPowOf2ApproxSignedBasis, SignedOnceDecompose},
    ntt::NumberTheoryTransform,
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    random::DiscreteGaussian,
    reduce::ReduceAddAssign,
    utils::Size,
    Field, NttField,
};
use rand::{CryptoRng, Rng};

use crate::{utils::PolyDecomposeSpace, NttRlwe};

use super::GadgetRlwe;

/// A representation of Ring Learning with Errors (RLWE) ciphertexts with respect to different powers
/// of a base, used to control noise growth in polynomial multiplications.
///
/// [`NttGadgetRlwe`] stores a sequence of [`NttRlwe`] ciphertexts where each [`NttRlwe<F>`] instance within
/// the `data` vector represents a ciphertext of a scaled version of a message `m` by successive
/// powers of the `basis`. The first element of `data` is the ciphertext of `m`, the second is `basis * m`,
/// the third is `basis² * m`, and so on. This is particularly useful in cryptographic operations
/// where reducing the noise growth during the multiplication of RLWE ciphertexts with polynomials is crucial.
///
/// The struct is generic over a type `F` that must implement the [`NttField`] trait, which ensures that
/// the field operations are compatible with Number Theoretic Transforms, a key requirement for
/// efficient polynomial operations in RLWE-based cryptography.
pub struct NttGadgetRlwe<F: NttField> {
    /// A vector of NTT RLWE ciphertexts, each encrypted message with a different power of the `basis`.
    data: Vec<NttRlwe<F>>,
    /// The base with respect to which the ciphertexts are scaled.
    basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
}

impl<F: NttField> Clone for NttGadgetRlwe<F> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            basis: self.basis,
        }
    }
}

impl<F: NttField> NttGadgetRlwe<F> {
    /// Creates a new [`NttGadgetRlwe<F>`].
    #[inline]
    pub fn new(
        data: Vec<NttRlwe<F>>,
        basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
    ) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_length());
        Self { data, basis }
    }

    /// Creates a new [`NttGadgetRlwe<F>`] with reference.
    #[inline]
    pub fn from_ref(
        data: &[NttRlwe<F>],
        basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
    ) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_length());
        Self {
            data: data.to_vec(),
            basis,
        }
    }

    /// Creates a [`NttGadgetRlwe<F>`] with all entries equal to zero.
    #[inline]
    pub fn zero(
        coeff_count: usize,
        basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
    ) -> Self {
        Self {
            data: (0..basis.decompose_length())
                .map(|_| NttRlwe::zero(coeff_count))
                .collect(),
            basis,
        }
    }

    /// Set all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.data.iter_mut().for_each(|rlwe| rlwe.set_zero());
    }

    /// Returns a reference to the data of this [`NttGadgetRlwe<F>`].
    #[inline]
    pub fn data(&self) -> &[NttRlwe<F>] {
        self.data.as_ref()
    }

    /// Returns the basis of this [`NttGadgetRlwe<F>`].
    #[inline]
    pub fn basis(&self) -> &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT> {
        &self.basis
    }

    /// Returns an iterator over the `data` of this [`NttGadgetRlwe<F>`].
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, NttRlwe<F>> {
        self.data.iter()
    }

    /// Returns an iterator over the `data` of this [`NttGadgetRlwe<F>`]
    /// that allows modifying each value.
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, NttRlwe<F>> {
        self.data.iter_mut()
    }

    /// Converts [`NttGadgetRlwe<F>`] into [`GadgetRlwe<F>`].
    #[inline]
    pub fn to_gadget_rlwe(self, ntt_table: &<F as NttField>::Table) -> GadgetRlwe<F> {
        GadgetRlwe::new(
            self.data
                .into_iter()
                .map(|g: NttRlwe<F>| g.to_rlwe(ntt_table))
                .collect(),
            self.basis,
        )
    }

    /// Performs addition operation:`self + rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn add_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.iter()
            .zip(rhs.iter())
            .zip(destination.iter_mut())
            .for_each(
                |((a, b), c): ((&NttRlwe<F>, &NttRlwe<F>), &mut NttRlwe<F>)| a.add_inplace(b, c),
            );
    }

    /// Performs subtraction operation:`self - rhs`,
    /// and put the result to the `destination`.
    #[inline]
    pub fn sub_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.iter()
            .zip(rhs.iter())
            .zip(destination.iter_mut())
            .for_each(
                |((a, b), c): ((&NttRlwe<F>, &NttRlwe<F>), &mut NttRlwe<F>)| a.sub_inplace(b, c),
            );
    }

    /// Perform `destination = self + rhs * ntt_polynomial`, and store the result into destination.
    #[inline]
    pub fn add_rhs_mul_scalar_inplace(
        &self,
        rhs: &Self,
        scalar: &FieldNttPolynomial<F>,
        destination: &mut Self,
    ) {
        destination
            .iter_mut()
            .zip(self.iter())
            .zip(rhs.iter())
            .for_each(
                |((des, l), r): ((&mut NttRlwe<F>, &NttRlwe<F>), &NttRlwe<F>)| {
                    l.add_ntt_rlwe_mul_ntt_polynomial_inplace(r, scalar, des);
                },
            )
    }

    /// Perform multiplication between [`NttGadgetRlwe<F>`] and [`FieldPolynomial<F>`],
    /// return a [`NttRlwe<F>`].
    pub fn mul_polynomial(
        &self,
        polynomial: &FieldPolynomial<F>,
        ntt_table: &<F as NttField>::Table,
    ) -> NttRlwe<F> {
        let coeff_count = polynomial.coeff_count();

        let mut decompose_space = PolyDecomposeSpace::new(coeff_count);
        let (adjust_poly, carries, decompose_poly) = decompose_space.get_mut();
        polynomial.init_adjust_poly_carries(self.basis(), carries, adjust_poly);

        let mut ntt_rlwe = <NttRlwe<F>>::zero(coeff_count);

        self.iter().zip(self.basis.decompose_iter()).for_each(
            |(gadget, once_decompose): (&NttRlwe<F>, SignedOnceDecompose<<F as Field>::ValueT>)| {
                adjust_poly.approx_signed_decompose(
                    once_decompose,
                    carries,
                    decompose_poly.as_mut(),
                );
                ntt_table.transform_slice(decompose_poly.as_mut());
                ntt_rlwe.add_ntt_rlwe_mul_ntt_polynomial_assign(gadget, decompose_poly);
            },
        );

        ntt_rlwe
    }

    /// Perform multiplication between [`NttGadgetRlwe<F>`] and [`FieldPolynomial<F>`],
    /// stores the result into `destination`.
    pub fn mul_polynomial_inplace(
        &self,
        polynomial: &FieldPolynomial<F>,
        ntt_table: &<F as NttField>::Table,
        decompose_space: &mut PolyDecomposeSpace<F>,
        destination: &mut NttRlwe<F>,
    ) {
        destination.set_zero();

        let (adjust_poly, carries, decompose_poly) = decompose_space.get_mut();

        polynomial.init_adjust_poly_carries(self.basis(), carries, adjust_poly);

        self.iter().zip(self.basis.decompose_iter()).for_each(
            |(g_rlwe, once_decompose): (&NttRlwe<F>, SignedOnceDecompose<<F as Field>::ValueT>)| {
                adjust_poly.approx_signed_decompose(
                    once_decompose,
                    carries,
                    decompose_poly.as_mut_slice(),
                );
                ntt_table.transform_slice(decompose_poly.as_mut_slice());
                destination.add_ntt_rlwe_mul_ntt_polynomial_assign(g_rlwe, decompose_poly);
            },
        )
    }

    /// Perform multiplication between [`NttGadgetRlwe<F>`] and [`FieldPolynomial<F>`],
    /// stores the result into `destination`.
    ///
    /// The coefficients in the `destination` may be in [0, 2*modulus) for some case,
    /// and fall back to [0, modulus) for normal case.
    pub fn mul_polynomial_inplace_fast(
        &self,
        polynomial: &FieldPolynomial<F>,
        ntt_table: &<F as NttField>::Table,
        decompose_space: &mut PolyDecomposeSpace<F>,
        destination: &mut NttRlwe<F>,
    ) {
        destination.set_zero();

        let (adjust_poly, carries, decompose_poly) = decompose_space.get_mut();

        polynomial.init_adjust_poly_carries(self.basis(), carries, adjust_poly);

        self.iter().zip(self.basis.decompose_iter()).for_each(
            |(g_rlwe, once_decompose): (&NttRlwe<F>, SignedOnceDecompose<<F as Field>::ValueT>)| {
                adjust_poly.approx_signed_decompose(
                    once_decompose,
                    carries,
                    decompose_poly.as_mut_slice(),
                );
                ntt_table.transform_slice(decompose_poly.as_mut_slice());
                destination.add_ntt_rlwe_mul_ntt_polynomial_assign_fast(g_rlwe, decompose_poly);
            },
        )
    }

    /// Generate a [`NttGadgetRlwe<F>`] sample which encrypts `0`.
    pub fn generate_random_zero_sample<R>(
        secret_key: &FieldNttPolynomial<F>,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let data = (0..basis.decompose_length())
            .map(|_| {
                <NttRlwe<F>>::generate_random_zero_sample(secret_key, gaussian, ntt_table, rng)
            })
            .collect();
        Self {
            data,
            basis: *basis,
        }
    }

    /// Generate a [`NttGadgetRlwe<F>`] sample which encrypts `1`.
    pub fn generate_random_one_sample<R>(
        secret_key: &FieldNttPolynomial<F>,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let data = basis
            .scalar_iter()
            .map(|scalar| {
                <NttRlwe<F>>::generate_random_value_sample(
                    secret_key, scalar, gaussian, ntt_table, rng,
                )
            })
            .collect();

        Self {
            data,
            basis: *basis,
        }
    }

    /// Generate a [`NttGadgetRlwe<F>`] sample which encrypts `poly`.
    pub fn generate_random_poly_sample<R>(
        secret_key: &FieldNttPolynomial<F>,
        poly: &FieldNttPolynomial<F>,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let data = basis
            .scalar_iter()
            .map(|scalar| {
                let mut r =
                    <NttRlwe<F>>::generate_random_zero_sample(secret_key, gaussian, ntt_table, rng);
                r.b_mut().add_mul_scalar_assign(poly, scalar);
                r
            })
            .collect();

        Self {
            data,
            basis: *basis,
        }
    }

    /// Generate a [`NttGadgetRlwe<F>`] sample which encrypts `-s`.
    pub fn generate_random_neg_secret_sample<R>(
        secret_key: &FieldNttPolynomial<F>,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let data = basis
            .scalar_iter()
            .map(|scalar| {
                let mut r =
                    <NttRlwe<F>>::generate_random_zero_sample(secret_key, gaussian, ntt_table, rng);
                r.a_mut_slice()
                    .iter_mut()
                    .for_each(|v| F::MODULUS.reduce_add_assign(v, scalar));
                r
            })
            .collect();

        Self {
            data,
            basis: *basis,
        }
    }
}

impl<F: NttField> Size for NttGadgetRlwe<F> {
    #[inline]
    fn size(&self) -> usize {
        if self.data.is_empty() {
            return 0;
        }
        self.data.len() * self.data[0].size()
    }
}
