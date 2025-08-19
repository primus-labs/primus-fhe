use algebra::{
    decompose::{NonPowOf2ApproxSignedBasis, SignedOnceDecompose},
    ntt::NumberTheoryTransform,
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    random::DiscreteGaussian,
    reduce::ReduceAddAssign,
    utils::Size,
    ByteCount, Field, NttField,
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use crate::{utils::PolyDecomposeSpace, NttRlwe, Rlwe};

use super::NttGadgetRlwe;

/// A representation of Ring Learning with Errors (RLWE) ciphertexts with respect to different powers
/// of a base, used to control noise growth in polynomial multiplications.
///
/// [`GadgetRlwe<F>`] stores a sequence of [`Rlwe<F>`] ciphertexts where each [`Rlwe<F>`] instance within
/// the `data` vector represents a ciphertext of a scaled version of a message `m` by successive
/// powers of the `basis`. The first element of `data` is the ciphertext of `m`, the second is `basis * m`,
/// the third is `basis² * m`, and so on. This is particularly useful in cryptographic operations
/// where reducing the noise growth during the multiplication of RLWE ciphertexts with polynomials is crucial.
///
/// The struct is generic over a type `F` that must implement the [`NttField`] trait, which ensures that
/// the field operations are compatible with Number Theoretic Transforms, a key requirement for
/// efficient polynomial operations in RLWE-based cryptography.
#[derive(Serialize, Deserialize)]
#[serde(bound = "F: NttField")]
pub struct GadgetRlwe<F: NttField> {
    /// A vector of RLWE ciphertexts, each encrypted message with a different power of the `basis`.
    data: Vec<Rlwe<F>>,
    /// The base with respect to which the ciphertexts are scaled.
    basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
}

impl<F: NttField> Clone for GadgetRlwe<F> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            basis: self.basis,
        }
    }
}

impl<F: NttField> GadgetRlwe<F> {
    /// Creates a new [`GadgetRlwe<F>`] from bytes `data`.
    #[inline]
    pub fn from_bytes(
        data: &[u8],
        dimension: usize,
        basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
    ) -> Self {
        let converted_data: &[F::ValueT] = bytemuck::cast_slice(data);

        let data: Vec<Rlwe<F>> = converted_data
            .chunks_exact(dimension << 1)
            .map(|chunk| {
                let (a, b) = unsafe { chunk.split_at_unchecked(dimension) };
                Rlwe {
                    a: FieldPolynomial::from_slice(a),
                    b: FieldPolynomial::from_slice(b),
                }
            })
            .collect();

        assert_eq!(data.len(), basis.decompose_length());

        Self { data, basis }
    }

    /// Creates a new [`GadgetRlwe<F>`] from bytes `data`.
    #[inline]
    pub fn from_bytes_assign(&mut self, data: &[u8], dimension: usize) {
        let converted_data: &[F::ValueT] = bytemuck::cast_slice(data);

        converted_data
            .chunks_exact(dimension << 1)
            .zip(self.iter_mut())
            .for_each(|(chunk, rlwe)| {
                let (a, b) = unsafe { chunk.split_at_unchecked(dimension) };
                rlwe.a.copy_from(a);
                rlwe.b.copy_from(b);
            });
    }

    /// Converts [`GadgetRlwe<F>`] into bytes.
    #[inline]
    pub fn into_bytes(&self, dimension: usize) -> Vec<u8> {
        let size = (self.data.len() << 1) * dimension * <F::ValueT as ByteCount>::BYTES_COUNT;
        let mut result = Vec::with_capacity(size);

        self.iter().for_each(|rlwe| {
            result.extend_from_slice(bytemuck::cast_slice(rlwe.a_slice()));
            result.extend_from_slice(bytemuck::cast_slice(rlwe.b_slice()));
        });

        result
    }

    /// Converts [`GadgetRlwe<F>`] into bytes, stored in `data``.
    #[inline]
    pub fn into_bytes_inplace(&self, data: &mut [u8], dimension: usize) {
        let poly_bytes_count = dimension * <F::ValueT as ByteCount>::BYTES_COUNT;

        data.chunks_exact_mut(poly_bytes_count << 1)
            .zip(self.iter())
            .for_each(|(chunk, rlwe): (&mut [u8], &Rlwe<F>)| {
                let (a, b) = unsafe { chunk.split_at_mut_unchecked(poly_bytes_count) };
                a.copy_from_slice(bytemuck::cast_slice(rlwe.a_slice()));
                b.copy_from_slice(bytemuck::cast_slice(rlwe.b_slice()));
            });
    }

    /// Returns the bytes count of [`GadgetRlwe<T>`].
    #[inline]
    pub fn bytes_count(&self) -> usize {
        self.data.len() * self.data[0].bytes_count()
    }
}

impl<F: NttField> GadgetRlwe<F> {
    /// Creates a new [`GadgetRlwe<F>`].
    #[inline]
    pub fn new(
        data: Vec<Rlwe<F>>,
        basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
    ) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_length());
        Self { data, basis }
    }

    /// Creates a new [`GadgetRlwe<F>`] with reference.
    #[inline]
    pub fn from_ref(
        data: &[Rlwe<F>],
        basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
    ) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_length());
        Self {
            data: data.to_vec(),
            basis,
        }
    }

    /// Creates a [`GadgetRlwe<F>`] with all entries equal to zero.
    #[inline]
    pub fn zero(
        coeff_count: usize,
        basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
    ) -> Self {
        Self {
            data: (0..basis.decompose_length())
                .map(|_| Rlwe::zero(coeff_count))
                .collect(),
            basis,
        }
    }

    /// Set all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.data.iter_mut().for_each(|rlwe| rlwe.set_zero());
    }

    /// Returns a reference to the `data` of this [`GadgetRlwe<F>`].
    #[inline]
    pub fn data(&self) -> &[Rlwe<F>] {
        self.data.as_ref()
    }

    /// Returns a reference to the basis of this [`GadgetRlwe<F>`].
    #[inline]
    pub fn basis(&self) -> &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT> {
        &self.basis
    }

    /// Returns an iterator over the `data` of this [`GadgetRlwe<F>`].
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, Rlwe<F>> {
        self.data.iter()
    }

    /// Converts [`GadgetRlwe<F>`] into [`NttGadgetRlwe<F>`].
    #[inline]
    pub fn to_ntt_gadget_rlwe(self, ntt_table: &<F as NttField>::Table) -> NttGadgetRlwe<F> {
        NttGadgetRlwe::new(
            self.data
                .into_iter()
                .map(|g: Rlwe<F>| g.to_ntt_rlwe(ntt_table))
                .collect(),
            self.basis,
        )
    }

    /// Returns an iterator over the `data` of this [`GadgetRlwe<F>`]
    /// that allows modifying each value.
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, Rlwe<F>> {
        self.data.iter_mut()
    }

    /// Performs addition operation:`self + rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn add_inplace(&self, rhs: &Self, destination: &mut Self) {
        debug_assert_eq!(self.basis, rhs.basis);
        self.iter()
            .zip(rhs.iter())
            .zip(destination.iter_mut())
            .for_each(|((a, b), c)| a.add_inplace(b, c));
    }

    /// Performs subtraction operation:`self - rhs`,
    /// and put the result to the `destination`.
    #[inline]
    pub fn sub_inplace(&self, rhs: &Self, destination: &mut Self) {
        debug_assert_eq!(self.basis, rhs.basis);
        self.iter()
            .zip(rhs.iter())
            .zip(destination.iter_mut())
            .for_each(|((a, b), c)| a.sub_inplace(b, c));
    }

    /// Perform multiplication between [`GadgetRlwe<F>`] and [`FieldPolynomial<F>`],
    /// return a [`Rlwe<F>`].
    pub fn mul_polynomial(
        &self,
        polynomial: &FieldPolynomial<F>,
        ntt_table: &<F as NttField>::Table,
    ) -> Rlwe<F> {
        let coeff_count = polynomial.coeff_count();

        let mut decompose_space = <PolyDecomposeSpace<F>>::new(coeff_count);
        let (adjust_poly, carries, decompose_poly) = decompose_space.get_mut();
        polynomial.init_adjust_poly_carries(self.basis(), carries, adjust_poly);

        let mut ntt_rlwe = <NttRlwe<F>>::zero(coeff_count);
        let mut temp = <NttRlwe<F>>::zero(coeff_count);

        self.iter().zip(self.basis.decompose_iter()).for_each(
            |(g_rlwe, once_decompose): (&Rlwe<F>, SignedOnceDecompose<<F as Field>::ValueT>)| {
                adjust_poly.approx_signed_decompose(
                    once_decompose,
                    carries,
                    decompose_poly.as_mut(),
                );
                ntt_table.transform_slice(decompose_poly.as_mut());
                g_rlwe.mul_ntt_polynomial_inplace(decompose_poly, ntt_table, &mut temp);
                ntt_rlwe.add_assign_element_wise(&temp);
            },
        );

        ntt_rlwe.to_rlwe(ntt_table)
    }

    /// Perform multiplication between [`GadgetRlwe<F>`] and [`FieldPolynomial<F>`],
    /// then add the `rlwe`, return a [`Rlwe<F>`].
    pub fn mul_polynomial_add_rlwe(
        &self,
        polynomial: &FieldPolynomial<F>,
        rlwe: Rlwe<F>,
        ntt_table: &<F as NttField>::Table,
    ) -> Rlwe<F> {
        let coeff_count = polynomial.coeff_count();

        let mut decompose_space = <PolyDecomposeSpace<F>>::new(coeff_count);
        let (adjust_poly, carries, decompose_poly) = decompose_space.get_mut();
        polynomial.init_adjust_poly_carries(self.basis(), carries, adjust_poly);

        let mut ntt_rlwe = rlwe.to_ntt_rlwe(ntt_table);
        let mut temp = <NttRlwe<F>>::zero(coeff_count);

        self.iter().zip(self.basis.decompose_iter()).for_each(
            |(gadget, once_decompose): (&Rlwe<F>, SignedOnceDecompose<<F as Field>::ValueT>)| {
                adjust_poly.approx_signed_decompose(
                    once_decompose,
                    carries,
                    decompose_poly.as_mut(),
                );
                ntt_table.transform_slice(decompose_poly.as_mut());
                gadget.mul_ntt_polynomial_inplace(decompose_poly, ntt_table, &mut temp);
                ntt_rlwe.add_assign_element_wise(&temp);
            },
        );

        ntt_rlwe.to_rlwe(ntt_table)
    }

    /// Generate a `GadgetRlwe<F>` sample which encrypts `0`.
    pub fn generate_random_zero_sample<R>(
        secret_key: &FieldNttPolynomial<F>,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: &DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let data: Vec<Rlwe<F>> = (0..basis.decompose_length())
            .map(|_| <Rlwe<F>>::generate_random_zero_sample(secret_key, gaussian, ntt_table, rng))
            .collect();
        Self {
            data,
            basis: *basis,
        }
    }

    /// Generate a [`GadgetRlwe<F>`] sample which encrypts `1`.
    pub fn generate_random_one_sample<R>(
        secret_key: &FieldNttPolynomial<F>,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: &DiscreteGaussian<<F as Field>::ValueT>,
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
                    <Rlwe<F>>::generate_random_zero_sample(secret_key, gaussian, ntt_table, rng);
                <F as Field>::MODULUS.reduce_add_assign(&mut r.b_mut()[0], scalar);
                r
            })
            .collect();

        Self {
            data,
            basis: *basis,
        }
    }

    /// Generate a [`GadgetRlwe<F>`] sample which encrypts `poly`.
    pub fn generate_random_poly_sample<R>(
        secret_key: &FieldNttPolynomial<F>,
        poly: &FieldPolynomial<F>,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: &DiscreteGaussian<<F as Field>::ValueT>,
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
                    <Rlwe<F>>::generate_random_zero_sample(secret_key, gaussian, ntt_table, rng);
                r.b_mut().add_mul_scalar_assign(poly, scalar);
                r
            })
            .collect();

        Self {
            data,
            basis: *basis,
        }
    }

    /// Generate a [`GadgetRlwe<F>`] sample which encrypts `-s`.
    pub fn generate_random_neg_secret_sample<R>(
        secret_key: &FieldNttPolynomial<F>,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: &DiscreteGaussian<<F as Field>::ValueT>,
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
                    <Rlwe<F>>::generate_random_zero_sample(secret_key, gaussian, ntt_table, rng);
                <F as Field>::MODULUS.reduce_add_assign(&mut r.a_mut()[0], scalar);
                r
            })
            .collect();

        Self {
            data,
            basis: *basis,
        }
    }
}

impl<F: NttField> Size for GadgetRlwe<F> {
    #[inline]
    fn size(&self) -> usize {
        if self.data.is_empty() {
            return 0;
        }
        self.data.len() * self.data[0].size()
    }
}
