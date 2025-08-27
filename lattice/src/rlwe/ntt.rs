use std::ops::MulAssign;

use algebra::{
    ntt::NumberTheoryTransform,
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    random::DiscreteGaussian,
    reduce::ReduceAddAssign,
    utils::Size,
    ByteCount, Field, NttField,
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use crate::{utils::PolyDecomposeSpace, NttGadgetRlwe};

use super::Rlwe;

/// A cryptographic structure for Ring Learning with Errors (RLWE).
/// This structure is used in advanced cryptographic systems and protocols, particularly
/// those that require efficient homomorphic encryption properties. It consists of two [`FieldNttPolynomial<F>`]
/// `a` and `b` over a finite field that supports Number Theoretic Transforms (NTT), which is
/// often necessary for efficient polynomial multiplication.
///
/// The [`NttRlwe`] struct is generic over a type `F` which is bounded by the `NttField` trait, ensuring
/// that the operations of addition, subtraction, and multiplication are performed in a field suitable
/// for NTT. This is crucial for the security and correctness of cryptographic operations based on RLWE.
///
/// The fields `a` and `b` are kept private within the crate to maintain encapsulation and are
/// accessible through public API functions that enforce any necessary invariants.
#[derive(Serialize, Deserialize)]
#[serde(bound = "F: NttField")]
pub struct NttRlwe<F: NttField> {
    /// Represents the first component in the RLWE structure.
    pub(crate) a: FieldNttPolynomial<F>,
    /// Represents the second component in the RLWE structure.
    pub(crate) b: FieldNttPolynomial<F>,
}

impl<F: NttField> Eq for NttRlwe<F> {}

impl<F: NttField> PartialEq for NttRlwe<F> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b
    }
}

impl<F: NttField> Clone for NttRlwe<F> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            a: self.a.clone(),
            b: self.b.clone(),
        }
    }
}

impl<F: NttField> NttRlwe<F> {
    /// Creates a new [`NttRlwe<F>`] from bytes `data`.
    #[inline]
    pub fn from_bytes(data: &[u8]) -> Self {
        let converted_data: &[F::ValueT] = bytemuck::cast_slice(data);

        let (a, b) = converted_data.split_at(converted_data.len() >> 1);

        Self {
            a: FieldNttPolynomial::from_slice(a),
            b: FieldNttPolynomial::from_slice(b),
        }
    }

    /// Creates a new [`NttRlwe<F>`] from bytes `data`.
    #[inline]
    pub fn from_bytes_assign(&mut self, data: &[u8]) {
        let converted_data: &[F::ValueT] = bytemuck::cast_slice(data);

        let (a, b) = converted_data.split_at(converted_data.len() >> 1);

        self.a.copy_from(a);
        self.b.copy_from(b);
    }

    /// Converts [`NttRlwe<F>`] into bytes.
    #[inline]
    pub fn into_bytes(&self) -> Vec<u8> {
        let data_a: &[u8] = bytemuck::cast_slice(self.a.as_slice());
        let data_b: &[u8] = bytemuck::cast_slice(self.b.as_slice());

        [data_a, data_b].concat()
    }

    /// Converts [`NttRlwe<F>`] into bytes, stored in `data``.
    #[inline]
    pub fn into_bytes_inplace(&self, data: &mut [u8]) {
        let data_a: &[u8] = bytemuck::cast_slice(self.a.as_slice());
        let data_b: &[u8] = bytemuck::cast_slice(self.b.as_slice());

        assert_eq!(data.len(), data_a.len() + data_b.len());

        let (a, b) = unsafe { data.split_at_mut_unchecked(data_a.len()) };

        a.copy_from_slice(data_a);
        b.copy_from_slice(data_b);
    }

    /// Returns the bytes count of [`NttRlwe<T>`].
    #[inline]
    pub fn bytes_count(&self) -> usize {
        (self.a.coeff_count() << 1) * <F::ValueT as ByteCount>::BYTES_COUNT
    }
}

impl<F: NttField> NttRlwe<F> {
    /// Creates a new [`NttRlwe<F>`].
    #[inline]
    pub fn new(a: FieldNttPolynomial<F>, b: FieldNttPolynomial<F>) -> Self {
        assert_eq!(a.coeff_count(), b.coeff_count());
        Self { a, b }
    }

    /// Given the a and b, drop self.
    #[inline]
    pub fn into_inner(self) -> (FieldNttPolynomial<F>, FieldNttPolynomial<F>) {
        (self.a, self.b)
    }

    /// Creates a new [`NttRlwe<F>`] with reference of [`FieldNttPolynomial<F>`].
    #[inline]
    pub fn from_ref(a: &FieldNttPolynomial<F>, b: &FieldNttPolynomial<F>) -> Self {
        assert_eq!(a.coeff_count(), b.coeff_count());
        Self {
            a: a.clone(),
            b: b.clone(),
        }
    }

    /// Creates a [`NttRlwe<F>`] with all entries equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> NttRlwe<F> {
        Self {
            a: <FieldNttPolynomial<F>>::zero(coeff_count),
            b: <FieldNttPolynomial<F>>::zero(coeff_count),
        }
    }

    /// Set all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.a.set_zero();
        self.b.set_zero();
    }

    /// ntt inverse transform
    #[inline]
    pub fn to_rlwe(self, ntt_table: &<F as NttField>::Table) -> Rlwe<F> {
        let Self { a, b } = self;

        let a = ntt_table.inverse_transform_inplace(a);
        let b = ntt_table.inverse_transform_inplace(b);

        Rlwe::new(a, b)
    }

    /// ntt inverse transform
    #[inline]
    pub fn inverse_transform_inplace(
        &self,
        ntt_table: &<F as NttField>::Table,
        destination: &mut Rlwe<F>,
    ) {
        let (a, b) = destination.a_b_mut_slices();

        a.copy_from_slice(self.a_slice());
        b.copy_from_slice(self.b_slice());

        ntt_table.inverse_transform_slice(a);
        ntt_table.inverse_transform_slice(b);
    }

    /// Returns a reference to the a of this [`NttRlwe<F>`].
    #[inline]
    pub fn a(&self) -> &FieldNttPolynomial<F> {
        &self.a
    }

    /// Returns a mutable reference to the a of this [`NttRlwe<F>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut FieldNttPolynomial<F> {
        &mut self.a
    }

    /// Returns a reference to the b of this [`NttRlwe<F>`].
    #[inline]
    pub fn b(&self) -> &FieldNttPolynomial<F> {
        &self.b
    }

    /// Returns a mutable reference to the b of this [`NttRlwe<F>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut FieldNttPolynomial<F> {
        &mut self.b
    }

    /// Returns a mutable reference to the `a` and `b` of this [`NttRlwe<F>`].
    #[inline]
    pub fn a_b_mut(&mut self) -> (&mut FieldNttPolynomial<F>, &mut FieldNttPolynomial<F>) {
        (&mut self.a, &mut self.b)
    }

    /// Extracts a slice of `a` of this [`NttRlwe<F>`].
    #[inline]
    pub fn a_slice(&self) -> &[<F as Field>::ValueT] {
        self.a.as_slice()
    }

    /// Extracts a mutable slice of `a` of this [`NttRlwe<F>`].
    #[inline]
    pub fn a_mut_slice(&mut self) -> &mut [<F as Field>::ValueT] {
        self.a.as_mut_slice()
    }

    /// Extracts a slice of `b` of this [`NttRlwe<F>`].
    #[inline]
    pub fn b_slice(&self) -> &[<F as Field>::ValueT] {
        self.b.as_slice()
    }

    /// Extracts a mutable slice of `b` of this [`NttRlwe<F>`].
    #[inline]
    pub fn b_mut_slice(&mut self) -> &mut [<F as Field>::ValueT] {
        self.b.as_mut_slice()
    }

    /// Extracts mutable slice of `a` and `b` of this [`NttRlwe<F>`].
    #[inline]
    pub fn a_b_mut_slices(&mut self) -> (&mut [<F as Field>::ValueT], &mut [<F as Field>::ValueT]) {
        (self.a.as_mut_slice(), self.b.as_mut_slice())
    }

    /// Gets the dimension of this [`NttRlwe<F>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.a.coeff_count()
    }

    /// Perform element-wise addition of two [`NttRlwe<F>`].
    #[inline]
    pub fn add_element_wise(self, rhs: &Self) -> Self {
        Self {
            a: self.a + rhs.a(),
            b: self.b + rhs.b(),
        }
    }

    /// Perform element-wise subtraction of two [`NttRlwe<F>`].
    #[inline]
    pub fn sub_element_wise(self, rhs: &Self) -> Self {
        Self {
            a: self.a - rhs.a(),
            b: self.b - rhs.b(),
        }
    }

    /// Performs an in-place element-wise addition
    /// on the `self` [`NttRlwe<F>`] with another `rhs` [`NttRlwe<F>`].
    #[inline]
    pub fn add_assign_element_wise(&mut self, rhs: &Self) {
        self.a += rhs.a();
        self.b += rhs.b();
    }

    /// Performs an in-place element-wise subtraction
    /// on the `self` [`NttRlwe<F>`] with another `rhs` [`NttRlwe<F>`].
    #[inline]
    pub fn sub_assign_element_wise(&mut self, rhs: &Self) {
        self.a -= rhs.a();
        self.b -= rhs.b();
    }

    /// Performs addition operation:`self + rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn add_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.a.add_inplace(rhs.a(), destination.a_mut());
        self.b.add_inplace(rhs.b(), destination.b_mut());
    }

    /// Performs subtraction operation:`self - rhs`,
    /// and put the result to the `destination`.
    #[inline]
    pub fn sub_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.a.sub_inplace(rhs.a(), destination.a_mut());
        self.b.sub_inplace(rhs.b(), destination.b_mut());
    }

    /// Performs a multiplication on the `self` [`NttRlwe<F>`] with another `polynomial` [`FieldNttPolynomial<F>`].
    #[inline]
    pub fn mul_ntt_polynomial_assign(&mut self, polynomial: &FieldNttPolynomial<F>) {
        self.a.mul_assign(polynomial);
        self.b.mul_assign(polynomial);
    }

    /// Performs a multiplication on the `self` [`NttRlwe<F>`] with another `polynomial` [`FieldNttPolynomial<F>`],
    /// stores the result into `destination`.
    #[inline]
    pub fn mul_ntt_polynomial_inplace(
        &self,
        polynomial: &FieldNttPolynomial<F>,
        destination: &mut Self,
    ) {
        self.a.mul_inplace(polynomial, destination.a_mut());
        self.b.mul_inplace(polynomial, destination.b_mut());
    }

    /// Performs `self = self + ntt_rlwe * ntt_polynomial`.
    #[inline]
    pub fn add_ntt_rlwe_mul_ntt_polynomial_assign(
        &mut self,
        ntt_rlwe: &Self,
        ntt_polynomial: &FieldNttPolynomial<F>,
    ) {
        self.a_mut().add_mul_assign(ntt_rlwe.a(), ntt_polynomial);
        self.b_mut().add_mul_assign(ntt_rlwe.b(), ntt_polynomial);
    }

    /// Performs `self = self + ntt_rlwe * ntt_polynomial`.
    ///
    /// The result coefficients may be in [0, 2*modulus) for some case,
    /// and fall back to [0, modulus) for normal case.
    #[inline]
    pub fn add_ntt_rlwe_mul_ntt_polynomial_assign_fast(
        &mut self,
        ntt_rlwe: &Self,
        ntt_polynomial: &FieldNttPolynomial<F>,
    ) {
        self.a_mut()
            .add_mul_assign_fast(ntt_rlwe.a(), ntt_polynomial);
        self.b_mut()
            .add_mul_assign_fast(ntt_rlwe.b(), ntt_polynomial);
    }

    /// Performs `destination = self + ntt_rlwe * ntt_polynomial`.
    #[inline]
    pub fn add_ntt_rlwe_mul_ntt_polynomial_inplace(
        &self,
        ntt_rlwe: &Self,
        ntt_polynomial: &FieldNttPolynomial<F>,
        destination: &mut Self,
    ) {
        ntt_rlwe
            .a()
            .mul_add_inplace(ntt_polynomial, self.a(), destination.a_mut());
        ntt_rlwe
            .b()
            .mul_add_inplace(ntt_polynomial, self.b(), destination.b_mut());
    }

    /// Performs `self = self + gadget_rlwe * polynomial`.
    #[inline]
    pub fn add_assign_gadget_rlwe_mul_polynomial(
        &mut self,
        gadget_rlwe: &NttGadgetRlwe<F>,
        polynomial: &FieldPolynomial<F>,
        ntt_table: &<F as NttField>::Table,
        decompose_space: &mut PolyDecomposeSpace<F>,
    ) {
        let (adjust_poly, carries, decompose_poly) = decompose_space.get_mut();

        polynomial.init_adjust_poly_carries(gadget_rlwe.basis(), carries, adjust_poly);

        gadget_rlwe
            .iter()
            .zip(gadget_rlwe.basis().decompose_iter())
            .for_each(|(g_rlwe, once_decompose)| {
                adjust_poly.approx_signed_decompose(
                    once_decompose,
                    carries,
                    decompose_poly.as_mut(),
                );
                ntt_table.transform_slice(decompose_poly.as_mut());
                self.add_ntt_rlwe_mul_ntt_polynomial_assign(g_rlwe, decompose_poly);
            });
    }

    /// Performs `self = self + gadget_rlwe * polynomial`.
    ///
    /// The result coefficients may be in [0, 2*modulus) for some case,
    /// and fall back to [0, modulus) for normal case.
    #[inline]
    pub fn add_assign_gadget_rlwe_mul_polynomial_fast(
        &mut self,
        gadget_rlwe: &NttGadgetRlwe<F>,
        polynomial: &FieldPolynomial<F>,
        ntt_table: &<F as NttField>::Table,
        decompose_space: &mut PolyDecomposeSpace<F>,
    ) {
        let (adjust_poly, carries, decompose_poly) = decompose_space.get_mut();

        polynomial.init_adjust_poly_carries(gadget_rlwe.basis(), carries, adjust_poly);

        gadget_rlwe
            .iter()
            .zip(gadget_rlwe.basis().decompose_iter())
            .for_each(|(g_rlwe, once_decompose)| {
                adjust_poly.approx_signed_decompose(
                    once_decompose,
                    carries,
                    decompose_poly.as_mut(),
                );
                ntt_table.transform_slice(decompose_poly.as_mut());
                self.add_ntt_rlwe_mul_ntt_polynomial_assign_fast(g_rlwe, decompose_poly);
            });
    }

    /// Performs `self = self - gadget_rlwe * polynomial`.
    #[inline]
    pub fn sub_assign_gadget_rlwe_mul_polynomial(
        &mut self,
        gadget_rlwe: &NttGadgetRlwe<F>,
        polynomial: &FieldPolynomial<F>,
        ntt_table: &<F as NttField>::Table,
        decompose_space: &mut PolyDecomposeSpace<F>,
    ) {
        let (adjust_poly, carries, decompose_poly) = decompose_space.get_mut();
        polynomial.neg_inplace(adjust_poly);
        adjust_poly.init_adjust_poly_carries_assign(gadget_rlwe.basis(), carries);

        gadget_rlwe
            .iter()
            .zip(gadget_rlwe.basis().decompose_iter())
            .for_each(|(g_rlwe, once_decompose)| {
                adjust_poly.approx_signed_decompose(
                    once_decompose,
                    carries,
                    decompose_poly.as_mut(),
                );
                ntt_table.transform_slice(decompose_poly.as_mut());
                self.add_ntt_rlwe_mul_ntt_polynomial_assign(g_rlwe, decompose_poly);
            });
    }

    /// Performs `self = self - gadget_rlwe * polynomial`.
    #[inline]
    pub fn sub_assign_gadget_rlwe_mul_polynomial_fast(
        &mut self,
        gadget_rlwe: &NttGadgetRlwe<F>,
        polynomial: &FieldPolynomial<F>,
        ntt_table: &<F as NttField>::Table,
        decompose_space: &mut PolyDecomposeSpace<F>,
    ) {
        let (adjust_poly, carries, decompose_poly) = decompose_space.get_mut();
        polynomial.neg_inplace(adjust_poly);
        adjust_poly.init_adjust_poly_carries_assign(gadget_rlwe.basis(), carries);

        gadget_rlwe
            .iter()
            .zip(gadget_rlwe.basis().decompose_iter())
            .for_each(|(g_rlwe, once_decompose)| {
                adjust_poly.approx_signed_decompose(
                    once_decompose,
                    carries,
                    decompose_poly.as_mut_slice(),
                );
                ntt_table.transform_slice(decompose_poly.as_mut_slice());
                self.add_ntt_rlwe_mul_ntt_polynomial_assign_fast(g_rlwe, decompose_poly);
            });
    }

    /// Generate a [`NttRlwe<F>`] sample which encrypts `0`.
    pub fn generate_random_zero_sample<R>(
        secret_key: &FieldNttPolynomial<F>,
        gaussian: &DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let rlwe_dimension = secret_key.coeff_count();
        let a = <FieldNttPolynomial<F>>::random(rlwe_dimension, rng);

        let e = <FieldPolynomial<F>>::random_gaussian(rlwe_dimension, gaussian, rng);
        let mut e = ntt_table.transform_inplace(e);
        e.add_mul_assign(&a, secret_key);

        Self { a, b: e }
    }

    /// Generate a [`NttRlwe<F>`] sample which encrypts `value`.
    pub fn generate_random_value_sample<R>(
        secret_key: &FieldNttPolynomial<F>,
        value: <F as Field>::ValueT,
        gaussian: &DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let rlwe_dimension = secret_key.coeff_count();
        let a = <FieldNttPolynomial<F>>::random(rlwe_dimension, rng);

        let mut e = <FieldPolynomial<F>>::random_gaussian(rlwe_dimension, gaussian, rng);
        F::MODULUS.reduce_add_assign(&mut e[0], value);

        let mut b = ntt_table.transform_inplace(e);
        b.add_mul_assign(&a, secret_key);

        Self { a, b }
    }
}

impl<F: NttField> Size for NttRlwe<F> {
    #[inline]
    fn size(&self) -> usize {
        self.a.size() * 2
    }
}
