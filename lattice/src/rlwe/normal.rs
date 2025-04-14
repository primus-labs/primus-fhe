use algebra::{
    ntt::NumberTheoryTransform,
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    random::DiscreteGaussian,
    reduce::{ReduceAddAssign, ReduceNeg, ReduceNegAssign, ReduceSubAssign},
    utils::Size,
    Field, NttField,
};
use rand::{CryptoRng, Rng};

use super::NttRlwe;

use crate::{
    utils::{NttRlweSpace, PolyDecomposeSpace},
    CmLwe, Lwe, NttRgsw,
};

/// A cryptographic structure for Ring Learning with Errors (RLWE).
/// This structure is used in advanced cryptographic systems and protocols, particularly
/// those that require efficient homomorphic encryption properties. It consists of two [`FieldPolynomial<F>`]
/// `a` and `b` over a finite field that supports Number Theoretic Transforms (NTT), which is
/// often necessary for efficient polynomial multiplication.
///
/// The [`Rlwe<F>`] struct is generic over a type `F` which is bounded by the `Field` trait, ensuring
/// that the operations of addition, subtraction, and multiplication are performed in a field suitable
/// for NTT. This is crucial for the security and correctness of cryptographic operations based on RLWE.
///
/// The fields `a` and `b` are kept private within the crate to maintain encapsulation and are
/// accessible through public API functions that enforce any necessary invariants.
pub struct Rlwe<F: Field> {
    /// Represents the first component in the RLWE structure.
    /// It is a polynomial where the coefficients are elements of the field `F`.
    pub(crate) a: FieldPolynomial<F>,
    /// Represents the second component in the RLWE structure.
    /// It's also a polynomial with coefficients in the field `F`.
    pub(crate) b: FieldPolynomial<F>,
}

impl<F: Field> Eq for Rlwe<F> {}

impl<F: Field> PartialEq for Rlwe<F> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b
    }
}

impl<F: Field> Clone for Rlwe<F> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            a: self.a.clone(),
            b: self.b.clone(),
        }
    }
}

impl<F: Field> Default for Rlwe<F> {
    #[inline]
    fn default() -> Self {
        Self {
            a: FieldPolynomial::new(Vec::new()),
            b: FieldPolynomial::new(Vec::new()),
        }
    }
}

impl<F: Field> Rlwe<F> {
    /// Creates a new [`Rlwe<F>`].
    #[inline]
    pub fn new(a: FieldPolynomial<F>, b: FieldPolynomial<F>) -> Self {
        assert_eq!(a.coeff_count(), b.coeff_count());
        Self { a, b }
    }

    /// Creates a new [`Rlwe<F>`] with reference of [`FieldPolynomial<F>`].
    #[inline]
    pub fn from_ref(a: &FieldPolynomial<F>, b: &FieldPolynomial<F>) -> Self {
        assert_eq!(a.coeff_count(), b.coeff_count());
        Self {
            a: a.clone(),
            b: b.clone(),
        }
    }

    /// Returns a reference to the `a` of this [`Rlwe<F>`].
    #[inline]
    pub fn a(&self) -> &FieldPolynomial<F> {
        &self.a
    }

    /// Returns a reference to the `b` of this [`Rlwe<F>`].
    #[inline]
    pub fn b(&self) -> &FieldPolynomial<F> {
        &self.b
    }

    /// Returns a mutable reference to the `a` of this [`Rlwe<F>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut FieldPolynomial<F> {
        &mut self.a
    }

    /// Returns a mutable reference to the `b` of this [`Rlwe<F>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut FieldPolynomial<F> {
        &mut self.b
    }

    /// Returns a mutable reference to the `a` and `b` of this [`Rlwe<F>`].
    #[inline]
    pub fn a_b_mut(&mut self) -> (&mut FieldPolynomial<F>, &mut FieldPolynomial<F>) {
        (&mut self.a, &mut self.b)
    }

    /// Extracts a slice of `a` of this [`Rlwe<F>`].
    #[inline]
    pub fn a_slice(&self) -> &[<F as Field>::ValueT] {
        self.a.as_slice()
    }

    /// Extracts a mutable slice of `a` of this [`Rlwe<F>`].
    #[inline]
    pub fn a_mut_slice(&mut self) -> &mut [<F as Field>::ValueT] {
        self.a.as_mut_slice()
    }

    /// Extracts a slice of `b` of this [`Rlwe<F>`].
    #[inline]
    pub fn b_slice(&self) -> &[<F as Field>::ValueT] {
        self.b.as_slice()
    }

    /// Extracts a mutable slice of `b` of this [`Rlwe<F>`].
    #[inline]
    pub fn b_mut_slice(&mut self) -> &mut [<F as Field>::ValueT] {
        self.b.as_mut_slice()
    }

    /// Extracts mutable slice of `a` and `b` of this [`Rlwe<F>`].
    #[inline]
    pub fn a_b_mut_slices(&mut self) -> (&mut [<F as Field>::ValueT], &mut [<F as Field>::ValueT]) {
        (self.a.as_mut_slice(), self.b.as_mut_slice())
    }

    /// Gets the dimension of this [`Rlwe<F>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.a.coeff_count()
    }

    /// Creates a new [`Rlwe<F>`] that is initialized to zero.
    ///
    /// The `coeff_count` parameter specifies the number of coefficients in the polynomial.
    /// Both `a` and `b` polynomials of the [`Rlwe<F>`] are initialized with zero coefficients.
    ///
    /// # Arguments
    ///
    /// * `coeff_count` - The number of coefficients in the polynomial.
    ///
    /// # Returns
    ///
    /// A new [`Rlwe<F>`] where both `a` and `b` polynomials are initialized to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> Self {
        Self {
            a: FieldPolynomial::zero(coeff_count),
            b: FieldPolynomial::zero(coeff_count),
        }
    }

    /// Set all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.a.set_zero();
        self.b.set_zero();
    }

    /// Perform element-wise addition of two [`Rlwe<F>`].
    #[inline]
    pub fn add_element_wise(self, rhs: &Self) -> Self {
        Self {
            a: self.a + rhs.a(),
            b: self.b + rhs.b(),
        }
    }

    /// Perform element-wise subtraction of two [`Rlwe<F>`].
    #[inline]
    pub fn sub_element_wise(self, rhs: &Self) -> Self {
        Self {
            a: self.a - rhs.a(),
            b: self.b - rhs.b(),
        }
    }

    /// Performs an in-place element-wise addition
    /// on the `self` [`Rlwe<F>`] with another `rhs` [`Rlwe<F>`].
    #[inline]
    pub fn add_assign_element_wise(&mut self, rhs: &Self) {
        self.a += rhs.a();
        self.b += rhs.b();
    }

    /// Performs an in-place element-wise subtraction
    /// on the `self` [`Rlwe<F>`] with another `rhs` [`Rlwe<F>`].
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

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_lwe_with_index(&self, index: usize) -> Lwe<<F as Field>::ValueT> {
        let split = index + 1;

        let mut a: Vec<_> = self.a_slice().to_vec();

        a[..split].reverse();
        a[split..].reverse();
        a[split..]
            .iter_mut()
            .for_each(|x| F::MODULUS.reduce_neg_assign(x));

        Lwe::new(a, self.b[index])
    }

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_first_few_lwe(&self, count: usize) -> CmLwe<<F as Field>::ValueT> {
        let mut a: Vec<_> = self.a.iter().map(|&x| F::MODULUS.reduce_neg(x)).collect();
        a[1..].reverse();
        F::MODULUS.reduce_neg_assign(&mut a[0]);

        CmLwe::new(a, self.b[..count].to_vec())
    }

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_lwe(&self) -> Lwe<<F as Field>::ValueT> {
        let mut a: Vec<_> = self.a.iter().map(|&x| F::MODULUS.reduce_neg(x)).collect();
        a[1..].reverse();
        F::MODULUS.reduce_neg_assign(&mut a[0]);

        Lwe::new(a, self.b[0])
    }

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_lwe_locally(self) -> Lwe<<F as Field>::ValueT> {
        let Self { a, b } = self;
        let mut a = a.inner_data();
        a[1..].reverse();
        a[1..]
            .iter_mut()
            .for_each(|v| F::MODULUS.reduce_neg_assign(v));

        Lwe::new(a, b[0])
    }

    /// Extract an LWE sample from RLWE reverselly.
    #[inline]
    pub fn extract_lwe_reverse_locally(self) -> Lwe<<F as Field>::ValueT> {
        let Self { a, b } = self;
        Lwe::new(a.inner_data(), b[0])
    }

    /// Extract an LWE sample from RLWE reverselly.
    #[inline]
    pub fn extract_partial_lwe_reverse_locally(
        self,
        dimension: usize,
    ) -> Lwe<<F as Field>::ValueT> {
        let Self { a, b } = self;
        let mut a = a.inner_data();
        a.truncate(dimension);
        Lwe::new(a, b[0])
    }

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_partial_lwe_locally(self, dimension: usize) -> Lwe<<F as Field>::ValueT> {
        let Self { a, b } = self;

        let mut a = a.inner_data();
        a[1..].reverse();
        a[1..]
            .iter_mut()
            .for_each(|v| F::MODULUS.reduce_neg_assign(v));

        a.truncate(dimension);
        Lwe::new(a, b[0])
    }
}

impl<F: NttField> Rlwe<F> {
    /// ntt inverse transform
    #[inline]
    pub fn to_ntt_rlwe(self, ntt_table: &<F as NttField>::Table) -> NttRlwe<F> {
        let Self { a, b } = self;

        let a = ntt_table.transform_inplace(a);
        let b = ntt_table.transform_inplace(b);

        NttRlwe::new(a, b)
    }

    /// ntt inverse transform
    #[inline]
    pub fn transform_inplace(
        &self,
        ntt_table: &<F as NttField>::Table,
        destination: &mut NttRlwe<F>,
    ) {
        let (a, b) = destination.a_b_mut_slices();

        a.copy_from_slice(self.a_slice());
        b.copy_from_slice(self.b_slice());

        ntt_table.transform_slice(a);
        ntt_table.transform_slice(b);
    }

    /// Performs a multiplication on the `self` [`Rlwe<F>`] with another `ntt_polynomial` [`FieldNttPolynomial<F>`],
    /// store the result into `destination` [`NttRlwe<F>`].
    #[inline]
    pub fn mul_ntt_polynomial_inplace(
        &self,
        ntt_polynomial: &FieldNttPolynomial<F>,
        ntt_table: &<F as NttField>::Table,
        destination: &mut NttRlwe<F>,
    ) {
        let (a, b) = destination.a_b_mut();

        a.copy_from(self.a());
        b.copy_from(self.b());

        ntt_table.transform_slice(a.as_mut_slice());
        ntt_table.transform_slice(b.as_mut_slice());

        *a *= ntt_polynomial;
        *b *= ntt_polynomial;
    }

    /// Perform `destination = self * (X^r - 1)`.
    pub fn mul_monic_monomial_sub_one_inplace(
        &self,
        dimension: usize, // N
        r: usize,
        destination: &mut Rlwe<F>,
    ) {
        if r <= dimension {
            #[inline]
            fn rotate_sub<F: NttField>(
                x: &mut FieldPolynomial<F>,
                y: &FieldPolynomial<F>,
                r: usize,
                n_sub_r: usize,
            ) {
                x[0..r]
                    .iter_mut()
                    .zip(y[n_sub_r..].iter())
                    .for_each(|(u, &v)| *u = <F as Field>::MODULUS.reduce_neg(v));
                x[r..]
                    .iter_mut()
                    .zip(y[0..n_sub_r].iter())
                    .for_each(|(u, &v)| *u = v);
                *x -= y;
            }
            let n_sub_r = dimension - r;
            rotate_sub(destination.a_mut(), self.a(), r, n_sub_r);
            rotate_sub(destination.b_mut(), self.b(), r, n_sub_r);
        } else {
            #[inline]
            fn rotate_sub<F: NttField>(
                x: &mut FieldPolynomial<F>,
                y: &FieldPolynomial<F>,
                r: usize,
                n_sub_r: usize,
            ) {
                x[0..r]
                    .iter_mut()
                    .zip(y[n_sub_r..].iter())
                    .for_each(|(u, &v)| *u = v);
                x[r..]
                    .iter_mut()
                    .zip(y[0..n_sub_r].iter())
                    .for_each(|(u, &v)| *u = <F as Field>::MODULUS.reduce_neg(v));
                *x -= y;
            }
            let r = r - dimension;
            let n_sub_r = dimension.checked_sub(r).expect("r > 2N !");
            rotate_sub(destination.a_mut(), self.a(), r, n_sub_r);
            rotate_sub(destination.b_mut(), self.b(), r, n_sub_r);
        }
    }

    /// Perform `self = self + rhs * X^r`.
    pub fn add_assign_rhs_mul_monic_monomial(
        &mut self,
        rhs: &Self,
        dimension: usize, // N
        r: usize,
    ) {
        if r <= dimension {
            #[inline]
            fn rotate_add<F: NttField>(
                x: &mut FieldPolynomial<F>,
                y: &FieldPolynomial<F>,
                r: usize,
                n_sub_r: usize,
            ) {
                x[0..r]
                    .iter_mut()
                    .zip(y[n_sub_r..].iter())
                    .for_each(|(u, &v)| <F as Field>::MODULUS.reduce_sub_assign(u, v));
                x[r..]
                    .iter_mut()
                    .zip(y[0..n_sub_r].iter())
                    .for_each(|(u, &v)| <F as Field>::MODULUS.reduce_add_assign(u, v));
            }
            let n_sub_r = dimension - r;
            rotate_add(self.a_mut(), rhs.a(), r, n_sub_r);
            rotate_add(self.b_mut(), rhs.b(), r, n_sub_r);
        } else {
            #[inline]
            fn rotate_add<F: NttField>(
                x: &mut FieldPolynomial<F>,
                y: &FieldPolynomial<F>,
                r: usize,
                n_sub_r: usize,
            ) {
                x[0..r]
                    .iter_mut()
                    .zip(y[n_sub_r..].iter())
                    .for_each(|(u, &v)| <F as Field>::MODULUS.reduce_add_assign(u, v));
                x[r..]
                    .iter_mut()
                    .zip(y[0..n_sub_r].iter())
                    .for_each(|(u, &v)| <F as Field>::MODULUS.reduce_sub_assign(u, v));
            }
            let r = r - dimension;
            let n_sub_r = dimension.checked_sub(r).unwrap();
            rotate_add(self.a_mut(), rhs.a(), r, n_sub_r);
            rotate_add(self.b_mut(), rhs.b(), r, n_sub_r);
        }
    }

    /// Performs a multiplication on the `self` [`Rlwe<F>`] with another `ntt_rgsw` [`NttRgsw<F>`],
    /// output the [`Rlwe<F>`] result to `destination`.
    ///
    /// # Attention
    /// The message of **`ntt_rgsw`** is restricted to small messages `m`, typically `m = ±Xⁱ`
    #[inline]
    pub fn mul_ntt_rgsw_inplace(
        &self,
        rgsw: &NttRgsw<F>,
        ntt_table: &<F as NttField>::Table,
        decompose_space: &mut PolyDecomposeSpace<F>,
        median: &mut NttRlweSpace<F>,
        destination: &mut Rlwe<F>,
    ) {
        rgsw.minus_s_m()
            .mul_polynomial_inplace_fast(self.a(), ntt_table, decompose_space, median);

        median.add_assign_gadget_rlwe_mul_polynomial_fast(
            rgsw.m(),
            self.b(),
            ntt_table,
            decompose_space,
        );

        median.inverse_transform_inplace(ntt_table, destination)
    }

    /// Performs a multiplication on the `self` [`Rlwe<F>`] with another `ntt_rgsw` [`NttRgsw<F>`],
    /// output the [`Rlwe<F>`] result back to `self`.
    ///
    /// # Attention
    /// The message of **`ntt_rgsw`** is restricted to small messages `m`, typically `m = ±Xⁱ`
    #[inline]
    pub fn mul_assign_ntt_rgsw(
        &mut self,
        rgsw: &NttRgsw<F>,
        ntt_table: &<F as NttField>::Table,
        decompose_space: &mut PolyDecomposeSpace<F>,
        median: &mut NttRlweSpace<F>,
    ) {
        rgsw.minus_s_m()
            .mul_polynomial_inplace_fast(self.a(), ntt_table, decompose_space, median);

        median.add_assign_gadget_rlwe_mul_polynomial_fast(
            rgsw.m(),
            self.b(),
            ntt_table,
            decompose_space,
        );

        median.inverse_transform_inplace(ntt_table, self)
    }

    /// Generate a `Rlwe<F>` sample which encrypts `0`.
    pub fn generate_random_zero_sample<R>(
        secret_key: &FieldNttPolynomial<F>,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let rlwe_dimension = secret_key.coeff_count();
        let a = <FieldPolynomial<F>>::random(rlwe_dimension, rng);

        let mut a_ntt = ntt_table.transform(&a);
        a_ntt *= secret_key;

        let mut e = <FieldPolynomial<F>>::random_gaussian(rlwe_dimension, gaussian, rng);
        e += ntt_table.inverse_transform_inplace(a_ntt);

        Self { a, b: e }
    }
}

impl<F: Field> Size for Rlwe<F> {
    #[inline]
    fn size(&self) -> usize {
        self.a.size() * 2
    }
}
