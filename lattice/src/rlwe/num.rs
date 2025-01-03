use algebra::{
    integer::UnsignedInteger,
    polynomial::NumPolynomial,
    reduce::{ReduceNeg, ReduceNegAssign},
};

use crate::{CmLwe, Lwe};

pub struct NumRlwe<T: UnsignedInteger> {
    /// Represents the first component in the RLWE structure.
    /// It is a polynomial where the coefficients are elements of the field `F`.
    pub(crate) a: NumPolynomial<T>,
    /// Represents the second component in the RLWE structure.
    /// It's also a polynomial with coefficients in the field `F`.
    pub(crate) b: NumPolynomial<T>,
}

impl<T: UnsignedInteger> Default for NumRlwe<T> {
    #[inline]
    fn default() -> Self {
        Self {
            a: Default::default(),
            b: Default::default(),
        }
    }
}

impl<T: UnsignedInteger> NumRlwe<T> {
    /// Creates a new [`NumRlwe<T>`].
    #[inline]
    pub fn new(a: NumPolynomial<T>, b: NumPolynomial<T>) -> Self {
        Self { a, b }
    }

    /// Returns a reference to the a of this [`NumRlwe<T>`].
    #[inline]
    pub fn a(&self) -> &NumPolynomial<T> {
        &self.a
    }

    /// Returns a reference to the b of this [`NumRlwe<T>`].
    #[inline]
    pub fn b(&self) -> &NumPolynomial<T> {
        &self.b
    }

    /// Returns a mutable reference to the a of this [`NumRlwe<T>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut NumPolynomial<T> {
        &mut self.a
    }

    /// Returns a mutable reference to the b of this [`NumRlwe<T>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut NumPolynomial<T> {
        &mut self.b
    }

    /// Returns a mutable reference to the `a` and `b` of this [`NumRlwe<T>`].
    #[inline]
    pub fn a_b_mut(&mut self) -> (&mut NumPolynomial<T>, &mut NumPolynomial<T>) {
        (&mut self.a, &mut self.b)
    }

    /// Extracts a slice of `a` of this [`NumRlwe<T>`].
    #[inline]
    pub fn a_slice(&self) -> &[T] {
        self.a.as_slice()
    }

    /// Extracts a slice of `b` of this [`NumRlwe<T>`].
    #[inline]
    pub fn b_slice(&self) -> &[T] {
        self.b.as_slice()
    }

    /// Extracts a mutable slice of `a` of this [`NumRlwe<T>`].
    #[inline]
    pub fn a_mut_slice(&mut self) -> &mut [T] {
        self.a.as_mut_slice()
    }

    /// Extracts a mutable slice of `b` of this [`NumRlwe<T>`].
    #[inline]
    pub fn b_mut_slice(&mut self) -> &mut [T] {
        self.b.as_mut_slice()
    }

    /// Extracts mutable slice of `a` and `b` of this [`NumRlwe<T>`].
    #[inline]
    pub fn a_b_mut_slices(&mut self) -> (&mut [T], &mut [T]) {
        (self.a.as_mut_slice(), self.b.as_mut_slice())
    }

    /// Creates a new [`NumRlwe<T>`] that is initialized to zero,
    /// both `a` and `b` polynomials are initialized to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> Self {
        Self {
            a: NumPolynomial::zero(coeff_count),
            b: NumPolynomial::zero(coeff_count),
        }
    }

    /// Set all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.a.set_zero();
        self.b.set_zero();
    }

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_lwe_with_index<M>(&self, index: usize, modulus: M) -> Lwe<T>
    where
        M: Copy + ReduceNegAssign<T>,
    {
        let split = index + 1;

        let mut a: Vec<_> = self.a_slice().to_vec();
        a[..split].reverse();
        a[split..].reverse();
        a[split..]
            .iter_mut()
            .for_each(|x| modulus.reduce_neg_assign(x));

        Lwe::new(a, self.b[index])
    }

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_first_few_lwe<M>(&self, count: usize, modulus: M) -> CmLwe<T>
    where
        M: Copy + ReduceNeg<T, Output = T> + ReduceNegAssign<T>,
    {
        let mut a: Vec<_> = self.a.iter().map(|&x| modulus.reduce_neg(x)).collect();
        a[1..].reverse();
        modulus.reduce_neg_assign(&mut a[0]);

        CmLwe::new(a, self.b[..count].to_vec())
    }

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_lwe<M>(&self, modulus: M) -> Lwe<T>
    where
        M: Copy + ReduceNeg<T, Output = T> + ReduceNegAssign<T>,
    {
        let mut a: Vec<_> = self.a.iter().map(|&x| modulus.reduce_neg(x)).collect();
        a[1..].reverse();
        modulus.reduce_neg_assign(&mut a[0]);

        Lwe::new(a, self.b[0])
    }

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_lwe_locally<M>(self, modulus: M) -> Lwe<T>
    where
        M: Copy + ReduceNegAssign<T>,
    {
        let Self { a, b } = self;
        let mut a = a.inner_data();

        a[1..].reverse();
        a[1..].iter_mut().for_each(|v| modulus.reduce_neg_assign(v));

        Lwe::new(a, b[0])
    }

    pub fn extract_first_few_lwe_locally<M>(self, count: usize, modulus: M) -> CmLwe<T>
    where
        M: Copy + ReduceNegAssign<T>,
    {
        let Self { a, b } = self;
        let mut a = a.inner_data();
        let mut b = b.inner_data();

        b.truncate(count);

        a[1..].reverse();
        a[1..].iter_mut().for_each(|v| modulus.reduce_neg_assign(v));

        CmLwe::new(a, b)
    }
}