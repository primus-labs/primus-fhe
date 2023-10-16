use std::{
    ops::{Add, AddAssign, Sub, SubAssign},
    slice::{Iter, IterMut},
};

use num_traits::Zero;

use crate::algebra::models::{Fp, FpElement};

use super::Poly;

/// The most basic polynomial, it stores the coefficients of the polynomial.
///
/// Due to efficiency, only addition and subtraction are supported, not multiplication.
#[derive(Clone, Default)]
pub struct Polynomial<const N: usize, const P: FpElement> {
    data: Vec<Fp<P>>,
}

impl<const N: usize, const P: FpElement> AsRef<Polynomial<N, P>> for Polynomial<N, P> {
    #[inline]
    fn as_ref(&self) -> &Polynomial<N, P> {
        self
    }
}

impl<const N: usize, const P: FpElement> Polynomial<N, P> {
    /// Creates a new [`Polynomial<N, P>`].
    pub fn new(poly: Vec<Fp<P>>) -> Self {
        assert_eq!(poly.len(), N);
        Self { data: poly }
    }

    /// Instantiates with provided length,
    /// all coefficients are 0.
    pub fn zero() -> Self {
        Self {
            data: vec![Zero::zero(); N],
        }
    }

    /// Sets all coefficients of this [`Polynomial<N, P>`] to zero.
    pub fn set_zero(&mut self) {
        self.data.fill(Zero::zero());
    }

    /// Returns a reference to the data of this [`Polynomial<N, P>`].
    #[inline]
    pub fn data(&self) -> &[Fp<P>] {
        self.data.as_ref()
    }

    /// Returns a mutable reference to the data of this [`Polynomial<N, P>`].
    #[inline]
    pub fn data_mut(&mut self) -> &mut [Fp<P>] {
        self.data.as_mut_slice()
    }
}

impl<const N: usize, const P: FpElement> IntoIterator for Polynomial<N, P> {
    type Item = Fp<P>;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<const N: usize, const P: FpElement> Poly<N, P> for Polynomial<N, P> {
    fn coeff_count(&self) -> usize {
        N
    }

    fn iter(&self) -> Iter<Fp<P>> {
        self.data.iter()
    }

    fn iter_mut(&mut self) -> IterMut<Fp<P>> {
        self.data.iter_mut()
    }
}

impl<const N: usize, const P: FpElement> Add for Polynomial<N, P> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.iter_mut().zip(rhs.iter()).for_each(|(a, &b)| *a += b);
        self
    }
}

impl<const N: usize, const P: FpElement> AddAssign for Polynomial<N, P> {
    fn add_assign(&mut self, rhs: Self) {
        self.iter_mut().zip(rhs.iter()).for_each(|(a, &b)| *a += b);
    }
}

impl<const N: usize, const P: FpElement> Sub for Polynomial<N, P> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.iter_mut().zip(rhs.iter()).for_each(|(a, &b)| *a -= b);
        self
    }
}

impl<const N: usize, const P: FpElement> SubAssign for Polynomial<N, P> {
    fn sub_assign(&mut self, rhs: Self) {
        self.iter_mut().zip(rhs.iter()).for_each(|(a, &b)| *a += b);
    }
}
