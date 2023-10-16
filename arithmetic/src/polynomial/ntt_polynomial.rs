use std::{
    ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign},
    slice::{Iter, IterMut},
};

use num_traits::Zero;

use crate::algebra::models::{Fp, FpElement};

use super::Poly;

/// A polynomial in ntt form, it stores the values of the polynomial at some particular points.
///
/// It supports addition, subtraction, and multiplication.
#[derive(Clone, Default)]
pub struct NTTPolynomial<const N: usize, const P: FpElement> {
    data: Vec<Fp<P>>,
}

impl<const N: usize, const P: FpElement> AsRef<NTTPolynomial<N, P>> for NTTPolynomial<N, P> {
    fn as_ref(&self) -> &NTTPolynomial<N, P> {
        self
    }
}

impl<const N: usize, const P: FpElement> NTTPolynomial<N, P> {
    /// Creates a new [`NTTPolynomial<N, P>`].
    pub fn new(data: Vec<Fp<P>>) -> Self {
        assert_eq!(data.len(), N);
        Self { data }
    }

    /// Instantiates with provided length,
    /// all coefficients are 0.
    pub fn zero() -> Self {
        Self {
            data: vec![Zero::zero(); N],
        }
    }

    /// Returns a reference to the poly of this [`NTTPolynomial<N, P>`].
    #[inline]
    pub fn data(&self) -> &[Fp<P>] {
        self.data.as_ref()
    }

    /// Returns a mutable reference to the poly of this [`NTTPolynomial<N, P>`].
    #[inline]
    pub fn data_mut(&mut self) -> &mut [Fp<P>] {
        self.data.as_mut_slice()
    }
}

impl<const N: usize, const P: FpElement> IntoIterator for NTTPolynomial<N, P> {
    type Item = Fp<P>;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<const N: usize, const P: FpElement> Poly<N, P> for NTTPolynomial<N, P> {
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

impl<const N: usize, const P: FpElement> AddAssign<&NTTPolynomial<N, P>> for NTTPolynomial<N, P> {
    fn add_assign(&mut self, rhs: &NTTPolynomial<N, P>) {
        self.iter_mut().zip(rhs.iter()).for_each(|(l, &r)| *l += r);
    }
}

impl<const N: usize, const P: FpElement> AddAssign for NTTPolynomial<N, P> {
    fn add_assign(&mut self, rhs: NTTPolynomial<N, P>) {
        *self += &rhs;
    }
}

impl<const N: usize, const P: FpElement> Add for NTTPolynomial<N, P> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<const N: usize, const P: FpElement> Add<&NTTPolynomial<N, P>> for NTTPolynomial<N, P> {
    type Output = NTTPolynomial<N, P>;

    fn add(mut self, rhs: &NTTPolynomial<N, P>) -> Self::Output {
        self += rhs;
        self
    }
}

impl<const N: usize, const P: FpElement> Add<NTTPolynomial<N, P>> for &NTTPolynomial<N, P> {
    type Output = NTTPolynomial<N, P>;

    fn add(self, mut rhs: NTTPolynomial<N, P>) -> Self::Output {
        rhs += self;
        rhs
    }
}

impl<const N: usize, const P: FpElement> Add<&NTTPolynomial<N, P>> for &NTTPolynomial<N, P> {
    type Output = NTTPolynomial<N, P>;

    fn add(self, rhs: &NTTPolynomial<N, P>) -> Self::Output {
        let poly = self.iter().zip(rhs.iter()).map(|(&l, &r)| l + r).collect();
        NTTPolynomial::<N, P>::new(poly)
    }
}

impl<const N: usize, const P: FpElement> SubAssign for NTTPolynomial<N, P> {
    fn sub_assign(&mut self, rhs: NTTPolynomial<N, P>) {
        *self -= &rhs;
    }
}
impl<const N: usize, const P: FpElement> SubAssign<&NTTPolynomial<N, P>> for NTTPolynomial<N, P> {
    fn sub_assign(&mut self, rhs: &NTTPolynomial<N, P>) {
        self.iter_mut().zip(rhs.iter()).for_each(|(l, &r)| *l -= r);
    }
}

impl<const N: usize, const P: FpElement> Sub for NTTPolynomial<N, P> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<const N: usize, const P: FpElement> Sub<&NTTPolynomial<N, P>> for NTTPolynomial<N, P> {
    type Output = NTTPolynomial<N, P>;

    fn sub(mut self, rhs: &NTTPolynomial<N, P>) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<const N: usize, const P: FpElement> Sub<NTTPolynomial<N, P>> for &NTTPolynomial<N, P> {
    type Output = NTTPolynomial<N, P>;

    fn sub(self, mut rhs: NTTPolynomial<N, P>) -> Self::Output {
        rhs.iter_mut()
            .zip(self.iter())
            .for_each(|(r, &l)| *r = l - *r);

        rhs
    }
}

impl<const N: usize, const P: FpElement> Sub<&NTTPolynomial<N, P>> for &NTTPolynomial<N, P> {
    type Output = NTTPolynomial<N, P>;

    fn sub(self, rhs: &NTTPolynomial<N, P>) -> Self::Output {
        let poly = self.iter().zip(rhs.iter()).map(|(&l, &r)| l - r).collect();
        NTTPolynomial::<N, P>::new(poly)
    }
}

impl<const N: usize, const P: FpElement> MulAssign<&NTTPolynomial<N, P>> for NTTPolynomial<N, P> {
    fn mul_assign(&mut self, rhs: &NTTPolynomial<N, P>) {
        self.iter_mut().zip(rhs.iter()).for_each(|(l, &r)| *l *= r);
    }
}

impl<const N: usize, const P: FpElement> MulAssign for NTTPolynomial<N, P> {
    fn mul_assign(&mut self, rhs: Self) {
        *self *= &rhs;
    }
}

impl<const N: usize, const P: FpElement> Mul for NTTPolynomial<N, P> {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<const N: usize, const P: FpElement> Mul<&NTTPolynomial<N, P>> for NTTPolynomial<N, P> {
    type Output = Self;

    fn mul(mut self, rhs: &NTTPolynomial<N, P>) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<const N: usize, const P: FpElement> Mul<NTTPolynomial<N, P>> for &NTTPolynomial<N, P> {
    type Output = NTTPolynomial<N, P>;

    fn mul(self, mut rhs: NTTPolynomial<N, P>) -> Self::Output {
        rhs *= self;
        rhs
    }
}

impl<const N: usize, const P: FpElement> Mul for &NTTPolynomial<N, P> {
    type Output = NTTPolynomial<N, P>;

    fn mul(self, rhs: &NTTPolynomial<N, P>) -> Self::Output {
        let poly = self.iter().zip(rhs.iter()).map(|(&l, &r)| l * r).collect();
        NTTPolynomial::<N, P>::new(poly)
    }
}
