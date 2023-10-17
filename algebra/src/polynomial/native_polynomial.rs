use std::{
    ops::{Add, AddAssign, Sub, SubAssign},
    slice::{Iter, IterMut},
};

use num_traits::Zero;

use crate::field::prime_fields::{Fp, FpElement};

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
}

impl<const N: usize, const P: FpElement> AsRef<[Fp<P>]> for Polynomial<N, P> {
    fn as_ref(&self) -> &[Fp<P>] {
        self.data.as_ref()
    }
}

impl<const N: usize, const P: FpElement> AsMut<[Fp<P>]> for Polynomial<N, P> {
    fn as_mut(&mut self) -> &mut [Fp<P>] {
        self.data.as_mut()
    }
}

impl<const N: usize, const P: FpElement> Zero for Polynomial<N, P> {
    fn zero() -> Self {
        Self {
            data: vec![Zero::zero(); N],
        }
    }

    fn is_zero(&self) -> bool {
        self.data.iter().all(Zero::is_zero)
    }

    fn set_zero(&mut self) {
        self.data = vec![Zero::zero(); N];
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

impl<const N: usize, const P: FpElement> AddAssign<&Polynomial<N, P>> for Polynomial<N, P> {
    fn add_assign(&mut self, rhs: &Polynomial<N, P>) {
        self.iter_mut().zip(rhs.iter()).for_each(|(l, &r)| *l += r);
    }
}

impl<const N: usize, const P: FpElement> AddAssign for Polynomial<N, P> {
    fn add_assign(&mut self, rhs: Polynomial<N, P>) {
        *self += &rhs;
    }
}

impl<const N: usize, const P: FpElement> Add for Polynomial<N, P> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<const N: usize, const P: FpElement> Add<&Polynomial<N, P>> for Polynomial<N, P> {
    type Output = Polynomial<N, P>;

    fn add(mut self, rhs: &Polynomial<N, P>) -> Self::Output {
        self += rhs;
        self
    }
}

impl<const N: usize, const P: FpElement> Add<Polynomial<N, P>> for &Polynomial<N, P> {
    type Output = Polynomial<N, P>;

    fn add(self, mut rhs: Polynomial<N, P>) -> Self::Output {
        rhs += self;
        rhs
    }
}

impl<const N: usize, const P: FpElement> Add<&Polynomial<N, P>> for &Polynomial<N, P> {
    type Output = Polynomial<N, P>;

    fn add(self, rhs: &Polynomial<N, P>) -> Self::Output {
        let poly = self.iter().zip(rhs.iter()).map(|(&l, &r)| l + r).collect();
        Polynomial::<N, P>::new(poly)
    }
}

impl<const N: usize, const P: FpElement> SubAssign for Polynomial<N, P> {
    fn sub_assign(&mut self, rhs: Polynomial<N, P>) {
        *self -= &rhs;
    }
}
impl<const N: usize, const P: FpElement> SubAssign<&Polynomial<N, P>> for Polynomial<N, P> {
    fn sub_assign(&mut self, rhs: &Polynomial<N, P>) {
        self.iter_mut().zip(rhs.iter()).for_each(|(l, &r)| *l -= r);
    }
}

impl<const N: usize, const P: FpElement> Sub for Polynomial<N, P> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<const N: usize, const P: FpElement> Sub<&Polynomial<N, P>> for Polynomial<N, P> {
    type Output = Polynomial<N, P>;

    fn sub(mut self, rhs: &Polynomial<N, P>) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<const N: usize, const P: FpElement> Sub<Polynomial<N, P>> for &Polynomial<N, P> {
    type Output = Polynomial<N, P>;

    fn sub(self, mut rhs: Polynomial<N, P>) -> Self::Output {
        rhs.iter_mut()
            .zip(self.iter())
            .for_each(|(r, &l)| *r = l - *r);

        rhs
    }
}

impl<const N: usize, const P: FpElement> Sub<&Polynomial<N, P>> for &Polynomial<N, P> {
    type Output = Polynomial<N, P>;

    fn sub(self, rhs: &Polynomial<N, P>) -> Self::Output {
        let poly = self.iter().zip(rhs.iter()).map(|(&l, &r)| l - r).collect();
        Polynomial::<N, P>::new(poly)
    }
}
