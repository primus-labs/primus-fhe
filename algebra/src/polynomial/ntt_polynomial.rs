use std::hash::Hash;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::slice::{Iter, IterMut};

use num_traits::Zero;

use crate::field::Field;

use super::Poly;

/// A polynomial in ntt form, it stores the values of the polynomial at some particular points.
///
/// It supports addition, subtraction, and multiplication.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
pub struct NTTPolynomial<F: Field> {
    data: Vec<F>,
    degree: usize,
}

impl<F: Field> NTTPolynomial<F> {
    /// Creates a new [`NTTPolynomial<F>`].
    #[inline]
    pub fn new(data: Vec<F>) -> Self {
        let degree = data.len();
        Self { data, degree }
    }
}

impl<F: Field> AsRef<NTTPolynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn as_ref(&self) -> &NTTPolynomial<F> {
        self
    }
}

impl<F: Field> AsRef<[F]> for NTTPolynomial<F> {
    #[inline]
    fn as_ref(&self) -> &[F] {
        self.data.as_ref()
    }
}

impl<F: Field> AsMut<[F]> for NTTPolynomial<F> {
    #[inline]
    fn as_mut(&mut self) -> &mut [F] {
        self.data.as_mut()
    }
}

impl<F: Field> Zero for NTTPolynomial<F> {
    #[inline]
    fn zero() -> Self {
        Self {
            data: Vec::new(),
            degree: 0,
        }
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.data.is_empty() || self.data.iter().all(Zero::is_zero)
    }

    #[inline]
    fn set_zero(&mut self) {
        self.data = vec![Zero::zero(); self.degree];
    }
}

impl<F: Field> IntoIterator for NTTPolynomial<F> {
    type Item = F;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<F: Field> Poly<F> for NTTPolynomial<F> {
    #[inline]
    fn coeff_count(&self) -> usize {
        self.degree
    }

    #[inline]
    fn from_slice(vec: &[F]) -> Self {
        Self::from_vec(vec.to_vec())
    }

    #[inline]
    fn from_vec(vec: Vec<F>) -> Self {
        let degree = vec.len();
        Self { data: vec, degree }
    }

    #[inline]
    fn iter(&self) -> Iter<F> {
        self.data.iter()
    }

    #[inline]
    fn iter_mut(&mut self) -> IterMut<F> {
        self.data.iter_mut()
    }
}

impl<F: Field> AddAssign<&NTTPolynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &NTTPolynomial<F>) {
        assert_eq!(self.degree, rhs.degree);
        self.iter_mut().zip(rhs.iter()).for_each(|(l, &r)| *l += r);
    }
}

impl<F: Field> AddAssign for NTTPolynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: NTTPolynomial<F>) {
        AddAssign::add_assign(self, &rhs);
    }
}

impl<F: Field> Add for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: Self) -> Self::Output {
        AddAssign::add_assign(&mut self, &rhs);
        self
    }
}

impl<F: Field> Add<&NTTPolynomial<F>> for NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn add(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        AddAssign::add_assign(&mut self, rhs);
        self
    }
}

impl<F: Field> Add<NTTPolynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn add(self, mut rhs: NTTPolynomial<F>) -> Self::Output {
        AddAssign::add_assign(&mut rhs, self);
        rhs
    }
}

impl<F: Field> Add<&NTTPolynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn add(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        assert_eq!(self.degree, rhs.degree);
        let poly = self.iter().zip(rhs.iter()).map(|(&l, &r)| l + r).collect();
        NTTPolynomial::<F>::new(poly)
    }
}

impl<F: Field> SubAssign for NTTPolynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: NTTPolynomial<F>) {
        SubAssign::sub_assign(self, &rhs);
    }
}
impl<F: Field> SubAssign<&NTTPolynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &NTTPolynomial<F>) {
        assert_eq!(self.degree, rhs.degree);
        self.iter_mut().zip(rhs.iter()).for_each(|(l, &r)| *l -= r);
    }
}

impl<F: Field> Sub for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: Self) -> Self::Output {
        SubAssign::sub_assign(&mut self, &rhs);
        self
    }
}

impl<F: Field> Sub<&NTTPolynomial<F>> for NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn sub(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        SubAssign::sub_assign(&mut self, rhs);
        self
    }
}

impl<F: Field> Sub<NTTPolynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    fn sub(self, mut rhs: NTTPolynomial<F>) -> Self::Output {
        assert_eq!(self.degree, rhs.degree);
        rhs.iter_mut()
            .zip(self.iter())
            .for_each(|(r, &l)| *r = l - *r);

        rhs
    }
}

impl<F: Field> Sub<&NTTPolynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn sub(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        assert_eq!(self.degree, rhs.degree);
        let poly = self.iter().zip(rhs.iter()).map(|(&l, &r)| l - r).collect();
        NTTPolynomial::<F>::new(poly)
    }
}

impl<F: Field> MulAssign<&NTTPolynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &NTTPolynomial<F>) {
        assert_eq!(self.degree, rhs.degree);
        self.iter_mut().zip(rhs.iter()).for_each(|(l, &r)| *l *= r);
    }
}

impl<F: Field> MulAssign for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        MulAssign::mul_assign(self, &rhs);
    }
}

impl<F: Field> Mul for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: Self) -> Self::Output {
        MulAssign::mul_assign(&mut self, &rhs);
        self
    }
}

impl<F: Field> Mul<&NTTPolynomial<F>> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: Field> Mul<NTTPolynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn mul(self, mut rhs: NTTPolynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut rhs, self);
        rhs
    }
}

impl<F: Field> Mul for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn mul(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        assert_eq!(self.degree, rhs.degree);
        let poly = self.iter().zip(rhs.iter()).map(|(&l, &r)| l * r).collect();
        NTTPolynomial::<F>::new(poly)
    }
}

impl<F: Field> Neg for NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn neg(mut self) -> Self::Output {
        self.data.iter_mut().for_each(|e| {
            *e = -*e;
        });
        self
    }
}
