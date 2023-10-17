use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::slice::{Iter, IterMut};

use num_traits::Zero;

use crate::field::Field;

use super::Poly;

/// The most basic polynomial, it stores the coefficients of the polynomial.
///
/// Due to efficiency, only addition and subtraction are supported, not multiplication.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
pub struct Polynomial<F: Field> {
    data: Vec<F>,
    degree: usize,
}

impl<F: Field> Polynomial<F> {
    /// Creates a new [`Polynomial<F>`].
    #[inline]
    pub fn new(poly: Vec<F>) -> Self {
        let degree = poly.len();
        Self { data: poly, degree }
    }
}

impl<F: Field> AsRef<Polynomial<F>> for Polynomial<F> {
    #[inline]
    fn as_ref(&self) -> &Polynomial<F> {
        self
    }
}

impl<F: Field> AsRef<[F]> for Polynomial<F> {
    #[inline]
    fn as_ref(&self) -> &[F] {
        self.data.as_ref()
    }
}

impl<F: Field> AsMut<[F]> for Polynomial<F> {
    #[inline]
    fn as_mut(&mut self) -> &mut [F] {
        self.data.as_mut()
    }
}

impl<F: Field> Zero for Polynomial<F> {
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

impl<F: Field> IntoIterator for Polynomial<F> {
    type Item = F;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<F: Field> Poly<F> for Polynomial<F> {
    #[inline]
    fn coeff_count(&self) -> usize {
        self.degree
    }

    #[inline]
    fn from_slice(poly: &[F]) -> Self {
        Self::from_vec(poly.to_vec())
    }

    #[inline]
    fn from_vec(poly: Vec<F>) -> Self {
        let degree = poly.len();
        Self { data: poly, degree }
    }

    #[inline]
    fn iter(&self) -> Iter<F> {
        self.data.iter()
    }

    #[inline]
    fn iter_mut(&mut self) -> IterMut<F> {
        self.data.iter_mut()
    }

    #[inline]
    fn alter_degree(&mut self, new_degree: usize, value: F) {
        self.data.resize(new_degree, value);
        self.degree = new_degree;
    }

    #[inline]
    fn alter_degree_with<FN>(&mut self, new_degree: usize, f: FN)
    where
        FN: FnMut() -> F,
    {
        self.data.resize_with(new_degree, f);
        self.degree = new_degree;
    }
}

impl<F: Field> AddAssign<&Polynomial<F>> for Polynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Polynomial<F>) {
        assert_eq!(self.degree, rhs.degree);
        self.iter_mut().zip(rhs.iter()).for_each(|(l, &r)| *l += r);
    }
}

impl<F: Field> AddAssign for Polynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Polynomial<F>) {
        AddAssign::add_assign(self, &rhs)
    }
}

impl<F: Field> Add for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: Self) -> Self::Output {
        AddAssign::add_assign(&mut self, &rhs);
        self
    }
}

impl<F: Field> Add<&Polynomial<F>> for Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn add(mut self, rhs: &Polynomial<F>) -> Self::Output {
        AddAssign::add_assign(&mut self, rhs);
        self
    }
}

impl<F: Field> Add<Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn add(self, mut rhs: Polynomial<F>) -> Self::Output {
        AddAssign::add_assign(&mut rhs, self);
        rhs
    }
}

impl<F: Field> Add<&Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn add(self, rhs: &Polynomial<F>) -> Self::Output {
        assert_eq!(self.degree, rhs.degree);
        let poly = self.iter().zip(rhs.iter()).map(|(&l, &r)| l + r).collect();
        Polynomial::<F>::new(poly)
    }
}

impl<F: Field> SubAssign for Polynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Polynomial<F>) {
        SubAssign::sub_assign(self, &rhs);
    }
}
impl<F: Field> SubAssign<&Polynomial<F>> for Polynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Polynomial<F>) {
        assert_eq!(self.degree, rhs.degree);
        self.iter_mut().zip(rhs.iter()).for_each(|(l, &r)| *l -= r);
    }
}

impl<F: Field> Sub for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: Self) -> Self::Output {
        SubAssign::sub_assign(&mut self, &rhs);
        self
    }
}

impl<F: Field> Sub<&Polynomial<F>> for Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn sub(mut self, rhs: &Polynomial<F>) -> Self::Output {
        SubAssign::sub_assign(&mut self, rhs);
        self
    }
}

impl<F: Field> Sub<Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn sub(self, mut rhs: Polynomial<F>) -> Self::Output {
        assert_eq!(self.degree, rhs.degree);
        rhs.iter_mut()
            .zip(self.iter())
            .for_each(|(r, &l)| *r = l - *r);

        rhs
    }
}

impl<F: Field> Sub<&Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn sub(self, rhs: &Polynomial<F>) -> Self::Output {
        assert_eq!(self.degree, rhs.degree);
        let poly = self.iter().zip(rhs.iter()).map(|(&l, &r)| l - r).collect();
        Polynomial::<F>::new(poly)
    }
}

impl<F: Field> MulAssign<&Polynomial<F>> for Polynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Polynomial<F>) {
        assert_eq!(self.degree, rhs.degree);
        todo!()
    }
}

impl<F: Field> MulAssign<Polynomial<F>> for Polynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Polynomial<F>) {
        MulAssign::mul_assign(self, &rhs);
    }
}

impl<F: Field> Mul<Polynomial<F>> for Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(mut self, rhs: Polynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut self, &rhs);
        self
    }
}

impl<F: Field> Mul<&Polynomial<F>> for Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(mut self, rhs: &Polynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: Field> Mul<Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, mut rhs: Polynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut rhs, self);
        rhs
    }
}

impl<F: Field> Mul<&Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        assert_eq!(self.degree, rhs.degree);
        todo!()
    }
}

impl<F: Field> Neg for Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn neg(mut self) -> Self::Output {
        self.data.iter_mut().for_each(|e| {
            *e = -*e;
        });
        self
    }
}
