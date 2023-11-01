use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::slice::{Iter, IterMut};

use num_traits::Zero;

use crate::field::prime_fields::{MulFactor, RootFactor};
use crate::field::{Field, NTTField};
use crate::transformation::NTTTable;

use super::{Poly, Polynomial};

/// A polynomial in ntt form, it stores the values of the polynomial at some particular points.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct NTTPolynomial<F: Field> {
    data: Vec<F>,
}

impl<F: Field> NTTPolynomial<F> {
    /// Creates a new [`NTTPolynomial<F>`].
    #[inline]
    pub fn new(data: Vec<F>) -> Self {
        Self { data }
    }

    /// Drop self, and return the data
    #[inline]
    pub fn data(self) -> Vec<F> {
        self.data
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
        Self { data: Vec::new() }
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.data.is_empty() || self.data.iter().all(Zero::is_zero)
    }

    #[inline]
    fn set_zero(&mut self) {
        let coeff_count = self.coeff_count();
        self.data = vec![Zero::zero(); coeff_count];
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
        self.data.len()
    }

    #[inline]
    fn from_slice(vec: &[F]) -> Self {
        Self::from_vec(vec.to_vec())
    }

    #[inline]
    fn from_vec(vec: Vec<F>) -> Self {
        Self { data: vec }
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
    fn resize(&mut self, new_degree: usize, value: F) {
        self.data.resize(new_degree, value);
    }

    #[inline]
    fn resize_with<FN>(&mut self, new_degree: usize, f: FN)
    where
        FN: FnMut() -> F,
    {
        self.data.resize_with(new_degree, f);
    }
}

impl<F: Field> AddAssign<&NTTPolynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &NTTPolynomial<F>) {
        assert_eq!(self.coeff_count(), rhs.coeff_count());
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
        assert_eq!(self.coeff_count(), rhs.coeff_count());
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
        assert_eq!(self.coeff_count(), rhs.coeff_count());
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
        assert_eq!(self.coeff_count(), rhs.coeff_count());
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
        assert_eq!(self.coeff_count(), rhs.coeff_count());
        let poly = self.iter().zip(rhs.iter()).map(|(&l, &r)| l - r).collect();
        NTTPolynomial::<F>::new(poly)
    }
}

impl<F: Field> MulAssign<&NTTPolynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &NTTPolynomial<F>) {
        assert_eq!(self.coeff_count(), rhs.coeff_count());
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
        assert_eq!(self.coeff_count(), rhs.coeff_count());
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

impl<F> NTTPolynomial<F>
where
    F: NTTField<Table = NTTTable<F>, Root = MulFactor<F>> + Mul<<F as NTTField>::Root, Output = F>,
    MulFactor<F>: RootFactor<F>,
{
    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a vector to a polynomial.
    ///
    /// # Arguments
    ///
    /// * `self` - inputs in bit-reversed order, outputs in normal order
    pub fn inverse_transform_inplace(mut self, ntt_table: &NTTTable<F>) -> Polynomial<F> {
        let values = self.as_mut();
        let log_n = ntt_table.coeff_count_power();

        debug_assert_eq!(values.len(), 1 << log_n);

        let mut root: MulFactor<F>;
        let mut u: F;
        let mut v: F;

        let roots = ntt_table.inv_root_powers();
        let mut root_iter = roots[1..].iter();

        for gap in (0..=1).map(|x| 1usize << x) {
            for vc in values.chunks_exact_mut(gap << 1) {
                root = *root_iter.next().unwrap();
                let (v0, v1) = vc.split_at_mut(gap);
                for (i, j) in std::iter::zip(v0, v1) {
                    u = *i;
                    v = *j;
                    *i = u + v;
                    *j = (u - v) * root;
                }
            }
        }

        for gap in (2..log_n - 1).map(|x| 1usize << x) {
            for vc in values.chunks_exact_mut(gap << 1) {
                root = *root_iter.next().unwrap();
                let (v0, v1) = vc.split_at_mut(gap);
                for (i, j) in std::iter::zip(v0.chunks_exact_mut(4), v1.chunks_exact_mut(4)) {
                    u = i[0];
                    v = j[0];
                    i[0] = u + v;
                    j[0] = (u - v) * root;

                    u = i[1];
                    v = j[1];
                    i[1] = u + v;
                    j[1] = (u - v) * root;

                    u = i[2];
                    v = j[2];
                    i[2] = u + v;
                    j[2] = (u - v) * root;

                    u = i[3];
                    v = j[3];
                    i[3] = u + v;
                    j[3] = (u - v) * root;
                }
            }
        }

        let gap = 1 << (log_n - 1);

        let scalar = *ntt_table.inv_degree();

        root = *root_iter.next().unwrap();
        let scaled_r = MulFactor::<F>::new(root.value() * scalar);
        let (v0, v1) = values.split_at_mut(gap);
        for (i, j) in std::iter::zip(v0.chunks_exact_mut(4), v1.chunks_exact_mut(4)) {
            u = i[0];
            v = j[0];
            i[0] = (u + v) * scalar;
            j[0] = (u - v) * scaled_r;

            u = i[1];
            v = j[1];
            i[1] = (u + v) * scalar;
            j[1] = (u - v) * scaled_r;

            u = i[2];
            v = j[2];
            i[2] = (u + v) * scalar;
            j[2] = (u - v) * scaled_r;

            u = i[3];
            v = j[3];
            i[3] = (u + v) * scalar;
            j[3] = (u - v) * scaled_r;
        }

        Polynomial::<F>::new(self.data)
    }

    /// Perform a fast inverse number theory transform.
    ///
    /// This function transforms a vector to a polynomial.
    ///
    /// # Arguments
    ///
    /// * `self` - inputs in bit-reversed order, outputs in normal order
    pub fn inverse_transform(&self, ntt_table: &NTTTable<F>) -> Polynomial<F> {
        self.clone().inverse_transform_inplace(ntt_table)
    }
}

#[cfg(test)]
mod tests {
    use crate::field::prime_fields::Fp32;

    use super::*;

    #[test]
    fn test_ntt_poly() {
        const P: u32 = 1000000513;
        type Fp = Fp32<P>;
        type PolyFp = NTTPolynomial<Fp>;

        let a = PolyFp::new(vec![Fp::new(1), Fp::new(P - 1)]);
        let b = PolyFp::new(vec![Fp::new(P - 1), Fp::new(1)]);

        let mul_result = PolyFp::new(vec![Fp::new(P - 1), Fp::new(P - 1)]);
        assert_eq!(&a * &b, mul_result);
        assert_eq!(&a * b.clone(), mul_result);
        assert_eq!(a.clone() * &b, mul_result);
        assert_eq!(a.clone() * b.clone(), mul_result);

        let add_result = PolyFp::new(vec![Fp::new(0), Fp::new(0)]);
        assert_eq!(&a + &b, add_result);
        assert_eq!(&a + b.clone(), add_result);
        assert_eq!(a.clone() + &b, add_result);
        assert_eq!(a.clone() + b.clone(), add_result);

        let sub_result = PolyFp::new(vec![Fp::new(2), Fp::new(P - 2)]);
        assert_eq!(&a - &b, sub_result);
        assert_eq!(&a - b.clone(), sub_result);
        assert_eq!(a.clone() - &b, sub_result);
        assert_eq!(a.clone() - b.clone(), sub_result);

        assert_eq!(-a, b);
    }
}
