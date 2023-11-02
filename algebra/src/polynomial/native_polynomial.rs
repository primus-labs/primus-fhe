use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};
use std::slice::{Iter, IterMut};

use num_traits::Zero;

use crate::field::prime_fields::{MulFactor, RootFactor};
use crate::field::{Field, NTTField};
use crate::transformation::NTTTable;

use super::Poly;

/// The most basic polynomial, it stores the coefficients of the polynomial.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Polynomial<F: Field> {
    data: Vec<F>,
}

impl<F: Field> Polynomial<F> {
    /// Creates a new [`Polynomial<F>`].
    #[inline]
    pub fn new(poly: Vec<F>) -> Self {
        Self { data: poly }
    }

    /// Drop self, and return the data
    #[inline]
    pub fn data(self) -> Vec<F> {
        self.data
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
        self.data.len()
    }

    #[inline]
    fn from_slice(poly: &[F]) -> Self {
        Self::from_vec(poly.to_vec())
    }

    #[inline]
    fn from_vec(poly: Vec<F>) -> Self {
        Self { data: poly }
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

impl<F: Field> AddAssign<&Polynomial<F>> for Polynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Polynomial<F>) {
        assert_eq!(self.coeff_count(), rhs.coeff_count());
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
        assert_eq!(self.coeff_count(), rhs.coeff_count());
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
        assert_eq!(self.coeff_count(), rhs.coeff_count());
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
        assert_eq!(self.coeff_count(), rhs.coeff_count());
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
        assert_eq!(self.coeff_count(), rhs.coeff_count());
        let poly = self.iter().zip(rhs.iter()).map(|(&l, &r)| l - r).collect();
        Polynomial::<F>::new(poly)
    }
}

// impl<F: Field> MulAssign<&Polynomial<F>> for Polynomial<F> {
//     #[inline]
//     fn mul_assign(&mut self, rhs: &Polynomial<F>) {
//         *self = Mul::mul(&*self, rhs)
//     }
// }

// impl<F: Field> MulAssign<Polynomial<F>> for Polynomial<F> {
//     #[inline]
//     fn mul_assign(&mut self, rhs: Polynomial<F>) {
//         *self = Mul::mul(&*self, &rhs)
//     }
// }

// impl<F: Field> Mul<Polynomial<F>> for Polynomial<F> {
//     type Output = Polynomial<F>;

//     #[inline]
//     fn mul(self, rhs: Polynomial<F>) -> Self::Output {
//         Mul::mul(&self, &rhs)
//     }
// }

// impl<F: Field> Mul<&Polynomial<F>> for Polynomial<F> {
//     type Output = Polynomial<F>;

//     #[inline]
//     fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
//         Mul::mul(&self, rhs)
//     }
// }

// impl<F: Field> Mul<Polynomial<F>> for &Polynomial<F> {
//     type Output = Polynomial<F>;

//     #[inline]
//     fn mul(self, rhs: Polynomial<F>) -> Self::Output {
//         Mul::mul(self, &rhs)
//     }
// }

// impl<F: Field> Mul<&Polynomial<F>> for &Polynomial<F> {
//     type Output = Polynomial<F>;

//     fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
//         assert_eq!(self.coeff_count(), rhs.coeff_count());
//         let coeff_count = self.coeff_count();

//         let mut result = vec![F::zero(); coeff_count];
//         let poly1: &[F] = self.as_ref();
//         let poly2: &[F] = rhs.as_ref();

//         for i in 0..coeff_count {
//             for j in 0..=i {
//                 result[i] += poly1[j] * poly2[i - j];
//             }
//         }

//         // mod (x^n + 1)
//         for i in coeff_count..coeff_count * 2 - 1 {
//             let k = i - coeff_count;
//             for j in i - coeff_count + 1..coeff_count {
//                 result[k] -= poly1[j] * poly2[i - j]
//             }
//         }

//         Polynomial::<F>::new(result)
//     }
// }

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

impl<F: NTTField<Table = NTTTable<F>, Root = MulFactor<F>>> Polynomial<F>
where
    F: Mul<<F as NTTField>::Root, Output = F>,
    MulFactor<F>: RootFactor<F>,
{
    /// The polynomial multiplication
    pub fn mul(&self, rhs: &Self, ntt_table: &NTTTable<F>) -> Polynomial<F> {
        ntt_table.inverse_transform_inplace(ntt_table.transform(self) * ntt_table.transform(rhs))
    }

    /// The polynomial multiplication assignment
    pub fn mul_assign(&mut self, rhs: &Self, ntt_table: &NTTTable<F>) {
        *self = ntt_table
            .inverse_transform_inplace(ntt_table.transform(self) * ntt_table.transform(rhs));
    }
}

#[cfg(test)]
mod tests {
    use crate::field::prime_fields::Fp32;

    use super::*;

    #[test]
    fn test_native_poly() {
        const P: u32 = 1000000513;
        type Fp = Fp32<P>;
        type PolyFp = Polynomial<Fp>;

        let a = PolyFp::new(vec![Fp::new(1), Fp::new(P - 1)]);
        let b = PolyFp::new(vec![Fp::new(P - 1), Fp::new(1)]);

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

    #[test]
    fn test_ntt_mul() {
        const P: u32 = 1000000513;
        type Fp = Fp32<P>;
        type PolyFp = Polynomial<Fp>;

        let ntt_table = Fp::generate_ntt_table(3).unwrap();

        let a = PolyFp::new(vec![
            Fp::new(1),
            Fp::new(1),
            Fp::new(0),
            Fp::new(0),
            Fp::new(0),
            Fp::new(0),
            Fp::new(0),
            Fp::new(0),
        ]);
        let b = PolyFp::new(vec![
            Fp::new(1),
            Fp::new(1),
            Fp::new(0),
            Fp::new(0),
            Fp::new(0),
            Fp::new(0),
            Fp::new(0),
            Fp::new(0),
        ]);

        let mul_result = PolyFp::new(vec![
            Fp::new(1),
            Fp::new(2),
            Fp::new(1),
            Fp::new(0),
            Fp::new(0),
            Fp::new(0),
            Fp::new(0),
            Fp::new(0),
        ]);
        assert_eq!(a.mul(&b, &ntt_table), mul_result);
    }
}
