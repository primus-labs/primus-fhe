use std::ops::{Add, AddAssign, Index, IndexMut, Mul, MulAssign, Neg, Sub, SubAssign};
use std::slice::{Iter, IterMut, SliceIndex};

use num_traits::Zero;

use crate::field::{Field, NTTField};
use crate::transformation::AbstractNTT;

use super::{NTTPolynomial, Poly};

/// Represents a polynomial where coefficients are elements of a specified field `F`.
///
/// The `Polynomial` struct is generic over a type `F` that must implement the `Field` trait, ensuring
/// that the polynomial coefficients can support field operations such as addition, subtraction,
/// multiplication, and division, where division is by a non-zero element. These operations are
/// fundamental in various areas of mathematics and computer science, especially in algorithms that involve
/// polynomial arithmetic in fields, such as error-correcting codes, cryptography, and numerical analysis.
///
/// The coefficients of the polynomial are stored in a vector `data`, with the `i`-th element
/// representing the coefficient of the `x^i` term. The vector is ordered from the constant term
/// at index 0 to the highest non-zero term. This struct can represent both dense and sparse polynomials,
/// but it doesn't inherently optimize for sparse representations.
///
/// # Fields
/// * `data: Vec<F>` - A vector of field elements representing the coefficients of the polynomial.
///
/// # Examples
/// ```ignore
/// // Assuming `F` implements `Field` and `Polynomial` is correctly defined.
/// let coeffs = vec![1, 2, 3];
/// let poly = Polynomial::new(coeffs);
/// // `poly` now represents the polynomial 1 + 2x + 3x^2.
/// ```
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Polynomial<F: Field> {
    data: Vec<F>,
}

impl<F: Field> From<Vec<F>> for Polynomial<F> {
    fn from(value: Vec<F>) -> Self {
        Self { data: value }
    }
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

    /// Creates a [`NTTPolynomial<F>`] with all coefficients equal to zero.
    #[inline]
    pub fn zero_with_coeff_count(coeff_count: usize) -> Self {
        Self {
            data: vec![Zero::zero(); coeff_count],
        }
    }

    /// Constructs a new, empty [`Polynomial<F>`] with at least the specified capacity.
    #[inline]
    fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Appends an element to the back of a [`Polynomial<F>`].
    #[inline]
    fn push(&mut self, value: F) {
        self.data.push(value)
    }

    /// Multipile `self` with the a scalar.
    #[inline]
    pub fn mul_scalar(&self, scalar: F::Scalar) -> Self {
        Self::new(
            self.iter()
                .map(|v| v.mul_scalar(scalar))
                .collect::<Vec<F>>(),
        )
    }
}

impl<F: Field, I: SliceIndex<[F]>> IndexMut<I> for Polynomial<F> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut *self.data, index)
    }
}

impl<F: Field, I: SliceIndex<[F]>> Index<I> for Polynomial<F> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.data, index)
    }
}

impl<F: NTTField> Polynomial<F> {
    /// Decompose `self` according to `basis`.
    pub fn decompose(&self, basis: F::Base) -> Vec<Self> {
        let decompose_len = F::decompose_len(basis);

        let mut ret: Vec<Self> = vec![Self::with_capacity(self.coeff_count()); decompose_len];
        for coeff in self.iter() {
            let decompose_res = F::decompose(coeff, basis);
            ret.iter_mut()
                .zip(decompose_res.into_iter())
                .for_each(|(d_p, d_c)| d_p.push(d_c));
        }

        ret
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
        let poly: Vec<F> = self.iter().zip(rhs.iter()).map(|(&l, &r)| l + r).collect();
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
        let poly: Vec<F> = self.iter().zip(rhs.iter()).map(|(&l, &r)| l - r).collect();
        Polynomial::<F>::new(poly)
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, rhs: Polynomial<F>) -> Self::Output {
        assert_eq!(self.coeff_count(), rhs.coeff_count());
        assert!(self.coeff_count().is_power_of_two());

        let log_n = self.coeff_count().trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();
        ntt_table.inverse_transform_inplace(
            ntt_table.transform_inplace(self) * ntt_table.transform_inplace(rhs),
        )
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        Mul::mul(self, rhs.clone())
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, rhs: Polynomial<F>) -> Self::Output {
        Mul::mul(self.clone(), rhs)
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        Mul::mul(self.clone(), rhs.clone())
    }
}

impl<F: NTTField> MulAssign<&Polynomial<F>> for Polynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Polynomial<F>) {
        *self = Mul::mul(self.clone(), rhs.clone())
    }
}

impl<F: NTTField> MulAssign<Polynomial<F>> for Polynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Polynomial<F>) {
        *self = Mul::mul(self.clone(), rhs)
    }
}

impl<F: NTTField> Mul<NTTPolynomial<F>> for Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, rhs: NTTPolynomial<F>) -> Self::Output {
        Mul::mul(self, &rhs)
    }
}

impl<F: NTTField> Mul<&NTTPolynomial<F>> for Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        assert_eq!(self.coeff_count(), rhs.coeff_count());
        assert!(self.coeff_count().is_power_of_two());

        let log_n = self.coeff_count().trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();
        ntt_table.inverse_transform_inplace(ntt_table.transform_inplace(self) * rhs)
    }
}

impl<F: NTTField> Mul<NTTPolynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, rhs: NTTPolynomial<F>) -> Self::Output {
        Mul::mul(self.clone(), &rhs)
    }
}

impl<F: NTTField> Mul<&NTTPolynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        Mul::mul(self.clone(), rhs)
    }
}

impl<F: NTTField> MulAssign<NTTPolynomial<F>> for Polynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: NTTPolynomial<F>) {
        *self = Mul::mul(self.clone(), rhs);
    }
}

impl<F: NTTField> MulAssign<&NTTPolynomial<F>> for Polynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &NTTPolynomial<F>) {
        *self = Mul::mul(self.clone(), rhs.clone());
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

impl<F: NTTField> Polynomial<F> {
    /// Convert `self` from [`Polynomial<F>`] into [`NTTPolynomial<F>`]
    #[inline]
    pub fn to_ntt_polynomial(self) -> NTTPolynomial<F> {
        <NTTPolynomial<F>>::from(self)
    }
}

impl<F: NTTField> From<NTTPolynomial<F>> for Polynomial<F> {
    #[inline]
    fn from(vec: NTTPolynomial<F>) -> Self {
        debug_assert!(vec.coeff_count().is_power_of_two());

        let ntt_table = F::get_ntt_table(vec.coeff_count().trailing_zeros()).unwrap();

        ntt_table.inverse_transform_inplace(vec)
    }
}

impl<F: NTTField> From<&NTTPolynomial<F>> for Polynomial<F> {
    #[inline]
    fn from(vec: &NTTPolynomial<F>) -> Self {
        <Polynomial<F>>::from(vec.clone())
    }
}

#[cfg(test)]
mod tests {
    use rand::prelude::*;
    use rand_distr::Standard;

    use crate::field::{BarrettConfig, Fp32};

    use super::*;

    #[test]
    fn test_native_poly() {
        type Fp = Fp32;
        const P: u32 = Fp32::BARRETT_MODULUS.value();
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
    fn test_native_poly_mul() {
        type Fp = Fp32;
        type PolyFp = Polynomial<Fp>;

        let p = Fp32::BARRETT_MODULUS.value();
        let log_n = 3;

        Fp::init_ntt_table(&[log_n]).unwrap();

        let distr = rand::distributions::Uniform::new(0, p);
        let mut rng = thread_rng();

        let coeffs1: Vec<Fp32> = distr
            .sample_iter(&mut rng)
            .take(1 << log_n)
            .map(Fp32::new)
            .collect();

        let coeffs2: Vec<Fp32> = distr
            .sample_iter(&mut rng)
            .take(1 << log_n)
            .map(Fp32::new)
            .collect();

        let a = PolyFp::new(coeffs1);
        let b = PolyFp::new(coeffs2);

        let mul_result = simple_mul(&a, &b);
        assert_eq!(a.mul(&b), mul_result);
    }

    fn simple_mul<F: Field>(lhs: &Polynomial<F>, rhs: &Polynomial<F>) -> Polynomial<F> {
        assert_eq!(lhs.coeff_count(), rhs.coeff_count());
        let coeff_count = lhs.coeff_count();

        let mut result = vec![F::zero(); coeff_count];
        let poly1: &[F] = lhs.as_ref();
        let poly2: &[F] = rhs.as_ref();

        for i in 0..coeff_count {
            for j in 0..=i {
                result[i] += poly1[j] * poly2[i - j];
            }
        }

        // mod (x^n + 1)
        for i in coeff_count..coeff_count * 2 - 1 {
            let k = i - coeff_count;
            for j in i - coeff_count + 1..coeff_count {
                result[k] -= poly1[j] * poly2[i - j]
            }
        }

        Polynomial::<F>::new(result)
    }

    #[test]
    fn test_poly_decompose() {
        const N: usize = 1 << 3;
        const B: u32 = 1 << 3;
        let rng = &mut thread_rng();
        let poly: Polynomial<Fp32> =
            Polynomial::new(Standard.sample_iter(rng).take(N).collect::<Vec<Fp32>>());
        let decompose = poly.decompose(B);
        let compose = decompose
            .into_iter()
            .enumerate()
            .fold(Polynomial::zero_with_coeff_count(N), |acc, (i, d)| {
                acc + d.mul_scalar(B.pow(i as u32))
            });
        assert_eq!(compose, poly);
    }

    #[test]
    fn test_poly_decompose_mul() {
        const N: usize = 1 << 3;
        const B: u32 = 1 << 3;
        let rng = &mut thread_rng();

        let poly1: Polynomial<Fp32> =
            Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
        let poly2: Polynomial<Fp32> =
            Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());

        let mul_result = &poly1 * &poly2;

        let decompose = poly1.decompose(B);
        let compose_mul_result = decompose
            .into_iter()
            .enumerate()
            .fold(Polynomial::zero_with_coeff_count(N), |acc, (i, d)| {
                acc + d * poly2.mul_scalar(B.pow(i as u32))
            });
        assert_eq!(compose_mul_result, mul_result);
    }
}
