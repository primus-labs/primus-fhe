use std::ops::{Add, AddAssign, Index, IndexMut, Mul, MulAssign, Neg, Sub, SubAssign};
use std::slice::{Iter, IterMut, SliceIndex};

use num_traits::Zero;
use rand_distr::Distribution;

use crate::field::{Field, NTTField};
use crate::transformation::AbstractNTT;
use crate::{Basis, Random};

use super::NTTPolynomial;

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
    #[inline]
    fn from(data: Vec<F>) -> Self {
        Self { data }
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
        Self::from(vec.clone())
    }
}

impl<F: Field> Polynomial<F> {
    /// Creates a new [`Polynomial<F>`].
    #[inline]
    pub fn new(poly: Vec<F>) -> Self {
        Self { data: poly }
    }

    /// Constructs a new polynomial from a slice.
    #[inline]
    pub fn from_slice(poly: &[F]) -> Self {
        Self::new(poly.to_vec())
    }

    /// Drop self, and return the data
    #[inline]
    pub fn data(self) -> Vec<F> {
        self.data
    }

    /// swap `self.data` with an outside data.
    #[inline]
    pub fn swap(&mut self, data: &mut Vec<F>) {
        std::mem::swap(&mut self.data, data);
    }

    /// Creates a [`Polynomial<F>`] with all coefficients equal to zero.
    #[inline]
    pub fn zero_with_coeff_count(coeff_count: usize) -> Self {
        Self {
            data: vec![F::ZERO; coeff_count],
        }
    }

    /// Constructs a new, empty [`Polynomial<F>`] with at least the specified capacity.
    #[inline]
    fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Extracts a slice containing the entire vector.
    #[inline]
    pub fn as_slice(&self) -> &[F] {
        self.data.as_slice()
    }

    /// Appends an element to the back of a [`Polynomial<F>`].
    #[inline]
    fn push(&mut self, value: F) {
        self.data.push(value);
    }

    /// Multipile `self` with the a scalar.
    #[inline]
    pub fn mul_scalar(&self, scalar: F::Inner) -> Self {
        Self::new(self.iter().map(|v| v.mul_scalar(scalar)).collect())
    }

    /// Get the coefficient counts of polynomial.
    #[inline]
    pub fn coeff_count(&self) -> usize {
        self.data.len()
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn iter(&self) -> Iter<F> {
        self.data.iter()
    }

    /// Returns an iterator that allows modifying each value or coefficient of the polynomial.
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<F> {
        self.data.iter_mut()
    }

    /// Alter the coefficient count of the polynomial.
    #[inline]
    pub fn resize(&mut self, new_degree: usize, value: F) {
        self.data.resize(new_degree, value);
    }

    /// Alter the coefficient count of the polynomial.
    #[inline]
    pub fn resize_with<FN>(&mut self, new_degree: usize, f: FN)
    where
        FN: FnMut() -> F,
    {
        self.data.resize_with(new_degree, f);
    }

    /// Given `x`, outputs `f(x)`
    #[inline]
    pub fn evaluate(&self, x: F) -> F {
        self.data.iter().rev().fold(F::ZERO, |acc, a| acc * x + a)
    }
}

impl<F: Field + Random> Polynomial<F> {
    /// Generate a random [`Polynomial<F>`].
    #[inline]
    pub fn random<R>(n: usize, rng: R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self {
            data: F::standard_distribution()
                .sample_iter(rng)
                .take(n)
                .collect(),
        }
    }

    /// Generate a random [`Polynomial<F>`] with a specified distribution `dis`.
    #[inline]
    pub fn random_with_dis<R, D>(n: usize, rng: R, dis: D) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        D: Distribution<F>,
    {
        Self {
            data: dis.sample_iter(rng).take(n).collect(),
        }
    }
}

impl<F: NTTField> Polynomial<F> {
    /// Convert `self` from [`Polynomial<F>`] to [`NTTPolynomial<F>`]
    #[inline]
    pub fn to_ntt_polynomial(self) -> NTTPolynomial<F> {
        <NTTPolynomial<F>>::from(self)
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
    pub fn decompose(&self, basis: Basis<F>) -> Vec<Self> {
        let mut ret: Vec<Self> =
            vec![Self::with_capacity(self.coeff_count()); basis.decompose_len()];
        for coeff in self.iter() {
            let decompose_res = coeff.decompose(basis);
            ret.iter_mut()
                .zip(decompose_res.into_iter())
                .for_each(|(d_p, d_c)| d_p.push(d_c));
        }

        ret
    }
}

impl<F: Field> AsRef<Self> for Polynomial<F> {
    #[inline]
    fn as_ref(&self) -> &Self {
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
        self.data.is_empty() || self.data.iter().all(F::is_zero)
    }

    #[inline]
    fn set_zero(&mut self) {
        let coeff_count = self.coeff_count();
        self.data = vec![F::ZERO; coeff_count];
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

impl<F: Field> AddAssign<&Self> for Polynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs.iter()).for_each(|(l, &r)| *l += r);
    }
}

impl<F: Field> AddAssign for Polynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        AddAssign::add_assign(self, &rhs);
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

impl<F: Field> Add<&Self> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Self) -> Self::Output {
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
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        let poly: Vec<F> = self.iter().zip(rhs.iter()).map(|(&l, &r)| l + r).collect();
        <Polynomial<F>>::new(poly)
    }
}

impl<F: Field> SubAssign for Polynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        SubAssign::sub_assign(self, &rhs);
    }
}
impl<F: Field> SubAssign<&Self> for Polynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
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

impl<F: Field> Sub<&Self> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &Self) -> Self::Output {
        SubAssign::sub_assign(&mut self, rhs);
        self
    }
}

impl<F: Field> Sub<Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn sub(self, mut rhs: Polynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
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
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        let poly: Vec<F> = self.iter().zip(rhs.iter()).map(|(&l, &r)| l - r).collect();
        <Polynomial<F>>::new(poly)
    }
}

impl<F: NTTField> Mul<Self> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        debug_assert!(self.coeff_count().is_power_of_two());

        let log_n = self.coeff_count().trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();
        ntt_table.inverse_transform_inplace(
            ntt_table.transform_inplace(self) * ntt_table.transform_inplace(rhs),
        )
    }
}

impl<F: NTTField> Mul<&Self> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
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

impl<F: NTTField> MulAssign<&Self> for Polynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        MulAssign::mul_assign(self, rhs.clone());
    }
}

impl<F: NTTField> MulAssign<Self> for Polynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        debug_assert!(self.coeff_count().is_power_of_two());

        let log_n = self.coeff_count().trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();

        let mut data = Vec::new();
        self.swap(&mut data);
        ntt_table.transform_slice(&mut data);

        let ret = ntt_table.inverse_transform_inplace(
            <NTTPolynomial<F>>::new(data) * ntt_table.transform_inplace(rhs),
        );
        self.data = ret.data;
    }
}

impl<F: NTTField> Mul<NTTPolynomial<F>> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: NTTPolynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        debug_assert!(self.coeff_count().is_power_of_two());

        let log_n = self.coeff_count().trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();
        ntt_table.inverse_transform_inplace(ntt_table.transform_inplace(self) * rhs)
    }
}

impl<F: NTTField> Mul<&NTTPolynomial<F>> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        debug_assert!(self.coeff_count().is_power_of_two());

        let log_n = self.coeff_count().trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();
        ntt_table.inverse_transform_inplace(ntt_table.transform_inplace(self) * rhs)
    }
}

impl<F: NTTField> Mul<NTTPolynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, rhs: NTTPolynomial<F>) -> Self::Output {
        Mul::mul(self.clone(), rhs)
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
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        debug_assert!(self.coeff_count().is_power_of_two());

        let log_n = self.coeff_count().trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();

        let mut data = Vec::new();
        self.swap(&mut data);
        ntt_table.transform_slice(&mut data);

        let ret = ntt_table.inverse_transform_inplace(<NTTPolynomial<F>>::new(data) * rhs);
        self.data = ret.data;
    }
}

impl<F: NTTField> MulAssign<&NTTPolynomial<F>> for Polynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &NTTPolynomial<F>) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        debug_assert!(self.coeff_count().is_power_of_two());

        let log_n = self.coeff_count().trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();

        let mut data = Vec::new();
        self.swap(&mut data);
        ntt_table.transform_slice(&mut data);

        let ret = ntt_table.inverse_transform_inplace(<NTTPolynomial<F>>::new(data) * rhs);
        self.data = ret.data;
    }
}

impl<F: Field> Neg for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn neg(mut self) -> Self::Output {
        self.data.iter_mut().for_each(|e| {
            *e = -*e;
        });
        self
    }
}
