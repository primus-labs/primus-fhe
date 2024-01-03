use std::ops::{Add, AddAssign, Index, IndexMut, Mul, MulAssign, Neg, Sub, SubAssign};
use std::slice::{Iter, IterMut, SliceIndex};

use num_traits::Zero;
use rand_distr::Distribution;

use crate::field::{Field, NTTField};
use crate::transformation::AbstractNTT;
use crate::Random;

use super::Polynomial;

/// A representation of a polynomial in Number Theoretic Transform (NTT) form.
///
/// The [`NTTPolynomial`] struct holds the coefficients of a polynomial after it has been transformed
/// using the NTT. NTT is an efficient algorithm for computing the discrete Fourier transform (DFT)
/// modulo a prime number, which can significantly speed up polynomial multiplication, especially
/// in the context of implementing fast modular multiplication for cryptographic applications.
///
/// The struct is generic over a type `F` that must implement the `Field` trait. This ensures that
/// the polynomial coefficients are elements of a finite field, which is a necessary condition for
/// the NTT to be applicable. The `Field` trait provides operations like addition, subtraction, and
/// multiplication modulo a prime, which are used in the NTT algorithm.
///
/// The vector `data` stores the coefficients of the polynomial in NTT form. This structure allows for
/// the use of non-recursive NTT algorithms for efficiency and is optimized for cases where multiple
/// polynomial products are computed in a batch or in cryptographic schemes like lattice-based encryption
/// or signatures.
///
/// # Fields
/// * `data: Vec<F>` - A vector that contains the coefficients of the polynomial in NTT form.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct NTTPolynomial<F: Field> {
    data: Vec<F>,
}

impl<F: Field> From<Vec<F>> for NTTPolynomial<F> {
    #[inline]
    fn from(value: Vec<F>) -> Self {
        Self { data: value }
    }
}

impl<F: NTTField> From<Polynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn from(poly: Polynomial<F>) -> Self {
        debug_assert!(poly.coeff_count().is_power_of_two());

        let ntt_table = F::get_ntt_table(poly.coeff_count().trailing_zeros()).unwrap();

        ntt_table.transform_inplace(poly)
    }
}

impl<F: NTTField> From<&Polynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn from(poly: &Polynomial<F>) -> Self {
        Self::from(poly.clone())
    }
}

impl<F: Field> NTTPolynomial<F> {
    /// Creates a new [`NTTPolynomial<F>`].
    #[inline]
    pub fn new(data: Vec<F>) -> Self {
        Self { data }
    }

    /// Constructs a new polynomial from a slice.
    #[inline]
    pub fn from_slice(vec: &[F]) -> Self {
        Self::new(vec.to_vec())
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
            data: vec![F::zero(); coeff_count],
        }
    }

    /// Get the coefficient counts of polynomial.
    #[inline]
    pub fn coeff_count(&self) -> usize {
        self.data.len()
    }

    /// Multipile `self` with the a scalar.
    #[inline]
    pub fn mul_scalar(&self, scalar: F::Inner) -> Self {
        Self::new(self.iter().map(|v| v.mul_scalar(scalar)).collect())
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
}

impl<F: Field + Random> NTTPolynomial<F> {
    /// Generate a random [`NTTPolynomial<F>`].
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

    /// Generate a random [`NTTPolynomial<F>`]  with a specified distribution `dis`.
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

impl<F: NTTField> NTTPolynomial<F> {
    /// Convert `self` from [`NTTPolynomial<F>`] to [`Polynomial<F>`]
    #[inline]
    pub fn to_native_polynomial(self) -> Polynomial<F> {
        <Polynomial<F>>::from(self)
    }

    /// Given `x`, outputs `f(x)`
    ///
    /// # Attention
    ///
    /// If you want to evaluate same poly with different `x`,
    /// you would better transform this [`NTTPolynomial<F>`] to [`Polynomial<F>`] first.
    /// And then, you use that [`Polynomial<F>`] to evaluate with different `x`.
    #[inline]
    pub fn evaluate(&self, x: F) -> F {
        self.clone().to_native_polynomial().evaluate(x)
    }
}

impl<F: Field, I: SliceIndex<[F]>> IndexMut<I> for NTTPolynomial<F> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut *self.data, index)
    }
}

impl<F: Field, I: SliceIndex<[F]>> Index<I> for NTTPolynomial<F> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.data, index)
    }
}

impl<F: Field> AsRef<Self> for NTTPolynomial<F> {
    #[inline]
    fn as_ref(&self) -> &Self {
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
        self.data.is_empty() || self.data.iter().all(F::is_zero)
    }

    #[inline]
    fn set_zero(&mut self) {
        let coeff_count = self.coeff_count();
        self.data = vec![F::zero(); coeff_count];
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

impl<F: Field> AddAssign<&Self> for NTTPolynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs.iter()).for_each(|(l, &r)| *l += r);
    }
}

impl<F: Field> AddAssign for NTTPolynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
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

impl<F: Field> Add<&Self> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Self) -> Self::Output {
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
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        let poly: Vec<F> = self.iter().zip(rhs.iter()).map(|(&l, &r)| l + r).collect();
        <NTTPolynomial<F>>::new(poly)
    }
}

impl<F: Field> SubAssign for NTTPolynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        SubAssign::sub_assign(self, &rhs);
    }
}
impl<F: Field> SubAssign<&Self> for NTTPolynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
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

impl<F: Field> Sub<&Self> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &Self) -> Self::Output {
        SubAssign::sub_assign(&mut self, rhs);
        self
    }
}

impl<F: Field> Sub<NTTPolynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn sub(self, mut rhs: NTTPolynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
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
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        let poly: Vec<F> = self.iter().zip(rhs.iter()).map(|(&l, &r)| l - r).collect();
        <NTTPolynomial<F>>::new(poly)
    }
}

impl<F: Field> Mul<Self> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: Self) -> Self::Output {
        MulAssign::mul_assign(&mut self, &rhs);
        self
    }
}

impl<F: Field> Mul<&Self> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: &Self) -> Self::Output {
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

impl<F: Field> Mul<&NTTPolynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn mul(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        let data = self.iter().zip(rhs.iter()).map(|(&l, &r)| l * r).collect();
        <NTTPolynomial<F>>::new(data)
    }
}

impl<F: Field> MulAssign<&Self> for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs.iter()).for_each(|(l, &r)| *l *= r);
    }
}

impl<F: Field> MulAssign for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        MulAssign::mul_assign(self, &rhs);
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Polynomial<F>) -> Self::Output {
        Mul::mul(&self, rhs)
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        Mul::mul(&self, rhs.clone())
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    fn mul(self, rhs: Polynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        debug_assert!(self.coeff_count().is_power_of_two());

        let log_n = self.coeff_count().trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();
        ntt_table.transform_inplace(rhs) * self
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        Mul::mul(self, rhs.clone())
    }
}

impl<F: NTTField> MulAssign<Polynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Polynomial<F>) {
        *self = Mul::mul(&*self, rhs);
    }
}

impl<F: NTTField> MulAssign<&Polynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Polynomial<F>) {
        *self = Mul::mul(&*self, rhs.clone());
    }
}

impl<F: Field> Neg for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn neg(mut self) -> Self::Output {
        self.data.iter_mut().for_each(|e| {
            *e = -*e;
        });
        self
    }
}
