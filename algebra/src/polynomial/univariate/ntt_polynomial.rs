use std::ops::{Add, AddAssign, Index, IndexMut, Mul, MulAssign, Neg, Sub, SubAssign};
use std::slice::{Iter, IterMut, SliceIndex};
use std::vec::IntoIter;

use num_traits::Inv;
use rand::{CryptoRng, Rng};
use rand_distr::Distribution;

use crate::transformation::AbstractNTT;
use crate::{Field, FieldUniformSampler, NTTField};

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

impl<F: NTTField> From<Polynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn from(polynomial: Polynomial<F>) -> Self {
        debug_assert!(polynomial.coeff_count().is_power_of_two());

        let ntt_table = F::get_ntt_table(polynomial.coeff_count().trailing_zeros()).unwrap();

        ntt_table.transform_inplace(polynomial)
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

    /// Drop self, and return the data.
    #[inline]
    pub fn data(self) -> Vec<F> {
        self.data
    }

    /// Returns a mutable reference to the data of this [`NTTPolynomial<F>`].
    #[inline]
    pub fn data_mut(&mut self) -> &mut Vec<F> {
        &mut self.data
    }

    /// Get the coefficient counts of polynomial.
    #[inline]
    pub fn coeff_count(&self) -> usize {
        self.data.len()
    }

    /// Creates a [`NTTPolynomial<F>`] with all coefficients equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> Self {
        Self {
            data: vec![F::zero(); coeff_count],
        }
    }

    /// Returns `true` if `self` is equal to `0`.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.data.is_empty() || self.data.iter().all(F::is_zero)
    }

    /// Sets `self` to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.data.fill(F::zero());
    }

    /// Copy the coefficients from another slice.
    #[inline]
    pub fn copy_from(&mut self, src: impl AsRef<[F]>) {
        self.data.copy_from_slice(src.as_ref())
    }

    /// Extracts a slice containing the entire vector.
    ///
    /// Equivalent to `&s[..]`.
    #[inline]
    pub fn as_slice(&self) -> &[F] {
        self.data.as_slice()
    }

    /// Extracts a mutable slice of the entire vector.
    ///
    /// Equivalent to `&mut s[..]`.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [F] {
        self.data.as_mut_slice()
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn iter(&self) -> Iter<F> {
        self.data.iter()
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn copied_iter(&self) -> std::iter::Copied<Iter<'_, F>> {
        self.data.iter().copied()
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

    /// Multiply `self` with the a scalar.
    #[inline]
    pub fn mul_scalar(&self, scalar: F) -> Self {
        Self::new(self.iter().map(|&v| v * scalar).collect())
    }

    /// Multiply `self` with the a scalar inplace.
    #[inline]
    pub fn mul_scalar_assign(&mut self, scalar: F) {
        self.iter_mut().for_each(|v| *v *= scalar)
    }

    /// Performs addition operation:`self + rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn add_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.iter()
            .zip(rhs)
            .zip(destination)
            .for_each(|((&x, &y), z)| {
                *z = x + y;
            })
    }

    /// Performs subtraction operation:`self - rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn sub_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.iter()
            .zip(rhs)
            .zip(destination)
            .for_each(|((&x, &y), z)| {
                *z = x - y;
            })
    }

    /// Performs subtraction operation:`self * rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn mul_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.iter()
            .zip(rhs)
            .zip(destination)
            .for_each(|((&x, &y), z)| {
                *z = x * y;
            })
    }

    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_assign(&mut self) {
        self.data.iter_mut().for_each(|v| *v = -*v);
    }

    /// Generate a random [`NTTPolynomial<F>`].
    #[inline]
    pub fn random<R>(n: usize, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self {
            data: FieldUniformSampler::new()
                .sample_iter(rng)
                .take(n)
                .collect(),
        }
    }

    /// Generate a random [`NTTPolynomial<F>`]  with a specified distribution `dis`.
    #[inline]
    pub fn random_with_distribution<R, D>(n: usize, rng: &mut R, distribution: D) -> Self
    where
        R: Rng + CryptoRng,
        D: Distribution<F>,
    {
        Self::new(distribution.sample_iter(rng).take(n).collect())
    }
}

impl<F: NTTField> NTTPolynomial<F> {
    /// Convert `self` from [`NTTPolynomial<F>`] to [`Polynomial<F>`]
    #[inline]
    pub fn into_native_polynomial(self) -> Polynomial<F> {
        <Polynomial<F>>::from(self)
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

impl<F: Field> IntoIterator for NTTPolynomial<F> {
    type Item = F;

    type IntoIter = IntoIter<F>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<'a, F: Field> IntoIterator for &'a NTTPolynomial<F> {
    type Item = &'a F;

    type IntoIter = Iter<'a, F>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter()
    }
}

impl<'a, F: Field> IntoIterator for &'a mut NTTPolynomial<F> {
    type Item = &'a mut F;

    type IntoIter = IterMut<'a, F>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter_mut()
    }
}

impl<F: Field> AddAssign<Self> for NTTPolynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs).for_each(|(l, r)| *l += r);
    }
}

impl<F: Field> AddAssign<&Self> for NTTPolynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs).for_each(|(l, r)| *l += r);
    }
}

impl<F: Field> Add<Self> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: Self) -> Self::Output {
        AddAssign::add_assign(&mut self, rhs);
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
        let data: Vec<F> = self.iter().zip(rhs).map(|(&l, r)| l + r).collect();
        <NTTPolynomial<F>>::new(data)
    }
}

impl<F: Field> SubAssign<Self> for NTTPolynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs).for_each(|(l, r)| *l -= r);
    }
}
impl<F: Field> SubAssign<&Self> for NTTPolynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs).for_each(|(l, r)| *l -= r);
    }
}

impl<F: Field> Sub<Self> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: Self) -> Self::Output {
        SubAssign::sub_assign(&mut self, rhs);
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
        rhs.iter_mut().zip(self).for_each(|(r, &l)| *r = l - *r);
        rhs
    }
}

impl<F: Field> Sub<&NTTPolynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn sub(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        let data: Vec<F> = self.iter().zip(rhs).map(|(&l, r)| l - r).collect();
        <NTTPolynomial<F>>::new(data)
    }
}

impl<F: Field> MulAssign<Self> for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs).for_each(|(l, r)| *l *= r);
    }
}

impl<F: Field> MulAssign<&Self> for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs).for_each(|(l, r)| *l *= r);
    }
}

impl<F: Field> Mul<Self> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: Self) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
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
        let data = self.iter().zip(rhs).map(|(&l, r)| l * r).collect();
        <NTTPolynomial<F>>::new(data)
    }
}

impl<F: NTTField> MulAssign<Polynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Polynomial<F>) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        *self *= rhs.into_ntt_polynomial();
    }
}

impl<F: NTTField> MulAssign<&Polynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Polynomial<F>) {
        MulAssign::mul_assign(self, rhs.clone());
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: Polynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        Mul::mul(self, rhs.clone())
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn mul(self, rhs: Polynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        NTTPolynomial::from(rhs) * self
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        Mul::mul(self, rhs.clone())
    }
}

impl<F: Field> Neg for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn neg(mut self) -> Self::Output {
        self.iter_mut().for_each(|e| {
            *e = -*e;
        });
        self
    }
}

impl<F: Field> Neg for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn neg(self) -> Self::Output {
        let data = self.iter().map(|&e| -e).collect();
        <NTTPolynomial<F>>::new(data)
    }
}

impl<F: Field> Inv for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn inv(mut self) -> Self::Output {
        self.iter_mut().for_each(|v| *v = v.inv());
        self
    }
}

impl<F: Field> Inv for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn inv(self) -> Self::Output {
        let data = self.iter().map(|v| v.inv()).collect();
        NTTPolynomial::new(data)
    }
}

/// Performs entry-wise add_mul operation.
///
/// Multiply entry-wise over last two [NTTPolynomial<F>], and add back to the first
/// [NTTPolynomial<F>].
#[inline]
pub fn ntt_add_mul_assign<F: NTTField>(
    x: &mut NTTPolynomial<F>,
    y: &NTTPolynomial<F>,
    z: &NTTPolynomial<F>,
) {
    x.into_iter()
        .zip(y)
        .zip(z)
        .for_each(|((a, &b), &c)| a.add_mul_assign(b, c));
}

/// Performs entry-wise add_mul operation.
///
/// Multiply entry-wise over middle two [NTTPolynomial<F>], and add the first
/// [NTTPolynomial<F>], store the result to last [NTTPolynomial<F>].
#[inline]
pub fn ntt_add_mul_inplace<F: NTTField>(
    x: &NTTPolynomial<F>,
    y: &NTTPolynomial<F>,
    z: &NTTPolynomial<F>,
    des: &mut NTTPolynomial<F>,
) {
    des.into_iter()
        .zip(x)
        .zip(y)
        .zip(z)
        .for_each(|(((d, &a), &b), &c)| *d = a.add_mul(b, c));
}

/// Performs entry-wise add_mul fast operation.
///
/// Multiply entry-wise over last two [NTTPolynomial<F>], and add back to the first
/// [NTTPolynomial<F>].
///
/// The result coefficients may be in [0, 2*modulus) for some case,
/// and fall back to [0, modulus) for normal case.
#[inline]
pub fn ntt_add_mul_assign_fast<F: NTTField>(
    x: &mut NTTPolynomial<F>,
    y: &NTTPolynomial<F>,
    z: &NTTPolynomial<F>,
) {
    x.into_iter()
        .zip(y)
        .zip(z)
        .for_each(|((a, &b), &c)| a.add_mul_assign_fast(b, c));
}
