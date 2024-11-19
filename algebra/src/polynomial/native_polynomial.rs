use std::ops::{Add, AddAssign, Index, IndexMut, Mul, MulAssign, Neg, Sub, SubAssign};
use std::slice::{Iter, IterMut, SliceIndex};
use std::vec::IntoIter;

use num_traits::Inv;
use rand::{CryptoRng, Rng};
use rand_distr::Distribution;

use crate::transformation::AbstractNTT;
use crate::{
    Basis, DecomposableField, Field, FieldDiscreteGaussianSampler, FieldUniformSampler, NTTField,
};

use super::NTTPolynomial;

/// Represents a polynomial where coefficients are elements of a specified field `F`.
///
/// The [`Polynomial`] struct is generic over a type `F` that must implement the [`Field`] trait, ensuring
/// that the polynomial coefficients can support field operations such as addition, subtraction,
/// multiplication, and division, where division is by a non-zero element. These operations are
/// fundamental in various areas of mathematics and computer science, especially in algorithms that involve
/// polynomial arithmetic in fields, such as error-correcting codes, cryptography, and numerical analysis.
///
/// The coefficients of the polynomial are stored in a vector `data`, with the `i`-th element
/// representing the coefficient of the `xⁱ` term. The vector is ordered from the constant term
/// at index 0 to the highest term. This struct can represent both dense and sparse polynomials,
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

impl<F: NTTField> From<NTTPolynomial<F>> for Polynomial<F> {
    #[inline]
    fn from(ntt_polynomial: NTTPolynomial<F>) -> Self {
        debug_assert!(ntt_polynomial.coeff_count().is_power_of_two());

        let ntt_table = F::get_ntt_table(ntt_polynomial.coeff_count().trailing_zeros()).unwrap();

        ntt_table.inverse_transform_inplace(ntt_polynomial)
    }
}

impl<F: Field> Polynomial<F> {
    /// Creates a new [`Polynomial<F>`].
    #[inline]
    pub fn new(polynomial: Vec<F>) -> Self {
        Self { data: polynomial }
    }

    /// Constructs a new polynomial from a slice.
    #[inline]
    pub fn from_slice(polynomial: &[F]) -> Self {
        Self::new(polynomial.to_vec())
    }

    /// Drop self, and return the data.
    #[inline]
    pub fn data(self) -> Vec<F> {
        self.data
    }

    /// Returns a mutable reference to the data of this [`Polynomial<F>`].
    #[inline]
    pub fn data_mut(&mut self) -> &mut Vec<F> {
        &mut self.data
    }

    /// Get the coefficient counts of polynomial.
    #[inline]
    pub fn coeff_count(&self) -> usize {
        self.data.len()
    }

    /// Creates a [`Polynomial<F>`] with all coefficients equal to zero.
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

    /// Resize the coefficient count of the polynomial.
    #[inline]
    pub fn resize(&mut self, new_degree: usize, value: F) {
        self.data.resize(new_degree, value);
    }

    /// Resize the coefficient count of the polynomial.
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

    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_assign(&mut self) {
        self.data.iter_mut().for_each(|v| *v = -*v);
    }

    /// Evaluate p(x).
    #[inline]
    pub fn evaluate(&self, x: F) -> F {
        self.data
            .iter()
            .rev()
            .fold(F::zero(), |acc, &a| a + acc * x)
    }

    /// Generate a random binary [`Polynomial<F>`].
    #[inline]
    pub fn random_with_binary<R>(n: usize, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self::new(crate::utils::sample_binary_field_vec(n, rng))
    }

    /// Generate a random ternary [`Polynomial<F>`].
    #[inline]
    pub fn random_with_ternary<R>(n: usize, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self::new(crate::utils::sample_ternary_field_vec(n, rng))
    }

    /// Generate a random [`Polynomial<F>`] with discrete gaussian distribution.
    #[inline]
    pub fn random_with_gaussian<R>(
        n: usize,
        rng: &mut R,
        gaussian: FieldDiscreteGaussianSampler,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        if gaussian.cbd_enable() {
            Self::new(crate::utils::sample_cbd_field_vec(n, rng))
        } else {
            Self::new(gaussian.sample_iter(rng).take(n).collect())
        }
    }

    /// Generate a random [`Polynomial<F>`].
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

    /// Generate a random [`Polynomial<F>`] with a specified distribution `dis`.
    #[inline]
    pub fn random_with_distribution<R, D>(n: usize, rng: &mut R, distribution: D) -> Self
    where
        R: Rng + CryptoRng,
        D: Distribution<F>,
    {
        Self::new(distribution.sample_iter(rng).take(n).collect())
    }
}

impl<F: NTTField> Polynomial<F> {
    /// Convert `self` from [`Polynomial<F>`] to [`NTTPolynomial<F>`].
    #[inline]
    pub fn into_ntt_polynomial(self) -> NTTPolynomial<F> {
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

impl<F: DecomposableField> Polynomial<F> {
    /// Decompose `self` according to `basis`.
    pub fn decompose(mut self, basis: Basis<F>) -> Vec<Self> {
        let mask = basis.mask();
        let bits = basis.bits();

        (0..basis.decompose_len())
            .map(|_| {
                let data: Vec<F> = self
                    .iter_mut()
                    .map(|v| v.decompose_lsb_bits(mask, bits))
                    .collect();
                <Polynomial<F>>::new(data)
            })
            .collect()
    }

    /// Decompose `self` according to `basis`.
    ///
    /// # Attention
    ///
    /// **`self`** will be a **zero** polynomial *after* performing this decomposition.
    pub fn decompose_inplace(&mut self, basis: Basis<F>, destination: &mut [Self]) {
        assert_eq!(destination.len(), basis.decompose_len());

        let mask = basis.mask();
        let bits = basis.bits();

        destination.iter_mut().for_each(|d_poly| {
            debug_assert_eq!(d_poly.coeff_count(), self.coeff_count());
            d_poly
                .into_iter()
                .zip(self.iter_mut())
                .for_each(|(d_i, p_i)| {
                    p_i.decompose_lsb_bits_at(d_i, mask, bits);
                })
        });
    }

    /// Decompose `self` according to `basis`.
    ///
    /// # Attention
    ///
    /// **`self`** will be modified *after* performing this decomposition.
    pub fn decompose_lsb_bits_inplace(&mut self, basis: Basis<F>, destination: &mut [F]) {
        debug_assert_eq!(destination.len(), self.coeff_count());
        let mask = basis.mask();
        let bits = basis.bits();

        destination.iter_mut().zip(self).for_each(|(d_i, p_i)| {
            p_i.decompose_lsb_bits_at(d_i, mask, bits);
        });
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

impl<F: Field> IntoIterator for Polynomial<F> {
    type Item = F;

    type IntoIter = IntoIter<F>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<'a, F: Field> IntoIterator for &'a Polynomial<F> {
    type Item = &'a F;

    type IntoIter = Iter<'a, F>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter()
    }
}

impl<'a, F: Field> IntoIterator for &'a mut Polynomial<F> {
    type Item = &'a mut F;

    type IntoIter = IterMut<'a, F>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter_mut()
    }
}

impl<F: Field> AddAssign<Self> for Polynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs).for_each(|(l, r)| *l += r);
    }
}

impl<F: Field> AddAssign<&Self> for Polynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs).for_each(|(l, r)| *l += r);
    }
}

impl<F: Field> Add<Self> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: Self) -> Self::Output {
        AddAssign::add_assign(&mut self, rhs);
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
        let polynomial: Vec<F> = self.iter().zip(rhs).map(|(&l, r)| l + r).collect();
        <Polynomial<F>>::new(polynomial)
    }
}

impl<F: Field> SubAssign<Self> for Polynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs).for_each(|(l, r)| *l -= r);
    }
}
impl<F: Field> SubAssign<&Self> for Polynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs).for_each(|(l, r)| *l -= r);
    }
}

impl<F: Field> Sub<Self> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: Self) -> Self::Output {
        SubAssign::sub_assign(&mut self, rhs);
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

    #[inline]
    fn sub(self, mut rhs: Polynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        rhs.iter_mut().zip(self).for_each(|(r, &l)| *r = l - *r);
        rhs
    }
}

impl<F: Field> Sub<&Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn sub(self, rhs: &Polynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        let polynomial: Vec<F> = self.iter().zip(rhs).map(|(&l, r)| l - r).collect();
        <Polynomial<F>>::new(polynomial)
    }
}

impl<F: NTTField> MulAssign<Self> for Polynomial<F> {
    fn mul_assign(&mut self, rhs: Self) {
        let coeff_count = self.coeff_count();
        debug_assert_eq!(coeff_count, rhs.coeff_count());
        debug_assert!(coeff_count.is_power_of_two());

        let log_n = coeff_count.trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();

        let lhs = self.as_mut_slice();
        let rhs = ntt_table.transform_inplace(rhs);
        ntt_table.transform_slice(lhs);
        ntt_mul_assign_fast(lhs, &rhs);
        ntt_table.inverse_transform_slice(lhs);
    }
}

impl<F: NTTField> MulAssign<&Self> for Polynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        MulAssign::mul_assign(self, rhs.clone());
    }
}

impl<F: NTTField> Mul<Self> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: Self) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: NTTField> Mul<&Self> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: &Self) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, mut rhs: Polynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut rhs, self.clone());
        rhs
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        Mul::mul(self.clone(), rhs.clone())
    }
}

impl<F: NTTField> Mul<NTTPolynomial<F>> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: NTTPolynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: NTTField> Mul<&NTTPolynomial<F>> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
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
        let coeff_count = self.coeff_count();
        debug_assert_eq!(coeff_count, rhs.coeff_count());
        debug_assert!(coeff_count.is_power_of_two());

        let log_n = coeff_count.trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();

        let lhs = self.as_mut_slice();
        ntt_table.transform_slice(lhs);
        ntt_mul_assign_fast(lhs, &rhs);
        ntt_table.inverse_transform_slice(lhs);
    }
}

impl<F: NTTField> MulAssign<&NTTPolynomial<F>> for Polynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &NTTPolynomial<F>) {
        let coeff_count = self.coeff_count();
        debug_assert_eq!(coeff_count, rhs.coeff_count());
        debug_assert!(coeff_count.is_power_of_two());

        let log_n = coeff_count.trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();

        let lhs = self.as_mut_slice();
        ntt_table.transform_slice(lhs);
        ntt_mul_assign_fast(lhs, rhs);
        ntt_table.inverse_transform_slice(lhs);
    }
}

impl<F: Field> Neg for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn neg(mut self) -> Self::Output {
        self.iter_mut().for_each(|e| {
            *e = -*e;
        });
        self
    }
}

impl<F: Field> Neg for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn neg(self) -> Self::Output {
        let data = self.iter().map(|&e| -e).collect();
        <Polynomial<F>>::new(data)
    }
}

impl<F: NTTField> Inv for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn inv(self) -> Self::Output {
        self.into_ntt_polynomial().inv().into_native_polynomial()
    }
}

impl<F: NTTField> Inv for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn inv(self) -> Self::Output {
        self.clone()
            .into_ntt_polynomial()
            .inv()
            .into_native_polynomial()
    }
}

/// Performs entry-wise fast mul operation.
///
/// The result coefficients may be in [0, 2*modulus) for some case,
/// and fall back to [0, modulus) for normal case.
#[inline]
fn ntt_mul_assign_fast<F: NTTField>(lhs: &mut [F], rhs: &NTTPolynomial<F>) {
    lhs.iter_mut()
        .zip(rhs)
        .for_each(|(l, &r)| l.mul_assign_fast(r));
}
