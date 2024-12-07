use std::slice::{Iter, IterMut};

use num_traits::ConstZero;

use crate::NTTField;

mod basic;
mod convert;
mod random;

mod add;
mod inv;
mod mul;
mod neg;
mod sub;

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
pub struct NTTPolynomial<F> {
    data: Vec<F>,
}

impl<F> NTTPolynomial<F> {
    /// Creates a new [`NTTPolynomial<F>`].
    #[inline]
    pub fn new(data: Vec<F>) -> Self {
        Self { data }
    }

    /// Returns a reference to the data of this [`NTTPolynomial<F>`].
    #[inline]
    pub fn data(&self) -> &[F] {
        &self.data
    }

    /// Returns a mutable reference to the data of this [`NTTPolynomial<F>`].
    #[inline]
    pub fn data_mut(&mut self) -> &mut Vec<F> {
        &mut self.data
    }

    /// Drop self, and return the data.
    #[inline]
    pub fn inner_data(self) -> Vec<F> {
        self.data
    }

    /// Get the coefficient counts of polynomial.
    #[inline]
    pub fn coeff_count(&self) -> usize {
        self.data.len()
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

    /// Returns an iterator that allows modifying each value or coefficient of the polynomial.
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<F> {
        self.data.iter_mut()
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

impl<F: Clone> NTTPolynomial<F> {
    /// Constructs a new polynomial from a slice.
    #[inline]
    pub fn from_slice(vec: &[F]) -> Self {
        Self::new(vec.to_vec())
    }

    /// Alter the coefficient count of the polynomial.
    #[inline]
    pub fn resize(&mut self, new_degree: usize, value: F) {
        self.data.resize(new_degree, value);
    }
}

impl<F: Copy> NTTPolynomial<F> {
    /// Copy the coefficients from another slice.
    #[inline]
    pub fn copy_from(&mut self, src: impl AsRef<[F]>) {
        self.data.copy_from_slice(src.as_ref())
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn copied_iter(&self) -> std::iter::Copied<Iter<'_, F>> {
        self.data.iter().copied()
    }
}

impl<F: Copy + ConstZero> NTTPolynomial<F> {
    /// Creates a [`NTTPolynomial<F>`] with all coefficients equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> Self {
        Self {
            data: vec![F::ZERO; coeff_count],
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
        self.data.fill(F::ZERO);
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
