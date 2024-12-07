use std::slice::{Iter, IterMut};

use num_traits::ConstZero;

use crate::{AddOps, MulOps};

mod basic;
mod convert;
mod decompose;
mod random;

mod add;
mod inv;
mod mul;
mod neg;
mod sub;

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
pub struct Polynomial<F> {
    data: Vec<F>,
}

impl<F> Polynomial<F> {
    /// Creates a new [`Polynomial<F>`].
    #[inline]
    pub fn new(polynomial: Vec<F>) -> Self {
        Self { data: polynomial }
    }

    /// Returns a reference to the data of this [`Polynomial<F>`].
    #[inline]
    pub fn data(&self) -> &[F] {
        &self.data
    }

    /// Returns a mutable reference to the data of this [`Polynomial<F>`].
    #[inline]
    pub fn data_mut(&mut self) -> &mut Vec<F> {
        &mut self.data
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

    /// Resize the coefficient count of the polynomial.
    #[inline]
    pub fn resize_with<FN>(&mut self, new_degree: usize, f: FN)
    where
        FN: FnMut() -> F,
    {
        self.data.resize_with(new_degree, f);
    }
}

impl<F: Clone> Polynomial<F> {
    /// Constructs a new polynomial from a slice.
    #[inline]
    pub fn from_slice(polynomial: &[F]) -> Self {
        Self::new(polynomial.to_vec())
    }

    /// Resize the coefficient count of the polynomial.
    #[inline]
    pub fn resize(&mut self, new_degree: usize, value: F) {
        self.data.resize(new_degree, value);
    }
}

impl<F: Copy> Polynomial<F> {
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

impl<F> Polynomial<F>
where
    F: Copy + ConstZero,
{
    /// Creates a [`Polynomial<F>`] with all coefficients equal to zero.
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

impl<F> Polynomial<F>
where
    F: AddOps + MulOps,
{
    /// Evaluate p(x).
    #[inline]
    pub fn evaluate(&self, x: F) -> F {
        self.data.iter().rev().fold(F::ZERO, |acc, &a| a + acc * x)
    }
}
