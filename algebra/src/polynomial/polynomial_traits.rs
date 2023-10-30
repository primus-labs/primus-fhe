use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::slice::{Iter, IterMut};

use num_traits::Zero;

use crate::field::{Field, NTTField};

/// A trait to indicate polynomial in coefficient form,
/// which can perform `modulo`, `add_modulo` and `sub_modulo`.
pub trait Poly<F: Field>:
    Sized
    + Clone
    + Debug
    + PartialEq
    + Eq
    + Zero
    + Neg
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + AddAssign<Self>
    + SubAssign<Self>
    + MulAssign<Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> MulAssign<&'a Self>
{
    /// Get the coefficient counts of polynomial.
    fn coeff_count(&self) -> usize;

    /// Constructs a new polynomial from a slice.
    fn from_slice(poly: &[F]) -> Self;

    /// Constructs a new polynomial from a vector.
    fn from_vec(poly: Vec<F>) -> Self;

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    fn iter(&self) -> Iter<F>;

    /// Returns an iterator that allows modifying each value or coefficient of the polynomial.
    fn iter_mut(&mut self) -> IterMut<F>;

    /// Alter the coefficient count of the polynomial.
    fn resize(&mut self, new_degree: usize, value: F);

    /// Alter the coefficient count of the polynomial.
    fn resize_with<FN>(&mut self, new_degree: usize, f: FN)
    where
        FN: FnMut() -> F;
}
