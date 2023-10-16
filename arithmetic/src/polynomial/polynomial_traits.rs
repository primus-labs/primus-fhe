use std::slice::{Iter, IterMut};

use crate::algebra::models::{Fp, FpElement};

/// A trait to indicate polynomial in coefficient form,
/// which can perform `modulo`, `add_modulo` and `sub_modulo`.
pub trait Poly<const N: usize, const P: FpElement>: Sized {
    /// Get the coefficient counts of polynomial.
    fn coeff_count(&self) -> usize;

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    fn iter(&self) -> Iter<Fp<P>>;

    /// Returns an iterator that allows modifying each value or coefficient of the polynomial.
    fn iter_mut(&mut self) -> IterMut<Fp<P>>;
}
