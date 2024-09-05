use crate::Field;

/// An iterator over the powers of a certain base element `b`: `b^0, b^1, b^2, ...`.
#[derive(Clone, Debug)]
pub struct Powers<F> {
    /// Base
    pub base: F,

    /// Current
    pub current: F,
}

impl<F: Field> Iterator for Powers<F> {
    type Item = F;

    fn next(&mut self) -> Option<F> {
        let result = self.current;
        self.current *= self.base;
        Some(result)
    }
}

#[inline]
pub(crate) fn powers<F: Field>(base: F) -> Powers<F> {
    shifted_powers(base, F::ONE)
}

#[inline]
pub(crate) fn shifted_powers<F: Field>(base: F, start: F) -> Powers<F> {
    Powers {
        base,
        current: start,
    }
}

/// Extend a field `F` element `x` to an array of length `D`
/// by filling zeros.
#[inline]
pub const fn field_to_array<F: Field, const D: usize>(x: F) -> [F; D] {
    let mut arr = [F::ZERO; D];
    arr[0] = x;
    arr
}

/// Naive polynomial multiplication.
pub fn naive_poly_mul<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
    // Grade school algorithm
    let mut product = vec![F::ZERO; a.len() + b.len() - 1];
    for (i, c1) in a.iter().enumerate() {
        for (j, c2) in b.iter().enumerate() {
            product[i + j] += *c1 * (*c2);
        }
    }
    product
}

/// Square
#[inline]
pub fn square<F: Field>(a: F) -> F {
    a * a
}
