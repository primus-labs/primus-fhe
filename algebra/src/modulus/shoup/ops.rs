use crate::{
    numeric::Numeric,
    reduce::{LazyReduceMul, LazyReduceMulAssign, ReduceMul, ReduceMulAssign},
};

use super::ShoupFactor;

impl<T: Numeric> LazyReduceMul<ShoupFactor<T>, T> for T {
    type Output = T;

    /// Calculates `a * b mod modulus`.
    ///
    /// The result is in [0, 2 * `modulus`).
    ///
    /// # Proof
    ///
    /// Let `x = b`, `w = a.value`, `w' = a.quotient`, `p = modulus` and `β = 2^(64)`.
    ///
    /// By definition, `w' = ⌊wβ/p⌋`. Let `q = ⌊w'x/β⌋`.
    ///
    /// Then, `0 ≤ wβ/p - w' < 1`, `0 ≤ w'x/β - q < 1`.
    ///
    /// Multiplying by `xp/β` and `p` respectively, and adding, yields
    ///
    /// `0 ≤ wx - qp < xp/β + p < 2p < β`
    #[inline]
    fn lazy_reduce_mul(self, a: ShoupFactor<T>, b: T) -> Self::Output {
        let hw = a.quotient.widening_mul_hw(b);
        a.value.wrapping_mul(b).wrapping_sub(self.wrapping_mul(hw))
    }
}

impl<T: Numeric> LazyReduceMul<T, ShoupFactor<T>> for T {
    type Output = T;

    #[inline]
    fn lazy_reduce_mul(self, a: T, b: ShoupFactor<T>) -> Self::Output {
        let hw = a.widening_mul_hw(b.quotient);
        a.wrapping_mul(b.value).wrapping_sub(self.wrapping_mul(hw))
    }
}

impl<T: Numeric> LazyReduceMulAssign<T, ShoupFactor<T>> for T {
    #[inline]
    fn lazy_reduce_mul_assign(self, a: &mut T, b: ShoupFactor<T>) {
        *a = self.lazy_reduce_mul(*a, b);
    }
}

impl<T: Numeric> ReduceMul<ShoupFactor<T>, T> for T {
    type Output = T;

    #[inline]
    fn reduce_mul(self, a: ShoupFactor<T>, b: T) -> Self::Output {
        self.reduce_once(self.lazy_reduce_mul(a, b))
    }
}

impl<T: Numeric> ReduceMul<T, ShoupFactor<T>> for T {
    type Output = T;

    #[inline]
    fn reduce_mul(self, a: T, b: ShoupFactor<T>) -> Self::Output {
        self.reduce_once(self.lazy_reduce_mul(a, b))
    }
}

impl<T: Numeric> ReduceMulAssign<T, ShoupFactor<T>> for T {
    #[inline]
    fn reduce_mul_assign(self, a: &mut T, b: ShoupFactor<T>) {
        *a = self.reduce_once(self.lazy_reduce_mul(*a, b));
    }
}
