mod primitive;
#[cfg(feature = "simd")]
mod simd;

/// Widening mul operation trait.
pub trait WideningMul: Sized {
    /// Widening multiplication. Computes `self * rhs`, widening to a larger integer.
    ///
    /// The returned value is always exact and can never overflow.
    ///
    /// Note that this method is semantically equivalent to `carrying_mul` with a
    /// carry of zero, with the latter instead returning a tuple denoting the low and
    /// high parts of the result. Consider using it instead if you need
    /// interoperability with other big int helper functions, or if this method isn't
    /// available for a given type.
    fn widening_mul(self, rhs: Self) -> (Self, Self);

    /// Calculates the complete product `self` * `rhs` without the possibility to overflow.
    ///
    /// This returns only the high-order (overflow) bits of the result.
    fn widening_mul_hw(self, rhs: Self) -> Self;
}
