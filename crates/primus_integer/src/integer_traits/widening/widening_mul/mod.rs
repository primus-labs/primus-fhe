mod primitive;
#[cfg(feature = "simd")]
mod simd;

/// Widening multiplication for unsigned words.
pub trait WideningMul: Sized {
    /// Calculates the complete product `self * rhs` without the possibility of
    /// overflow.
    ///
    /// This returns the low-order (wrapping) word and high-order (overflow)
    /// word of the exact result as `(low, high)`. For word radix `B = 2^w`,
    /// each scalar value or SIMD lane satisfies
    /// `self * rhs = low + high * B`.
    ///
    /// This is semantically equivalent to
    /// [`CarryingMul::carrying_mul`](super::CarryingMul::carrying_mul) with a
    /// zero carry-in.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn widening_mul(self, rhs: Self) -> (Self, Self);

    /// Returns the high word of the exact product `self * rhs`.
    ///
    /// This is the `high` component returned by [`Self::widening_mul`], or
    /// equivalently `floor(self * rhs / 2^w)` for a `w`-bit word.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn widening_mul_hw(self, rhs: Self) -> Self;
}
