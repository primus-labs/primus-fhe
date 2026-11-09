mod primitive;
#[cfg(feature = "simd")]
mod simd;

/// Carrying multiplication for unsigned words.
///
/// Unlike [`CarryingAdd`](super::CarryingAdd), these operations accept a full
/// word as `carry`, not a one-bit carry flag. SIMD values are processed
/// lane-wise.
pub trait CarryingMul: Sized {
    /// Calculates the full multiplication `self * rhs + carry` without the
    /// possibility of overflow.
    ///
    /// This returns the low-order (wrapping) word and high-order (overflow)
    /// word of the exact result as `(low, high)`. For word radix `B = 2^w`,
    /// `self * rhs + carry = low + high * B`.
    ///
    /// The extra full-word addend and high-order result allow these operations
    /// to be chained for multi-word long multiplication. Use
    /// [`Self::carrying_mul_add`] when a second full-word addend is required.
    ///
    /// With a zero carry-in, this is equivalent to
    /// [`WideningMul::widening_mul`](super::WideningMul::widening_mul).
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn carrying_mul(self, rhs: Self, carry: Self) -> (Self, Self);

    /// Calculates the full multiplication `self * rhs + carry + add` without
    /// the possibility of overflow.
    ///
    /// Both `carry` and `add` are full words. This returns the low-order
    /// (wrapping) word and high-order (overflow) word of the exact result as
    /// `(low, high)`. For word radix `B = 2^w`,
    /// `self * rhs + carry + add = low + high * B`.
    ///
    /// Even when every input is `B - 1`, the result is `B^2 - 1` and therefore
    /// fits exactly in two words. Use [`Self::carrying_mul`] when only one
    /// full-word addend is required.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn carrying_mul_add(self, rhs: Self, carry: Self, add: Self) -> (Self, Self);

    /// Returns the high word of `self * rhs + carry`.
    ///
    /// This is the `high` component returned by [`Self::carrying_mul`].
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn carrying_mul_hw(self, rhs: Self, carry: Self) -> Self;

    /// Returns the high word of `self * rhs + carry + add`.
    ///
    /// This is the `high` component returned by [`Self::carrying_mul_add`].
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn carrying_mul_add_hw(self, rhs: Self, carry: Self, add: Self) -> Self;
}
