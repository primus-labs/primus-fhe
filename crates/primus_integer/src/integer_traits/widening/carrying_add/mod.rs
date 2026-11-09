mod primitive;
#[cfg(feature = "simd")]
mod simd;

/// Carrying addition for unsigned words.
pub trait CarryingAdd: Sized {
    /// A scalar carry bit or a SIMD mask encoding one carry bit per lane.
    type CarryT;

    /// Calculates `self + rhs + carry`, returning `(sum, carry_out)`.
    ///
    /// This performs ternary addition of two unsigned words and a carry-in bit,
    /// like a full adder. Chaining the carry-out into the next more-significant
    /// word permits multi-word addition.
    ///
    /// For word radix `B = 2^w`, each scalar value or SIMD lane satisfies
    /// `self + rhs + carry = sum + carry_out * B`, with each carry interpreted
    /// as either zero or one.
    ///
    /// With a zero carry-in, this is equivalent to `overflowing_add`.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn carrying_add(self, rhs: Self, carry: Self::CarryT) -> (Self, Self::CarryT);
}
