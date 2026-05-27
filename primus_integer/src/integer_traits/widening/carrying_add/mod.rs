mod primitive;
#[cfg(feature = "simd")]
mod simd;

/// Carrying add operation trait
pub trait CarryingAdd: Sized {
    /// The type of `carry`.
    type CarryT;

    /// Calculates `self` + `rhs` + `carry` and returns a tuple containing
    /// the sum and the output carry (in that order).
    ///
    /// Performs "ternary addition" of two integer operands and a carry-in
    /// bit, and returns an output integer and a carry-out bit. This allows
    /// chaining together multiple additions to create a wider addition, and
    /// can be useful for bignum addition.
    ///
    /// If the input carry is false, this method is equivalent to
    /// `overflowing_add`, and the output carry is
    /// equal to the overflow flag.
    fn carrying_add(self, rhs: Self, carry: Self::CarryT) -> (Self, Self::CarryT);
}
