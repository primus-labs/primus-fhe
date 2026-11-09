mod primitive;
#[cfg(feature = "simd")]
mod simd;

/// Borrowing subtraction for unsigned words.
pub trait BorrowingSub: Sized {
    /// A scalar borrow bit or a SIMD mask encoding one borrow bit per lane.
    type BorrowT;

    /// Calculates `self - rhs - borrow`, returning `(difference, borrow_out)`.
    ///
    /// This performs ternary subtraction of an unsigned word and a borrow-in
    /// bit from `self`, like a full subtractor. Chaining the borrow-out into the
    /// next more-significant word permits multi-word subtraction.
    ///
    /// For word radix `B = 2^w`, each scalar value or SIMD lane satisfies
    /// `self + borrow_out * B = difference + rhs + borrow`, with each borrow
    /// interpreted as either zero or one.
    ///
    /// With a zero borrow-in, this is equivalent to `overflowing_sub`.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn borrowing_sub(self, rhs: Self, borrow: Self::BorrowT) -> (Self, Self::BorrowT);
}
