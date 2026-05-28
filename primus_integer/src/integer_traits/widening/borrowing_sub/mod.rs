mod primitive;
#[cfg(feature = "simd")]
mod simd;

/// Borrowing sub operation trait
pub trait BorrowingSub: Sized {
    /// The type of `borrow`.
    type BorrowT;

    /// Calculates `self` &minus; `rhs` &minus; `borrow` and returns a tuple
    /// containing the difference and the output borrow.
    ///
    /// Performs "ternary subtraction" by subtracting both an integer
    /// operand and a borrow-in bit from `self`, and returns an output
    /// integer and a borrow-out bit. This allows chaining together multiple
    /// subtractions to create a wider subtraction, and can be useful for
    /// bignum subtraction.
    fn borrowing_sub(self, rhs: Self, borrow: Self::BorrowT) -> (Self, Self::BorrowT);
}
