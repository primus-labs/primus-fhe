use std::ops::Sub;

/// Borrowing sub operation trait
pub trait BorrowingSub: Sized + Sub<Self, Output = Self> {
    /// The type of `borrow`.
    type BorrowT;

    /// Calculates `self` - `rhs` - `borrow` and returns a tuple containing
    /// the difference and the output borrow.
    ///
    /// Performs "ternary subtraction" by subtracting both an integer operand and a borrow-in bit from self,
    /// and returns an output integer and a borrow-out bit. This allows chaining together multiple subtractions
    /// to create a wider subtraction, and can be useful for bignum subtraction.
    fn borrowing_sub(self, rhs: Self, borrow: Self::BorrowT) -> (Self, Self::BorrowT);
}

macro_rules! impl_uint_borrowing_sub {
    ($($T:ty),*) => {
        $(
            impl BorrowingSub for $T {
                type BorrowT = bool;

                #[inline]
                fn borrowing_sub(self, rhs: Self, borrow: Self::BorrowT) -> (Self, Self::BorrowT) {
                    #[cfg(feature = "nightly")]
                    {
                        self.borrowing_sub(rhs, borrow)
                    }

                    #[cfg(not(feature = "nightly"))]
                    {
                        let (a, b) = self.overflowing_sub(rhs);
                        let (c, d) = a.overflowing_sub(borrow as Self);
                        (c, b || d)
                    }
                }
            }
        )*
    };
}

impl_uint_borrowing_sub! {u8, u16, u32, u64, u128, usize}
