use std::ops::Add;

/// Carrying add operation trait
pub trait CarryingAdd: Sized + Add<Self, Output = Self> {
    /// The type of `carry`.
    type CarryT;

    /// Calculates `self` + `rhs` + `carry` and checks for overflow.
    ///
    /// Performs “ternary addition” of two integer operands and a carry-in bit,
    /// and returns a tuple of the sum along with a boolean indicating
    /// whether an arithmetic overflow would occur. On overflow, the wrapped value is returned.
    ///
    /// This allows chaining together multiple additions to create a wider addition,
    /// and can be useful for bignum addition.
    /// This method should only be used for the most significant word.
    ///
    /// The output boolean returned by this method is not a carry flag,
    /// and should not be added to a more significant word.
    ///
    /// If the input carry is false, this method is equivalent to `overflowing_add`.
    fn carrying_add(self, rhs: Self, carry: Self::CarryT) -> (Self, Self::CarryT);
}

macro_rules! impl_uint_carrying_add {
    ($($T:ty),*) => {
        $(
            impl CarryingAdd for $T {
                type CarryT = bool;

                #[inline]
                fn carrying_add(self, rhs: Self, carry: Self::CarryT) -> (Self, Self::CarryT) {
                    #[cfg(feature = "nightly")]
                    {
                        self.carrying_add(rhs, carry)
                    }

                    #[cfg(not(feature = "nightly"))]
                    {
                        let (a, b) = self.overflowing_add(rhs);
                        let (c, d) = a.overflowing_add(carry as Self);
                        (c, b || d)
                    }
                }
            }
        )*
    };
}

impl_uint_carrying_add! {u8, u16, u32, u64, u128, usize}
