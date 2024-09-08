/// Carrying mul operation trait.
pub trait CarryingMul: Sized {
    /// Calculates the "full multiplication" `self` * `rhs` + `carry` without
    /// the possibility to overflow.
    ///
    /// This returns the low-order (wrapping) bits and the high-order (overflow) bits
    /// of the result as two separate values, in that order.
    ///
    /// Performs "long multiplication" which takes in an extra amount to add, and may return
    /// an additional amount of overflow. This allows for chaining together multiple multiplications
    /// to create "big integers" which represent larger values.
    fn carrying_mul(self, rhs: Self, carry: Self) -> (Self, Self);

    /// Calculates the "full multiplication" `self` * `rhs` + `carry` without
    /// the possibility to overflow.
    ///
    /// This returns only the high-order (overflow) bits of the result.
    ///
    /// Performs "long multiplication" which takes in an extra amount to add, and may return
    /// an additional amount of overflow. This allows for chaining together multiple multiplications
    /// to create "big integers" which represent larger values.
    fn carrying_mul_hw(self, rhs: Self, carry: Self) -> Self;
}

macro_rules! uint_carrying_mul_impl {
    ($T:ty, $W:ty) => {
        impl CarryingMul for $T {
            #[inline]
            fn carrying_mul(self, rhs: Self, carry: Self) -> (Self, Self) {
                #[cfg(feature = "nightly")]
                {
                    self.carrying_mul(rhs, carry)
                }

                #[cfg(not(feature = "nightly"))]
                {
                    let wide = (self as $W) * (rhs as $W) + (carry as $W);
                    (wide as Self, (wide >> Self::BITS) as Self)
                }
            }

            #[inline]
            fn carrying_mul_hw(self, rhs: Self, carry: Self) -> Self {
                #[cfg(feature = "nightly")]
                {
                    self.carrying_mul(rhs, carry).1
                }

                #[cfg(not(feature = "nightly"))]
                {
                    let wide = (self as $W) * (rhs as $W) + (carry as $W);
                    (wide >> Self::BITS) as Self
                }
            }
        }
    };
}

uint_carrying_mul_impl! { u8, u16 }
uint_carrying_mul_impl! { u16, u32 }
uint_carrying_mul_impl! { u32, u64 }
uint_carrying_mul_impl! { u64, u128 }
