/// Carrying mul operation trait.
pub trait CarryingMul: Sized {
    /// A wider type for multiplication
    type WideT;

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
}

macro_rules! uint_carrying_mul_impl {
    ($SelfT:ty, $WideT:ty) => {
        impl CarryingMul for $SelfT {
            type WideT = $WideT;

            #[inline]
            fn carrying_mul(self, rhs: Self, carry: Self) -> (Self, Self) {
                #[cfg(feature = "nightly")]
                {
                    self.carrying_mul(rhs, carry)
                }

                #[cfg(not(feature = "nightly"))]
                {
                    let wide =
                        (self as Self::WideT) * (rhs as Self::WideT) + (carry as Self::WideT);
                    (wide as Self, (wide >> Self::BITS) as Self)
                }
            }
        }
    };
}

uint_carrying_mul_impl! { u8, u16 }
uint_carrying_mul_impl! { u16, u32 }
uint_carrying_mul_impl! { u32, u64 }
uint_carrying_mul_impl! { u64, u128 }
