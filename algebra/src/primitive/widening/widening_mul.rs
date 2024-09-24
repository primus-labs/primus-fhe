/// Widening mul operation trait.
pub trait WideningMul: Sized {
    /// Calculates the complete product `self` * `rhs` without the possibility to overflow.
    ///
    /// This returns the low-order (wrapping) bits and the high-order (overflow) bits
    /// of the result as two separate values, in that order.
    fn widening_mul(self, rhs: Self) -> (Self, Self);

    /// Calculates the complete product `self` * `rhs` without the possibility to overflow.
    ///
    /// This returns only the high-order (overflow) bits of the result.
    fn widening_mul_hw(self, rhs: Self) -> Self;
}

macro_rules! uint_widening_mul_impl {
    ($T:ty, $W:ty) => {
        impl WideningMul for $T {
            #[inline]
            fn widening_mul(self, rhs: Self) -> (Self, Self) {
                #[cfg(feature = "nightly")]
                {
                    self.widening_mul(rhs)
                }

                #[cfg(not(feature = "nightly"))]
                {
                    let wide = (self as $W) * (rhs as $W);
                    (wide as Self, (wide >> Self::BITS) as Self)
                }
            }

            #[inline]
            fn widening_mul_hw(self, rhs: Self) -> Self {
                #[cfg(feature = "nightly")]
                {
                    self.widening_mul(rhs).1
                }

                #[cfg(not(feature = "nightly"))]
                {
                    let wide = (self as $W) * (rhs as $W);
                    (wide >> Self::BITS) as Self
                }
            }
        }
    };
}

uint_widening_mul_impl! { u8, u16 }
uint_widening_mul_impl! { u16, u32 }
uint_widening_mul_impl! { u32, u64 }
uint_widening_mul_impl! { u64, u128 }
