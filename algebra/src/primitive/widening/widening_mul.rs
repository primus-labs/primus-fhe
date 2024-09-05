/// Widening mul operation trait.
pub trait WideningMul: Sized {
    /// A wider type for multiplication
    type WideT;

    /// Calculates the complete product `self` * `rhs` without the possibility to overflow.
    ///
    /// This returns the low-order (wrapping) bits and the high-order (overflow) bits
    /// of the result as two separate values, in that order.
    fn widening_mul(self, rhs: Self) -> (Self, Self);
}

macro_rules! uint_widening_mul_impl {
    ($SelfT:ty, $WideT:ty) => {
        impl WideningMul for $SelfT {
            type WideT = $WideT;

            #[inline]
            fn widening_mul(self, rhs: Self) -> (Self, Self) {
                #[cfg(feature = "nightly")]
                {
                    self.widening_mul(rhs)
                }

                #[cfg(not(feature = "nightly"))]
                {
                    let wide = (self as Self::WideT) * (rhs as Self::WideT);
                    (wide as Self, (wide >> Self::BITS) as Self)
                }
            }
        }
    };
}

uint_widening_mul_impl! { u8, u16 }
uint_widening_mul_impl! { u16, u32 }
uint_widening_mul_impl! { u32, u64 }
uint_widening_mul_impl! { u64, u128 }
