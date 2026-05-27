use super::WideningMul;

macro_rules! uint_widening_mul_impl {
    ($T:ty, $W:ty) => {
        impl WideningMul for $T {
            #[inline]
            fn widening_mul(self, rhs: Self) -> (Self, Self) {
                // <$T>::widening_mul(self, rhs)
                let wide = (self as $W) * (rhs as $W);
                (wide as Self, (wide >> Self::BITS) as Self)
            }

            #[inline]
            fn widening_mul_hw(self, rhs: Self) -> Self {
                let wide = (self as $W) * (rhs as $W);
                (wide >> Self::BITS) as Self
            }
        }
    };
}

uint_widening_mul_impl! { u8, u16 }
uint_widening_mul_impl! { u16, u32 }
uint_widening_mul_impl! { u32, u64 }
uint_widening_mul_impl! { u64, u128 }

#[cfg(target_pointer_width = "32")]
uint_widening_mul_impl! { usize, u64 }
#[cfg(target_pointer_width = "64")]
uint_widening_mul_impl! { usize, u128 }

impl WideningMul for u128 {
    #[inline]
    fn widening_mul(self, rhs: Self) -> (Self, Self) {
        const HALF: u32 = 64;
        const LOWER_MASK: u128 = !0 >> HALF;

        let a_low = self & LOWER_MASK;
        let a_high = self >> HALF;
        let b_low = rhs & LOWER_MASK;
        let b_high = rhs >> HALF;

        let mut low = a_low.wrapping_mul(b_low);
        let mut t = low >> HALF;
        low &= LOWER_MASK;

        t += a_high.wrapping_mul(b_low);
        let mut high = t >> HALF;
        t &= LOWER_MASK;

        t += a_low.wrapping_mul(b_high);
        low |= (t & LOWER_MASK) << HALF;

        high += t >> HALF;
        high += a_high.wrapping_mul(b_high);

        (low, high)
    }

    #[inline]
    fn widening_mul_hw(self, rhs: Self) -> Self {
        const HALF: u32 = 64;
        const LOWER_MASK: u128 = !0 >> HALF;

        let a_low = self & LOWER_MASK;
        let a_high = self >> HALF;
        let b_low = rhs & LOWER_MASK;
        let b_high = rhs >> HALF;

        let low = a_low.wrapping_mul(b_low);
        let mut t = low >> HALF;

        t += a_high.wrapping_mul(b_low);
        let mut high = t >> HALF;
        t &= LOWER_MASK;

        t += a_low.wrapping_mul(b_high);

        high += t >> HALF;
        high += a_high.wrapping_mul(b_high);

        high
    }
}
