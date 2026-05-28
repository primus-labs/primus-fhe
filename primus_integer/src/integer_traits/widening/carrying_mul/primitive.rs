use super::CarryingMul;

macro_rules! uint_carrying_mul_impl {
    ($T:ty, $W:ty) => {
        impl CarryingMul for $T {
            #[inline]
            fn carrying_mul(self, rhs: Self, carry: Self) -> (Self, Self) {
                <$T>::carrying_mul(self, rhs, carry)
            }

            #[inline]
            fn carrying_mul_add(self, rhs: Self, carry: Self, add: Self) -> (Self, Self) {
                <$T>::carrying_mul_add(self, rhs, carry, add)
            }

            #[inline]
            fn carrying_mul_hw(self, rhs: Self, carry: Self) -> Self {
                let wide = (self as $W) * (rhs as $W) + (carry as $W);
                (wide >> Self::BITS) as Self
            }

            #[inline]
            fn carrying_mul_add_hw(self, rhs: Self, carry: Self, add: Self) -> Self {
                let wide = (self as $W) * (rhs as $W) + (carry as $W) + (add as $W);
                (wide >> Self::BITS) as Self
            }
        }
    };
}

uint_carrying_mul_impl! { u8, u16 }
uint_carrying_mul_impl! { u16, u32 }
uint_carrying_mul_impl! { u32, u64 }
uint_carrying_mul_impl! { u64, u128 }

#[cfg(target_pointer_width = "32")]
uint_carrying_mul_impl! { usize, u64 }
#[cfg(target_pointer_width = "64")]
uint_carrying_mul_impl! { usize, u128 }

impl CarryingMul for u128 {
    #[cfg(target_pointer_width = "64")]
    #[inline]
    fn carrying_mul(self, rhs: Self, carry: Self) -> (Self, Self) {
        <u128>::carrying_mul(self, rhs, carry)
    }

    #[cfg(target_pointer_width = "64")]
    #[inline]
    fn carrying_mul_add(self, rhs: Self, carry: Self, add: Self) -> (Self, Self) {
        <u128>::carrying_mul_add(self, rhs, carry, add)
    }

    #[cfg(target_pointer_width = "32")]
    #[inline]
    fn carrying_mul(self, rhs: Self, carry: Self) -> (Self, Self) {
        const HALF: u32 = 64;
        const LOWER_MASK: u128 = !0 >> HALF;

        let a_low = self & LOWER_MASK;
        let a_high = self >> HALF;
        let b_low = rhs & LOWER_MASK;
        let b_high = rhs >> HALF;
        let carry_low = carry & LOWER_MASK;
        let carry_high = carry >> HALF;

        let mut low = a_low.wrapping_mul(b_low).wrapping_add(carry_low);
        let mut t = low >> HALF;
        low &= LOWER_MASK;

        t += a_high.wrapping_mul(b_low).wrapping_add(carry_high);
        let mut high = t >> HALF;
        t &= LOWER_MASK;

        t += a_low.wrapping_mul(b_high);
        low |= (t & LOWER_MASK) << HALF;

        high += t >> HALF;
        high += a_high.wrapping_mul(b_high);

        (low, high)
    }

    #[cfg(target_pointer_width = "32")]
    #[inline]
    fn carrying_mul_add(self, rhs: Self, carry: Self, add: Self) -> (Self, Self) {
        const HALF: u32 = 64;
        const LOWER_MASK: u128 = !0 >> HALF;

        let a_low = self & LOWER_MASK;
        let a_high = self >> HALF;
        let b_low = rhs & LOWER_MASK;
        let b_high = rhs >> HALF;
        let carry_low = carry & LOWER_MASK;
        let carry_high = carry >> HALF;
        let add_low = add & LOWER_MASK;
        let add_high = add >> HALF;

        let mut low = a_low
            .wrapping_mul(b_low)
            .wrapping_add(carry_low)
            .wrapping_add(add_low);
        let mut t = low >> HALF;
        low &= LOWER_MASK;

        t += a_high.wrapping_mul(b_low).wrapping_add(carry_high);
        let mut high = t >> HALF;
        t &= LOWER_MASK;

        t += a_low.wrapping_mul(b_high).wrapping_add(add_high);
        low |= (t & LOWER_MASK) << HALF;

        high += a_high.wrapping_mul(b_high).wrapping_add(t >> HALF);

        (low, high)
    }

    #[inline]
    fn carrying_mul_hw(self, rhs: Self, carry: Self) -> Self {
        const HALF: u32 = 64;
        const LOWER_MASK: u128 = !0 >> HALF;

        let a_low = self & LOWER_MASK;
        let a_high = self >> HALF;
        let b_low = rhs & LOWER_MASK;
        let b_high = rhs >> HALF;
        let carry_low = carry & LOWER_MASK;
        let carry_high = carry >> HALF;

        let low = a_low.wrapping_mul(b_low).wrapping_add(carry_low);
        let mut t = low >> HALF;

        t += a_high.wrapping_mul(b_low).wrapping_add(carry_high);
        let mut high = t >> HALF;
        t &= LOWER_MASK;

        t += a_low.wrapping_mul(b_high);

        high += t >> HALF;
        high += a_high.wrapping_mul(b_high);

        high
    }

    #[inline]
    fn carrying_mul_add_hw(self, rhs: Self, carry: Self, add: Self) -> Self {
        const HALF: u32 = 64;
        const LOWER_MASK: u128 = !0 >> HALF;

        let a_low = self & LOWER_MASK;
        let a_high = self >> HALF;
        let b_low = rhs & LOWER_MASK;
        let b_high = rhs >> HALF;
        let carry_low = carry & LOWER_MASK;
        let carry_high = carry >> HALF;
        let add_low = add & LOWER_MASK;
        let add_high = add >> HALF;

        let low = a_low
            .wrapping_mul(b_low)
            .wrapping_add(carry_low)
            .wrapping_add(add_low);
        let mut t = low >> HALF;

        t += a_high.wrapping_mul(b_low).wrapping_add(carry_high);
        let mut high = t >> HALF;
        t &= LOWER_MASK;

        t += a_low.wrapping_mul(b_high).wrapping_add(add_high);

        high += a_high.wrapping_mul(b_high).wrapping_add(t >> HALF);

        high
    }
}
