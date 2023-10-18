pub(crate) trait Widening: Sized {
    type WideT;

    fn carry_add(self, rhs: Self, carry: bool) -> (Self, bool);

    fn borrow_sub(self, rhs: Self, borrow: bool) -> (Self, bool);

    fn widen_mul(self, rhs: Self) -> (Self, Self);

    fn carry_mul(self, rhs: Self, carry: Self) -> (Self, Self);
}

macro_rules! uint_widening_impl {
    ($SelfT:ty, $WideT:ty) => {
        impl Widening for $SelfT {
            type WideT = $WideT;

            #[inline]
            fn carry_add(self, rhs: Self, carry: bool) -> (Self, bool) {
                let (a, b) = self.overflowing_add(rhs);
                let (c, d) = a.overflowing_add(carry as Self);
                (c, b || d)
            }

            #[inline]
            fn borrow_sub(self, rhs: Self, borrow: bool) -> (Self, bool) {
                let (a, b) = self.overflowing_sub(rhs);
                let (c, d) = a.overflowing_sub(borrow as Self);
                (c, b || d)
            }

            #[inline]
            fn widen_mul(self, rhs: Self) -> (Self, Self) {
                let wide = (self as Self::WideT) * (rhs as Self::WideT);
                (wide as Self, (wide >> Self::BITS) as Self)
            }

            #[inline]
            fn carry_mul(self, rhs: Self, carry: Self) -> (Self, Self) {
                let wide = (self as Self::WideT) * (rhs as Self::WideT) + (carry as Self::WideT);
                (wide as Self, (wide >> Self::BITS) as Self)
            }
        }
    };
}

uint_widening_impl! { u8, u16 }
uint_widening_impl! { u16, u32 }
uint_widening_impl! { u32, u64 }
uint_widening_impl! { u64, u128 }

/// Extension trait to provide access to bits of integers.
pub(crate) trait Bits {
    /// The number of bits this type has.
    const N_BITS: u32;
}

macro_rules! bits {
    ($t:tt, $n:tt) => {
        impl Bits for $t {
            const N_BITS: u32 = $n;
        }
    };
}

bits!(i8, 8);
bits!(u8, 8);
bits!(i16, 16);
bits!(u16, 16);
bits!(i32, 32);
bits!(u32, 32);
bits!(i64, 64);
bits!(u64, 64);
bits!(i128, 128);
bits!(u128, 128);

#[cfg(target_pointer_width = "32")]
bits!(isize, 32);

#[cfg(target_pointer_width = "32")]
bits!(usize, 32);

#[cfg(target_pointer_width = "64")]
bits!(isize, 64);

#[cfg(target_pointer_width = "64")]
bits!(usize, 64);
