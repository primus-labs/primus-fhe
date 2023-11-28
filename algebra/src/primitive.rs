/// A trait for big number calculation
pub trait Widening: Sized {
    /// A wider type for multiplication
    type WideT;

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
    /// If the input carry is false, this method is equivalent to overflowing_add.
    fn carry_add(self, rhs: Self, carry: bool) -> (Self, bool);

    /// Calculates `self` − `rhs` − `borrow` and returns a tuple containing
    /// the difference and the output borrow.
    ///
    /// Performs "ternary subtraction" by subtracting both an integer operand and a borrow-in bit from self,
    /// and returns an output integer and a borrow-out bit. This allows chaining together multiple subtractions
    /// to create a wider subtraction, and can be useful for bignum subtraction.
    fn borrow_sub(self, rhs: Self, borrow: bool) -> (Self, bool);

    /// Calculates the complete product `self` * `rhs` without the possibility to overflow.
    ///
    /// This returns the low-order (wrapping) bits and the high-order (overflow) bits
    /// of the result as two separate values, in that order.
    fn widen_mul(self, rhs: Self) -> (Self, Self);

    /// Calculates the "full multiplication" `self` * `rhs` + `carry` without
    /// the possibility to overflow.
    ///
    /// This returns the low-order (wrapping) bits and the high-order (overflow) bits
    /// of the result as two separate values, in that order.
    ///
    /// Performs "long multiplication" which takes in an extra amount to add, and may return
    /// an additional amount of overflow. This allows for chaining together multiple multiplications
    /// to create "big integers" which represent larger values.
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
pub trait Bits {
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
