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
    /// If the input carry is false, this method is equivalent to `overflowing_add`.
    fn carry_add(self, rhs: Self, carry: bool) -> (Self, bool);

    /// Calculates `self` - `rhs` - `borrow` and returns a tuple containing
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

#[doc = " Calculates the quotient of `self` and `rhs`, rounding the result towards positive infinity."]
#[doc = ""]
#[doc = " # Panics"]
#[doc = ""]
#[doc = " This function will panic if `rhs` is zero."]
#[doc = ""]
#[doc = " ## Overflow behavior"]
#[doc = ""]
#[doc = " On overflow, this function will panic if overflow checks are enabled (default in debug"]
#[doc = " mode) and wrap if overflow checks are disabled (default in release mode)."]
pub const fn div_ceil(lhs: u32, rhs: u32) -> u32 {
    let d = lhs / rhs;
    let r = lhs % rhs;
    if r > 0 {
        d + 1
    } else {
        d
    }
}

/// A trait for big number calculation
pub trait WrappingOps: Sized + Copy {
    /// Wrapping addition. Computes `self + rhs`, wrapping around at the boundary of the type.
    fn wrapping_add(self, rhs: Self) -> Self;

    /// Wrapping subtraction. Computes `self - rhs`, wrapping around at the boundary of the type.
    fn wrapping_sub(self, rhs: Self) -> Self;

    /// Wrapping negation. Computes `-self`, wrapping around at the boundary of the type.
    ///
    /// Since unsigned types do not have negative equivalents
    /// all applications of this function will wrap (except for `-0`).
    /// For values smaller than the corresponding signed type's maximum the result
    /// is the same as casting the corresponding signed value.
    /// Any larger values are equivalent to `MAX + 1 - (val - MAX - 1)` where `MAX` is the corresponding signed type's maximum.
    fn wrapping_neg(self) -> Self;

    /// Wrapping multiplication. Computes `self * rhs`, wrapping around at the boundary of the type.
    fn wrapping_mul(self, rhs: Self) -> Self;
}

macro_rules! wrapping_impl {
    ($($SelfT:ty),*) => {$(
        impl WrappingOps for $SelfT {
            #[inline]
            fn wrapping_add(self, rhs: Self) -> Self {
                self.wrapping_add(rhs)
            }

            #[inline]
            fn wrapping_sub(self, rhs: Self) -> Self {
                self.wrapping_sub(rhs)
            }

            #[inline]
            fn wrapping_neg(self) -> Self {
                self.wrapping_neg()
            }

            #[inline]
            fn wrapping_mul(self, rhs: Self) -> Self {
                self.wrapping_mul(rhs)
            }
        })*
    };
}

wrapping_impl!(i8, u8, i16, u16, i32, u32, i64, u64, i128, u128);

/// A trait to convert from type `T` by `as`.
pub trait AsFrom<T: Copy>: Copy {
    /// Convert `value` from type `T` into `Self` by `as`.
    fn as_from(value: T) -> Self;
}

/// A trait to convert `self` into type `T` by `as`.
pub trait AsInto<T: Copy>: Copy {
    /// Convert `self` from type `Self` into `T` by `as`.
    fn as_into(self) -> T;
}

impl<T: Copy, U: Copy> AsInto<T> for U
where
    T: AsFrom<U>,
{
    #[inline]
    fn as_into(self) -> T {
        T::as_from(self)
    }
}

impl<T: Copy> AsFrom<T> for T {
    #[inline(always)]
    fn as_from(value: T) -> Self {
        value
    }
}

macro_rules! impl_as_from {
    (@ $T: ty => $(#[$cfg:meta])* impl $U: ty ) => {
        $(#[$cfg])*
        impl AsFrom<$T> for $U {
            #[inline] fn as_from(value: $T) -> $U { value as $U }
        }
    };
    ($T: ty => { $( $U: ty ),* } ) => {$(
        impl_as_from!(@ $T => impl $U);
    )*};
}

impl_as_from!(u8 => { char, f32, f64, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(i8 => { f32, f64, u8, u16, u32, u64, u128, usize, i16, i32, i64, i128, isize });
impl_as_from!(u16 => { f32, f64, u8, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(i16 => { f32, f64, u8, u16, u32, u64, u128, usize, i8, i32, i64, i128, isize });
impl_as_from!(u32 => { f32, f64, u8, u16, u64, u128, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(i32 => { f32, f64, u8, u16, u32, u64, u128, usize, i8, i16, i64, i128, isize });
impl_as_from!(u64 => { f32, f64, u8, u16, u32, u128, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(i64 => { f32, f64, u8, u16, u32, u64, u128, usize, i8, i16, i32, i128, isize });
impl_as_from!(u128 => { f32, f64, u8, u16, u32, u64, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(i128 => { f32, f64, u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, isize });
impl_as_from!(usize => { f32, f64, u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, isize });
impl_as_from!(isize => { f32, f64, u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128 });
impl_as_from!(f32 => { f64, u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(f64 => { f32, u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(char => { u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(bool => { u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize });
