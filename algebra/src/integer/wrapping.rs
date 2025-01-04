use core::num::Wrapping;
use core::ops::{Add, Mul, Neg, Shl, Shr, Sub};

macro_rules! impl_wrapping {
    ($trait_name:ident, $method:ident, $T:ty) => {
        impl $trait_name for $T {
            #[inline]
            fn $method(self, v: Self) -> Self {
                <$T>::$method(self, v)
            }
        }
    };
    ($trait_name:ident, $method:ident, $T:ty, $rhs:ty) => {
        impl $trait_name<$rhs> for $T {
            #[inline]
            fn $method(self, v: $rhs) -> Self {
                <$T>::$method(self, v)
            }
        }
    };
}

/// Performs addition that wraps around on overflow.
pub trait WrappingAdd: Sized + Copy + Add<Self, Output = Self> {
    /// Wrapping (modular) addition. Computes `self + other`, wrapping around at the boundary of
    /// the type.
    fn wrapping_add(self, v: Self) -> Self;
}

impl_wrapping!(WrappingAdd, wrapping_add, u8);
impl_wrapping!(WrappingAdd, wrapping_add, u16);
impl_wrapping!(WrappingAdd, wrapping_add, u32);
impl_wrapping!(WrappingAdd, wrapping_add, u64);
impl_wrapping!(WrappingAdd, wrapping_add, usize);
impl_wrapping!(WrappingAdd, wrapping_add, u128);

impl_wrapping!(WrappingAdd, wrapping_add, i8);
impl_wrapping!(WrappingAdd, wrapping_add, i16);
impl_wrapping!(WrappingAdd, wrapping_add, i32);
impl_wrapping!(WrappingAdd, wrapping_add, i64);
impl_wrapping!(WrappingAdd, wrapping_add, isize);
impl_wrapping!(WrappingAdd, wrapping_add, i128);

/// Performs subtraction that wraps around on overflow.
pub trait WrappingSub: Sized + Copy + Sub<Self, Output = Self> {
    /// Wrapping (modular) subtraction. Computes `self - other`, wrapping around at the boundary
    /// of the type.
    fn wrapping_sub(self, v: Self) -> Self;
}

impl_wrapping!(WrappingSub, wrapping_sub, u8);
impl_wrapping!(WrappingSub, wrapping_sub, u16);
impl_wrapping!(WrappingSub, wrapping_sub, u32);
impl_wrapping!(WrappingSub, wrapping_sub, u64);
impl_wrapping!(WrappingSub, wrapping_sub, usize);
impl_wrapping!(WrappingSub, wrapping_sub, u128);

impl_wrapping!(WrappingSub, wrapping_sub, i8);
impl_wrapping!(WrappingSub, wrapping_sub, i16);
impl_wrapping!(WrappingSub, wrapping_sub, i32);
impl_wrapping!(WrappingSub, wrapping_sub, i64);
impl_wrapping!(WrappingSub, wrapping_sub, isize);
impl_wrapping!(WrappingSub, wrapping_sub, i128);

/// Performs multiplication that wraps around on overflow.
pub trait WrappingMul: Sized + Copy + Mul<Self, Output = Self> {
    /// Wrapping (modular) multiplication. Computes `self * other`, wrapping around at the boundary
    /// of the type.
    fn wrapping_mul(self, v: Self) -> Self;
}

impl_wrapping!(WrappingMul, wrapping_mul, u8);
impl_wrapping!(WrappingMul, wrapping_mul, u16);
impl_wrapping!(WrappingMul, wrapping_mul, u32);
impl_wrapping!(WrappingMul, wrapping_mul, u64);
impl_wrapping!(WrappingMul, wrapping_mul, usize);
impl_wrapping!(WrappingMul, wrapping_mul, u128);

impl_wrapping!(WrappingMul, wrapping_mul, i8);
impl_wrapping!(WrappingMul, wrapping_mul, i16);
impl_wrapping!(WrappingMul, wrapping_mul, i32);
impl_wrapping!(WrappingMul, wrapping_mul, i64);
impl_wrapping!(WrappingMul, wrapping_mul, isize);
impl_wrapping!(WrappingMul, wrapping_mul, i128);

macro_rules! impl_wrapping_unary {
    ($trait_name:ident, $method:ident, $T:ty) => {
        impl $trait_name for $T {
            #[inline]
            fn $method(self) -> $T {
                <$T>::$method(self)
            }
        }
    };
}

/// Performs a negation that does not panic.
pub trait WrappingNeg: Sized + Copy {
    /// Wrapping (modular) negation. Computes `-self`,
    /// wrapping around at the boundary of the type.
    ///
    /// Since unsigned types do not have negative equivalents
    /// all applications of this function will wrap (except for `-0`).
    /// For values smaller than the corresponding signed type's maximum
    /// the result is the same as casting the corresponding signed value.
    /// Any larger values are equivalent to `MAX + 1 - (val - MAX - 1)` where
    /// `MAX` is the corresponding signed type's maximum.
    ///
    /// ```ignore
    /// assert_eq!(100i8.wrapping_neg(), -100);
    /// assert_eq!((-100i8).wrapping_neg(), 100);
    /// assert_eq!((-128i8).wrapping_neg(), -128); // wrapped!
    /// ```
    fn wrapping_neg(self) -> Self;
}

impl_wrapping_unary!(WrappingNeg, wrapping_neg, u8);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, u16);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, u32);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, u64);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, usize);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, u128);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, i8);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, i16);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, i32);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, i64);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, isize);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, i128);

macro_rules! impl_wrapping_shift {
    ($trait_name:ident, $method:ident, $T:ty) => {
        impl $trait_name for $T {
            #[inline]
            fn $method(self, rhs: u32) -> $T {
                <$T>::$method(self, rhs)
            }
        }
    };
}

/// Performs a left shift that does not panic.
pub trait WrappingShl: Sized + Copy + Shl<usize, Output = Self> {
    /// Panic-free bitwise shift-left; yields `self << mask(rhs)`,
    /// where `mask` removes any high order bits of `rhs` that would
    /// cause the shift to exceed the bitwidth of the type.
    ///
    /// ```ignore
    /// let x: u16 = 0x0001;
    ///
    /// assert_eq!(WrappingShl::wrapping_shl(&x, 0),  0x0001);
    /// assert_eq!(WrappingShl::wrapping_shl(&x, 1),  0x0002);
    /// assert_eq!(WrappingShl::wrapping_shl(&x, 15), 0x8000);
    /// assert_eq!(WrappingShl::wrapping_shl(&x, 16), 0x0001);
    /// ```
    fn wrapping_shl(self, rhs: u32) -> Self;
}

impl_wrapping_shift!(WrappingShl, wrapping_shl, u8);
impl_wrapping_shift!(WrappingShl, wrapping_shl, u16);
impl_wrapping_shift!(WrappingShl, wrapping_shl, u32);
impl_wrapping_shift!(WrappingShl, wrapping_shl, u64);
impl_wrapping_shift!(WrappingShl, wrapping_shl, usize);
impl_wrapping_shift!(WrappingShl, wrapping_shl, u128);

impl_wrapping_shift!(WrappingShl, wrapping_shl, i8);
impl_wrapping_shift!(WrappingShl, wrapping_shl, i16);
impl_wrapping_shift!(WrappingShl, wrapping_shl, i32);
impl_wrapping_shift!(WrappingShl, wrapping_shl, i64);
impl_wrapping_shift!(WrappingShl, wrapping_shl, isize);
impl_wrapping_shift!(WrappingShl, wrapping_shl, i128);

/// Performs a right shift that does not panic.
pub trait WrappingShr: Sized + Copy + Shr<usize, Output = Self> {
    /// Panic-free bitwise shift-right; yields `self >> mask(rhs)`,
    /// where `mask` removes any high order bits of `rhs` that would
    /// cause the shift to exceed the bitwidth of the type.
    ///
    /// ```ignore
    /// let x: u16 = 0x8000;
    ///
    /// assert_eq!(WrappingShr::wrapping_shr(&x, 0),  0x8000);
    /// assert_eq!(WrappingShr::wrapping_shr(&x, 1),  0x4000);
    /// assert_eq!(WrappingShr::wrapping_shr(&x, 15), 0x0001);
    /// assert_eq!(WrappingShr::wrapping_shr(&x, 16), 0x8000);
    /// ```
    fn wrapping_shr(self, rhs: u32) -> Self;
}

impl_wrapping_shift!(WrappingShr, wrapping_shr, u8);
impl_wrapping_shift!(WrappingShr, wrapping_shr, u16);
impl_wrapping_shift!(WrappingShr, wrapping_shr, u32);
impl_wrapping_shift!(WrappingShr, wrapping_shr, u64);
impl_wrapping_shift!(WrappingShr, wrapping_shr, usize);
impl_wrapping_shift!(WrappingShr, wrapping_shr, u128);

impl_wrapping_shift!(WrappingShr, wrapping_shr, i8);
impl_wrapping_shift!(WrappingShr, wrapping_shr, i16);
impl_wrapping_shift!(WrappingShr, wrapping_shr, i32);
impl_wrapping_shift!(WrappingShr, wrapping_shr, i64);
impl_wrapping_shift!(WrappingShr, wrapping_shr, isize);
impl_wrapping_shift!(WrappingShr, wrapping_shr, i128);

// Well this is a bit funny, but all the more appropriate.
impl<T: WrappingAdd> WrappingAdd for Wrapping<T>
where
    Wrapping<T>: Add<Output = Wrapping<T>>,
{
    fn wrapping_add(self, v: Self) -> Self {
        Wrapping(self.0.wrapping_add(v.0))
    }
}
impl<T: WrappingSub> WrappingSub for Wrapping<T>
where
    Wrapping<T>: Sub<Output = Wrapping<T>>,
{
    fn wrapping_sub(self, v: Self) -> Self {
        Wrapping(self.0.wrapping_sub(v.0))
    }
}
impl<T: WrappingMul> WrappingMul for Wrapping<T>
where
    Wrapping<T>: Mul<Output = Wrapping<T>>,
{
    fn wrapping_mul(self, v: Self) -> Self {
        Wrapping(self.0.wrapping_mul(v.0))
    }
}
impl<T: WrappingNeg> WrappingNeg for Wrapping<T>
where
    Wrapping<T>: Neg<Output = Wrapping<T>>,
{
    fn wrapping_neg(self) -> Self {
        Wrapping(self.0.wrapping_neg())
    }
}
impl<T: WrappingShl> WrappingShl for Wrapping<T>
where
    Wrapping<T>: Shl<usize, Output = Wrapping<T>>,
{
    fn wrapping_shl(self, rhs: u32) -> Self {
        Wrapping(self.0.wrapping_shl(rhs))
    }
}
impl<T: WrappingShr> WrappingShr for Wrapping<T>
where
    Wrapping<T>: Shr<usize, Output = Wrapping<T>>,
{
    fn wrapping_shr(self, rhs: u32) -> Self {
        Wrapping(self.0.wrapping_shr(rhs))
    }
}

#[test]
fn test_wrapping_traits() {
    fn wrapping_add<T: WrappingAdd>(a: T, b: T) -> T {
        a.wrapping_add(b)
    }
    fn wrapping_sub<T: WrappingSub>(a: T, b: T) -> T {
        a.wrapping_sub(b)
    }
    fn wrapping_mul<T: WrappingMul>(a: T, b: T) -> T {
        a.wrapping_mul(b)
    }
    fn wrapping_neg<T: WrappingNeg>(a: T) -> T {
        a.wrapping_neg()
    }
    fn wrapping_shl<T: WrappingShl>(a: T, b: u32) -> T {
        a.wrapping_shl(b)
    }
    fn wrapping_shr<T: WrappingShr>(a: T, b: u32) -> T {
        a.wrapping_shr(b)
    }
    assert_eq!(wrapping_add(255, 1), 0u8);
    assert_eq!(wrapping_sub(0, 1), 255u8);
    assert_eq!(wrapping_mul(255, 2), 254u8);
    assert_eq!(wrapping_neg(255), 1u8);
    assert_eq!(wrapping_shl(255, 8), 255u8);
    assert_eq!(wrapping_shr(255, 8), 255u8);
    assert_eq!(wrapping_add(255, 1), (Wrapping(255u8) + Wrapping(1u8)).0);
    assert_eq!(wrapping_sub(0, 1), (Wrapping(0u8) - Wrapping(1u8)).0);
    assert_eq!(wrapping_mul(255, 2), (Wrapping(255u8) * Wrapping(2u8)).0);
    assert_eq!(wrapping_neg(255), (-Wrapping(255u8)).0);
    assert_eq!(wrapping_shl(255, 8), (Wrapping(255u8) << 8).0);
    assert_eq!(wrapping_shr(255, 8), (Wrapping(255u8) >> 8).0);
}

#[test]
fn wrapping_is_wrappingadd() {
    fn require_wrappingadd<T: WrappingAdd>(_: &T) {}
    require_wrappingadd(&Wrapping(42));
}

#[test]
fn wrapping_is_wrappingsub() {
    fn require_wrappingsub<T: WrappingSub>(_: &T) {}
    require_wrappingsub(&Wrapping(42));
}

#[test]
fn wrapping_is_wrappingmul() {
    fn require_wrappingmul<T: WrappingMul>(_: &T) {}
    require_wrappingmul(&Wrapping(42));
}

#[test]
fn wrapping_is_wrappingneg() {
    fn require_wrappingneg<T: WrappingNeg>(_: &T) {}
    require_wrappingneg(&Wrapping(42));
}

#[test]
fn wrapping_is_wrappingshl() {
    fn require_wrappingshl<T: WrappingShl>(_: &T) {}
    require_wrappingshl(&Wrapping(42));
}

#[test]
fn wrapping_is_wrappingshr() {
    fn require_wrappingshr<T: WrappingShr>(_: &T) {}
    require_wrappingshr(&Wrapping(42));
}
