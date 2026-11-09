use core::ops::{Add, Mul, Sub};

macro_rules! impl_wrapping {
    ($trait_name:ident, $method:ident, $T:ty) => {
        impl $trait_name for $T {
            #[inline]
            fn $method(self, rhs: Self) -> Self {
                <$T>::$method(self, rhs)
            }
        }
    };
    ($trait_name:ident, $method:ident, $T:ty, $rhs:ty) => {
        impl $trait_name<$rhs> for $T {
            #[inline]
            fn $method(self, rhs: $rhs) -> Self {
                <$T>::$method(self, rhs)
            }
        }
    };
}

/// Provides wrapping addition for generic integer code.
pub trait WrappingAdd: Sized + Add<Self, Output = Self> {
    /// Computes `self + rhs`, wrapping around at the numeric bounds of `Self`.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn wrapping_add(self, rhs: Self) -> Self;
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

/// Provides wrapping subtraction for generic integer code.
pub trait WrappingSub: Sized + Sub<Self, Output = Self> {
    /// Computes `self - rhs`, wrapping around at the numeric bounds of `Self`.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn wrapping_sub(self, rhs: Self) -> Self;
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

/// Provides wrapping multiplication for generic integer code.
pub trait WrappingMul: Sized + Mul<Self, Output = Self> {
    /// Computes `self * rhs`, wrapping around at the numeric bounds of `Self`.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn wrapping_mul(self, rhs: Self) -> Self;
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

/// Provides wrapping negation for generic integer code.
pub trait WrappingNeg: Sized {
    /// Computes `-self`, wrapping around at the numeric bounds of `Self`.
    ///
    /// For primitive integers, negating a signed type's `MIN` value returns
    /// `MIN`; negating an unsigned value performs modular negation.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_integer::WrappingNeg;
    ///
    /// assert_eq!(WrappingNeg::wrapping_neg(100i8), -100);
    /// assert_eq!(WrappingNeg::wrapping_neg(-100i8), 100);
    /// assert_eq!(WrappingNeg::wrapping_neg(-128i8), -128); // wrapped!
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
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

/// Provides wrapping left shift for generic integer code.
pub trait WrappingShl: Sized {
    /// Computes a panic-free left shift after masking any high-order bits of
    /// `rhs` that would make the shift exceed the bit width of `Self`.
    ///
    /// This is not a rotation: bits shifted out of the value are discarded.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_integer::WrappingShl;
    ///
    /// let x: u16 = 0x0001;
    ///
    /// assert_eq!(WrappingShl::wrapping_shl(x, 0),  0x0001);
    /// assert_eq!(WrappingShl::wrapping_shl(x, 1),  0x0002);
    /// assert_eq!(WrappingShl::wrapping_shl(x, 15), 0x8000);
    /// assert_eq!(WrappingShl::wrapping_shl(x, 16), 0x0001);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
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

/// Provides wrapping right shift for generic integer code.
pub trait WrappingShr: Sized {
    /// Computes a panic-free right shift after masking any high-order bits of
    /// `rhs` that would make the shift exceed the bit width of `Self`.
    ///
    /// This is not a rotation: bits shifted out of the value are discarded.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_integer::WrappingShr;
    ///
    /// let x: u16 = 0x8000;
    ///
    /// assert_eq!(WrappingShr::wrapping_shr(x, 0),  0x8000);
    /// assert_eq!(WrappingShr::wrapping_shr(x, 1),  0x4000);
    /// assert_eq!(WrappingShr::wrapping_shr(x, 15), 0x0001);
    /// assert_eq!(WrappingShr::wrapping_shr(x, 16), 0x8000);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
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
