mod borrowing_sub;
mod carrying_add;
mod carrying_mul;
mod widening_mul;

use core::ops::{Add, AddAssign};

pub use borrowing_sub::BorrowingSub;
pub use carrying_add::CarryingAdd;
pub use carrying_mul::CarryingMul;
pub use widening_mul::WideningMul;

use crate::UnsignedInteger;

/// A trait for big number calculation
pub trait WideningOps: CarryingAdd + BorrowingSub + WideningMul + CarryingMul {}

impl<T> WideningOps for T where T: CarryingAdd + BorrowingSub + WideningMul + CarryingMul {}

/// [`Widening`] for `u8`.
pub type WideningU8 = Widening<u8>;
/// [`Widening`] for `u16`.
pub type WideningU16 = Widening<u16>;
/// [`Widening`] for `u32`.
pub type WideningU32 = Widening<u32>;
/// [`Widening`] for `u64`.
pub type WideningU64 = Widening<u64>;
/// [`Widening`] for `u128`.
pub type WideningU128 = Widening<u128>;
/// [`Widening`] for `usize`.
pub type WideningUsize = Widening<usize>;

/// A double-width unsigned integer represented as a (low, high) limb pair.
///
/// `Widening<T>` stores the low limb in the first field and the high limb in
/// the second field. It supports addition with carry propagation via [`Add`]
/// and [`AddAssign`], accepting both owned and borrowed operands as well as
/// plain `(T, T)` tuples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Widening<T: UnsignedInteger>(pub T, pub T);

impl<T: UnsignedInteger> Add<Widening<T>> for Widening<T> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let (lo, carry) = self.0.overflowing_add(rhs.0);
        let (hi, _) = self.1.carrying_add(rhs.1, carry);
        Widening(lo, hi)
    }
}

impl<T: UnsignedInteger> Add<&Widening<T>> for Widening<T> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Widening<T>) -> Self::Output {
        let (lo, carry) = self.0.overflowing_add(rhs.0);
        let (hi, _) = self.1.carrying_add(rhs.1, carry);
        Widening(lo, hi)
    }
}

impl<T: UnsignedInteger> Add<Widening<T>> for &Widening<T> {
    type Output = Widening<T>;

    #[inline]
    fn add(self, rhs: Widening<T>) -> Self::Output {
        let (lo, carry) = self.0.overflowing_add(rhs.0);
        let (hi, _) = self.1.carrying_add(rhs.1, carry);
        Widening(lo, hi)
    }
}

impl<T: UnsignedInteger> Add<&Widening<T>> for &Widening<T> {
    type Output = Widening<T>;

    #[inline]
    fn add(self, rhs: &Widening<T>) -> Self::Output {
        let (lo, carry) = self.0.overflowing_add(rhs.0);
        let (hi, _) = self.1.carrying_add(rhs.1, carry);
        Widening(lo, hi)
    }
}

impl<T: UnsignedInteger> AddAssign<Widening<T>> for Widening<T> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        let (lo, carry) = self.0.overflowing_add(rhs.0);
        let (hi, _) = self.1.carrying_add(rhs.1, carry);
        self.0 = lo;
        self.1 = hi;
    }
}

impl<T: UnsignedInteger> AddAssign<&Widening<T>> for Widening<T> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let (lo, carry) = self.0.overflowing_add(rhs.0);
        let (hi, _) = self.1.carrying_add(rhs.1, carry);
        self.0 = lo;
        self.1 = hi;
    }
}

impl<T: UnsignedInteger> Add<(T, T)> for Widening<T> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: (T, T)) -> Self::Output {
        let (lo, carry) = self.0.overflowing_add(rhs.0);
        let (hi, _) = self.1.carrying_add(rhs.1, carry);
        Widening(lo, hi)
    }
}

impl<T: UnsignedInteger> Add<(T, T)> for &Widening<T> {
    type Output = Widening<T>;

    #[inline]
    fn add(self, rhs: (T, T)) -> Self::Output {
        let (lo, carry) = self.0.overflowing_add(rhs.0);
        let (hi, _) = self.1.carrying_add(rhs.1, carry);
        Widening(lo, hi)
    }
}

impl<T: UnsignedInteger> AddAssign<(T, T)> for Widening<T> {
    #[inline]
    fn add_assign(&mut self, rhs: (T, T)) {
        let (lo, carry) = self.0.overflowing_add(rhs.0);
        let (hi, _) = self.1.carrying_add(rhs.1, carry);
        self.0 = lo;
        self.1 = hi;
    }
}
