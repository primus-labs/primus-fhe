use std::fmt::Display;

use crate::{numeric::Numeric, reduce::Modulus};

#[macro_use]
mod macros;
mod ops;
mod root;

/// A modulus, using barrett reduction algorithm.
///
/// The struct stores the modulus number and some precomputed
/// data. Here, `b` = 2^T::BITS
///
/// It's efficient if many reductions are performed with a single modulus.
#[derive(Debug, Clone, Copy)]
pub struct BarrettModulus<T: Numeric> {
    /// the value to indicate the modulus
    value: T,
    /// ratio `µ` = ⌊b²/value⌋
    ratio: [T; 2],
}

impl<T: Numeric> Display for BarrettModulus<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<T: Numeric> BarrettModulus<T> {
    /// Returns the value of this [`BarrettModulus<T>`].
    #[inline]
    pub const fn value(&self) -> T {
        self.value
    }

    /// Returns the ratio of this [`BarrettModulus<T>`].
    #[inline]
    pub const fn ratio(&self) -> [T; 2] {
        self.ratio
    }
}

impl<T: Numeric> Modulus<T> for BarrettModulus<T> {
    #[inline]
    fn modulus_minus_one(self) -> T {
        self.value - T::ONE
    }
}

impl_barrett_modulus!(impl BarrettModulus<u8>; WideType: u16);
impl_barrett_modulus!(impl BarrettModulus<u16>; WideType: u32);
impl_barrett_modulus!(impl BarrettModulus<u32>; WideType: u64);
impl_barrett_modulus!(impl BarrettModulus<u64>; WideType: u128);
