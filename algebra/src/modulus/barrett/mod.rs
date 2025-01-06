use std::fmt::Display;

use crate::{
    integer::{AsFrom, AsInto},
    numeric::Numeric,
    reduce::{Modulus, ModulusValue},
};

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
    /// Creates a new [`BarrettModulus<T>`] with the given value.
    pub fn new_generic(value: T) -> Self {
        if value <= T::ONE {
            panic!("modulus can't be 0 or 1.")
        }
        let bit_count = T::BITS - value.leading_zeros();
        assert!(bit_count < T::BITS - 1);

        let (numerator, _) = div_inplace(value);

        Self {
            value,
            ratio: numerator,
        }
    }

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
    fn from_value(value: ModulusValue<T>) -> Self {
        match value {
            ModulusValue::Native => panic!("Not match for native"),
            ModulusValue::PowerOf2(value)
            | ModulusValue::Prime(value)
            | ModulusValue::Others(value) => Self::new_generic(value),
        }
    }

    #[inline]
    fn modulus_value(&self) -> ModulusValue<T> {
        ModulusValue::Others(self.value)
    }

    #[inline]
    fn modulus_minus_one(&self) -> T {
        self.value - T::ONE
    }
}

impl_barrett_modulus!(impl BarrettModulus<u8>; WideType: u16);
impl_barrett_modulus!(impl BarrettModulus<u16>; WideType: u32);
impl_barrett_modulus!(impl BarrettModulus<u32>; WideType: u64);
impl_barrett_modulus!(impl BarrettModulus<u64>; WideType: u128);

#[inline]
fn div_rem<T: Numeric>(numerator: T, divisor: T) -> (T, T) {
    (numerator / divisor, numerator % divisor)
}

#[inline]
fn div_wide<T: Numeric>(hi: T, divisor: T) -> (T, T) {
    let lhs = T::WideT::as_from(hi) << <T>::BITS;
    let rhs = T::WideT::as_from(divisor);
    ((lhs / rhs).as_into(), (lhs % rhs).as_into())
}

#[inline]
fn div_half<T: Numeric>(rem: T, divisor: T) -> (T, T) {
    let half_bits: u32 = T::BITS >> 1;
    let (hi, rem) = div_rem(rem << half_bits, divisor);
    let (lo, rem) = div_rem(rem << half_bits, divisor);
    ((hi << half_bits) | lo, rem)
}

fn div_inplace<T: Numeric>(value: T) -> ([T; 2], T) {
    let mut numerator = [T::ZERO, T::ZERO];
    let rem;

    if value <= (T::MAX >> (T::BITS >> 1)) {
        let (q, r) = div_half(T::ONE, value);
        numerator[1] = q;

        let (q, r) = div_half(r, value);
        numerator[0] = q;
        rem = r;
    } else {
        let (q, r) = div_wide(T::ONE, value);
        numerator[1] = q;

        let (q, r) = div_wide(r, value);
        numerator[0] = q;
        rem = r;
    }
    (numerator, rem)
}
