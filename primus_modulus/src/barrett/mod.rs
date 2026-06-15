use core::fmt::Display;

use primus_integer::FheUint;
use primus_reduce::ReduceOnce;

use crate::integer::{DivRemScalar, UnsignedInteger};

mod ops;
mod slice;

#[cfg(feature = "simd")]
pub mod simd;

#[cfg(feature = "simd")]
pub use simd::{SimdBarrettModulus, simd_reduce_dot_product};

/// A modulus, using barrett reduction algorithm.
///
/// The struct stores the modulus number and some precomputed
/// data. Here, `b` = 2^T::BITS
///
/// It's efficient if many reductions are performed with a single modulus.
#[derive(Debug, Clone, Copy)]
pub struct BarrettModulus<T: UnsignedInteger> {
    /// the value to indicate the modulus
    value: T,
    /// ratio `µ` = floor(b²/value)
    ratio: [T; 2],
}

impl<T: UnsignedInteger> BarrettModulus<T> {
    /// Creates a new [`BarrettModulus<T>`] with the given value.
    ///
    /// # Panics
    ///
    /// Panics if `value ≤ 1` or if the bit-width of `value` is too large
    /// (≥ `T::BITS - 1`).  For a fallible variant see [`try_new`](Self::try_new).
    pub fn new(value: T) -> Self {
        assert!(value > T::ONE, "modulus can't be 0 or 1.");
        let leading_zeros = value.leading_zeros();
        assert!(leading_zeros > 1, "modulus is too large.");
        Self::new_unchecked(value)
    }

    /// Creates a new [`BarrettModulus<T>`] without validating the modulus value.
    ///
    /// # Correctness
    ///
    /// `value` must satisfy `1 < value < 2^(T::BITS - 1)`.
    #[inline]
    pub fn new_unchecked(value: T) -> Self {
        let mut quotient = [T::ZERO; 3];
        let _rem = DivRemScalar::div_rem_scalar(&[T::ZERO, T::ZERO, T::ONE], value, &mut quotient);
        Self {
            value,
            ratio: [quotient[0], quotient[1]],
        }
    }

    /// Creates a [`BarrettModulus<T>`] from precomputed parts.
    ///
    /// The `ratio` must equal `floor(b² / value)` where `b = 2^T::BITS`.
    #[inline]
    pub const fn from_parts(value: T, ratio: [T; 2]) -> Self {
        Self { value, ratio }
    }

    /// Fallible constructor returning `None` if the value is out of range.
    #[inline]
    pub fn try_new(value: T) -> Option<Self> {
        if value <= T::ONE {
            return None;
        }
        let leading_zeros = value.leading_zeros();
        if leading_zeros < 2 {
            return None;
        }
        Some(Self::new_unchecked(value))
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

    /// Barrett reduction for a 2-limb value `(hi·B + lo)`.
    ///
    /// Step 1: `q = floor((hi·B + lo) · µ / B²)`
    /// Step 2: `r = lo - q · modulus`
    #[inline]
    fn lazy_reduce_wide(&self, lo: T, hi: T) -> T {
        //                        ratio[1]  ratio[0]
        //                   *          hi        lo
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //                      +-------------------+
        //                      |         a         |    <-- lo * ratio[0]
        //                      +-------------------+
        //             +------------------+
        //             |        b         |              <-- lo * ratio[1]
        //             +------------------+
        //             +------------------+
        //             |        c         |              <-- hi * ratio[0]
        //             +------------------+
        //   +------------------+
        //   |        d         |                        <-- hi * ratio[1]
        //   +------------------+
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //             +--------+
        //             |   q₃   |
        //             +--------+
        let ah = lo.widening_mul_hw(self.ratio[0]);

        let b = lo.carrying_mul(self.ratio[1], ah);
        let c = hi.widening_mul(self.ratio[0]);

        let d = hi.wrapping_mul(self.ratio[1]);

        let bch = b.1.carrying_add(c.1, b.0.overflowing_add(c.0).1).0;

        let q = d.wrapping_add(bch);

        // Step 2.
        lo.wrapping_sub(q.wrapping_mul(self.value))
    }

    #[inline]
    pub fn reduce_wide(&self, lo: T, hi: T) -> T {
        self.reduce_once(self.lazy_reduce_wide(lo, hi))
    }
}

impl<T: UnsignedInteger> Display for BarrettModulus<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<T: FheUint> primus_reduce::Modulus for BarrettModulus<T> {
    type ValueT = T;

    #[inline]
    fn value(self) -> Option<Self::ValueT> {
        Some(self.value)
    }

    #[inline(always)]
    unsafe fn value_unchecked(self) -> Self::ValueT {
        self.value
    }

    #[inline(always)]
    fn minus_one(self) -> Self::ValueT {
        self.value - T::ONE
    }
}
