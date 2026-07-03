use primus_integer::{DivWide, UnsignedInteger};

use crate::{FactorBase, FactorMul, LazyFactorMul};

mod slice;

#[cfg(feature = "simd")]
mod simd;

#[cfg(feature = "simd")]
pub use simd::SimdShoupFactor;

/// Precomputed Shoup factor for fast multiplication by a fixed value.
///
/// Stores `value` and `floor(value * 2^T::BITS / modulus)` so repeated
/// multiplications by `value` can avoid division. Every operation must use the
/// same modulus used to construct or reset the factor.
///
/// The modulus must be less than `2^(T::BITS - 1)` so the lazy range fits in
/// one word.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShoupFactor<T: UnsignedInteger> {
    /// Fixed multiplier represented by this factor.
    value: T,
    /// Precomputed quotient `floor(value * 2^T::BITS / modulus)`.
    quotient: T,
}

impl<T: UnsignedInteger> FactorBase<T> for ShoupFactor<T> {
    /// Constructs a [`ShoupFactor<T>`].
    ///
    /// * `value` must be less than `modulus`.
    /// * `modulus` must be less than `2^(T::BITS - 1)`.
    #[inline]
    fn new(value: T, modulus: T) -> Self {
        debug_assert!(value < modulus);

        // Calculate the quotient of `value * 2^T::BITS / modulus`.
        let quotient = DivWide::div_wide(T::ZERO, value, modulus);

        Self { value, quotient }
    }
}

impl<T: UnsignedInteger> ShoupFactor<T> {
    /// Constructs a [`ShoupFactor<T>`] from an already-computed value and
    /// quotient pair.
    ///
    /// The caller must ensure that `quotient == floor(value * 2^T::BITS /
    /// modulus)` for the intended modulus. No division is performed.
    ///
    /// This is useful when value and quotient are stored in separate
    /// structure-of-arrays layouts (e.g. for SIMD).
    #[inline]
    pub const fn from_raw(value: T, quotient: T) -> Self {
        Self { value, quotient }
    }

    /// Computes the Shoup quotient `floor(value * 2^T::BITS / modulus)`
    /// without constructing a full [`ShoupFactor<T>`].
    ///
    /// This is equivalent to `ShoupFactor::new(value, modulus).quotient()`
    /// but avoids discarding the value field.
    #[inline]
    pub fn quotient_for(value: T, modulus: T) -> T {
        DivWide::div_wide(T::ZERO, value, modulus)
    }

    /// Recomputes the quotient for a new modulus.
    ///
    /// The current value must be less than `modulus`, and `modulus` must be
    /// less than `2^(T::BITS - 1)`.
    #[inline]
    pub fn set_modulus(&mut self, modulus: T) {
        debug_assert!(self.value < modulus);

        // Calculate the quotient of `value * 2^T::BITS / modulus`.
        self.quotient = DivWide::div_wide(T::ZERO, self.value, modulus);
    }

    /// Resets the content of [`ShoupFactor<T>`].
    ///
    /// * `value` must be less than `modulus`.
    /// * `modulus` must be less than `2^(T::BITS - 1)`.
    #[inline]
    pub fn set(&mut self, value: T, modulus: T) {
        self.value = value;
        self.set_modulus(modulus);
    }

    /// Returns the value of this [`ShoupFactor<T>`].
    #[inline]
    pub const fn value(self) -> T {
        self.value
    }

    /// Returns the quotient of this [`ShoupFactor<T>`].
    #[inline]
    pub const fn quotient(self) -> T {
        self.quotient
    }
}

impl<T: UnsignedInteger> LazyFactorMul<T> for ShoupFactor<T> {
    /// Calculates `self.value() * b (mod 2 * modulus)`.
    ///
    /// `b` must be less than `modulus`, `modulus` must match the modulus used
    /// to precompute `self.quotient()`, and `modulus` must be less than
    /// `2^(T::BITS - 1)`. The result is in `[0, 2 * modulus)`.
    ///
    /// # Proof
    ///
    /// Let `x = b`, `w = self.value`, `w' = self.quotient`, `p = modulus`, and
    /// `B = 2^T::BITS`.
    ///
    /// By definition, `w' = floor(wB / p)`. Let `q = floor(w'x / B)`.
    ///
    /// Then, `0 <= wB / p - w' < 1`, `0 <= w'x / B - q < 1`.
    ///
    /// Multiplying by `xp / B` and `p` respectively, and adding, yields
    ///
    /// `0 <= wx - qp < xp / B + p < 2p < B`.
    #[inline]
    fn lazy_factor_mul_modulo(self, b: T, modulus: T) -> T {
        let hw = self.quotient.widening_mul_hw(b);
        self.value
            .wrapping_mul(b)
            .wrapping_sub(modulus.wrapping_mul(hw))
    }
}

impl<T: UnsignedInteger> FactorMul<T> for ShoupFactor<T> {
    /// Calculates `self.value() * b (mod modulus)`.
    ///
    /// `b` must be less than `modulus`, `modulus` must match the modulus used
    /// to precompute `self.quotient()`, and `modulus` must be less than
    /// `2^(T::BITS - 1)`. The result is in `[0, modulus)`.
    #[inline]
    fn factor_mul_modulo(self, b: T, modulus: T) -> T {
        let t = self.lazy_factor_mul_modulo(b, modulus);
        t.min(t.wrapping_sub(modulus))
    }
}
