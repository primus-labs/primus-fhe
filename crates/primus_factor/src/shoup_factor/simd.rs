use core::simd::cmp::SimdPartialOrd;
use std::simd::cmp::SimdOrd;

use primus_integer::{
    DivWide, LaneArray, SimdArray, SimdInteger, SimdMaskArray, SimdUnsignedInteger, WideningMul,
};

use crate::{FactorMul, LazyFactorMul};

use super::ShoupFactor;

/// SIMD Shoup factor for fast multiplication by fixed per-lane values.
///
/// Stores one fixed multiplier and one precomputed quotient per SIMD lane.
/// Every operation must use the same modulus used to construct or reset the
/// factor.
///
/// The modulus must be less than `2^(T::BITS - 1)` so the lazy range fits in
/// one word per lane.
#[derive(Debug, Clone, Copy, Default)]
pub struct SimdShoupFactor<T: SimdUnsignedInteger> {
    /// Fixed multiplier represented by each SIMD lane.
    value: T::SimdT,
    /// Precomputed quotient for each SIMD lane.
    quotient: T::SimdT,
}

impl<T: SimdUnsignedInteger> From<ShoupFactor<T>> for SimdShoupFactor<T> {
    #[inline]
    fn from(factor: ShoupFactor<T>) -> Self {
        Self {
            value: T::SimdT::splat(factor.value()),
            quotient: T::SimdT::splat(factor.quotient()),
        }
    }
}

impl<T: SimdUnsignedInteger> SimdShoupFactor<T> {
    /// Constructs a [`SimdShoupFactor<T>`].
    ///
    /// * Every lane of `value` must be less than `modulus`.
    /// * `modulus` must be less than `2^(T::BITS - 1)`.
    #[inline]
    pub fn new(value: T::SimdT, modulus: T) -> Self {
        debug_assert!(value.simd_lt(T::SimdT::splat(modulus)).all());

        Self {
            value,
            quotient: Self::compute_quotient(value, modulus),
        }
    }

    /// Constructs a [`SimdShoupFactor<T>`] from raw SIMD lanes.
    ///
    /// The caller must ensure each quotient lane was precomputed from the
    /// corresponding value lane and the modulus used by later operations.
    #[inline]
    pub fn with_quotient(value: T::SimdT, quotient: T::SimdT) -> Self {
        Self { value, quotient }
    }

    /// Constructs a [`SimdShoupFactor<T>`] from one scalar factor per SIMD lane.
    ///
    /// # Panics
    ///
    /// Panics if `factors.len()` is not equal to `T::LANE_COUNT`.
    #[inline]
    pub fn from_slice(factors: &[ShoupFactor<T>]) -> Self {
        assert_eq!(factors.len(), T::LANE_COUNT);

        let mut values = <T as SimdInteger>::Array::zero();
        let mut quotients = <T as SimdInteger>::Array::zero();
        for ((value, quotient), factor) in values
            .as_mut()
            .iter_mut()
            .zip(quotients.as_mut().iter_mut())
            .zip(factors.iter().copied())
        {
            *value = factor.value();
            *quotient = factor.quotient();
        }

        Self {
            value: T::SimdT::from_array(values),
            quotient: T::SimdT::from_array(quotients),
        }
    }

    /// Recomputes quotients for a new modulus.
    ///
    /// Every lane of the current value must be less than `modulus`, and
    /// `modulus` must be less than `2^(T::BITS - 1)`.
    #[inline]
    pub fn set_modulus(&mut self, modulus: T) {
        debug_assert!(self.value.simd_lt(T::SimdT::splat(modulus)).all());

        self.quotient = Self::compute_quotient(self.value, modulus);
    }

    /// Resets the content of [`SimdShoupFactor<T>`].
    ///
    /// * Every lane of `value` must be less than `modulus`.
    /// * `modulus` must be less than `2^(T::BITS - 1)`.
    #[inline]
    pub fn set(&mut self, value: T::SimdT, modulus: T) {
        self.value = value;
        self.set_modulus(modulus);
    }

    /// Returns the value of this [`SimdShoupFactor<T>`].
    #[inline]
    pub fn value(self) -> T::SimdT {
        self.value
    }

    /// Returns the quotient of this [`SimdShoupFactor<T>`].
    #[inline]
    pub fn quotient(self) -> T::SimdT {
        self.quotient
    }

    #[inline]
    fn compute_quotient(value: T::SimdT, modulus: T) -> T::SimdT {
        let mut quotient = <T as SimdInteger>::Array::zero();
        for (quotient, value) in quotient.as_mut().iter_mut().zip(value.to_array()) {
            *quotient = DivWide::div_wide(T::ZERO, value, modulus);
        }

        T::SimdT::from_array(quotient)
    }
}

impl<T: SimdUnsignedInteger> LazyFactorMul<T::SimdT> for SimdShoupFactor<T> {
    #[inline]
    fn lazy_factor_mul_modulo(self, b: T::SimdT, modulus: T::SimdT) -> T::SimdT {
        let hw = self.quotient.widening_mul_hw(b);
        self.value * b - (modulus * hw)
    }
}

impl<T: SimdUnsignedInteger> FactorMul<T::SimdT> for SimdShoupFactor<T> {
    #[inline]
    fn factor_mul_modulo(self, b: T::SimdT, modulus: T::SimdT) -> T::SimdT {
        let t = self.lazy_factor_mul_modulo(b, modulus);
        t.simd_min(t - modulus)
    }
}
