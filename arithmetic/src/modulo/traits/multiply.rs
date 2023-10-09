#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::BigIntHelperMethods;

/// A number used for fast modular multiplication.
///
/// This is efficient if many operations are multiplied by
/// the same number and then reduced with the same modulus.
#[derive(Clone, Copy, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MulModuloFactor {
    pub(crate) value: u64,
    pub(crate) quotient: u64,
}

#[inline]
fn mul_base_then_div_mod(value: u64, modulus: u64) -> u64 {
    debug_assert!(
        value < modulus,
        "value {value} must be less than modulus {modulus}"
    );

    // ⌊(value * (2^64)) / modulus⌋
    (((value as u128) << 64) / modulus as u128) as u64
}

impl MulModuloFactor {
    /// Constructs a [`MulModuloFactor`].
    ///
    /// * `value` must be less than `modulus`.
    /// * `modulus` must be at most
    /// [`MODULUS_BIT_COUNT_MAX`](crate::constants::MODULUS_BIT_COUNT_MAX) bits.
    #[inline]
    pub fn new(value: u64, modulus: u64) -> Self {
        Self {
            value,
            quotient: mul_base_then_div_mod(value, modulus),
        }
    }

    /// Resets the content of [`MulModuloFactor`].
    ///
    /// * `value` must be less than `modulus`.
    /// * `modulus` must be at most
    /// [`MODULUS_BIT_COUNT_MAX`](crate::constants::MODULUS_BIT_COUNT_MAX) bits.
    pub fn set(&mut self, value: u64, modulus: u64) {
        self.value = value;
        self.set_modulus(modulus);
    }

    /// Resets the `modulus` of [`MulModuloFactor`].
    ///
    /// * `modulus` must be at most
    /// [`MODULUS_BIT_COUNT_MAX`](crate::constants::MODULUS_BIT_COUNT_MAX) bits.
    #[inline]
    pub fn set_modulus(&mut self, modulus: u64) {
        self.quotient = mul_base_then_div_mod(self.value, modulus);
    }

    /// Returns the value of this [`MulModuloFactor`].
    #[inline]
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Returns the quotient of this [`MulModuloFactor`].
    #[inline]
    pub fn quotient(&self) -> u64 {
        self.quotient
    }

    /// Calculates `rhs * self.value mod modulus`.
    ///
    /// The result is in [0, 2 * `modulus`).
    ///
    /// # Proof
    ///
    /// Let `x = rhs`, `w = self.value`, `w' = self.quotient`, `p = modulus` and `β = 2^(64)`.
    ///
    /// By definition, `w' = ⌊wβ/p⌋`. Let `q = ⌊w'x/β⌋`.
    ///
    /// Then, `0 ≤ wβ/p − w' < 1`, `0 ≤ w'x/β - q < 1`.
    ///
    /// Multiplying by `xp/β` and `p` respectively, and adding, yields
    ///
    /// `0 ≤ wx − qp < xp/β + p < 2p < β`
    #[inline]
    pub fn mul_modulo_lazy(&self, rhs: u64, modulus: u64) -> u64 {
        let (_, hw64) = self.quotient.widen_mul(rhs);
        self.value
            .wrapping_mul(rhs)
            .wrapping_sub(hw64.wrapping_mul(modulus))
    }
}

/// The modular multiplication.
pub trait MulModulo<Modulus, Rhs = Self> {
    type Output;

    /// Calculates `self * rhs mod modulus`.
    ///
    /// The result is in `[0, modulus)`.
    fn mul_modulo(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

impl MulModulo<u64, MulModuloFactor> for u64 {
    type Output = Self;

    /// Calculates `self * rhs mod modulus`
    ///
    /// The result is in `[0, modulus)`
    ///
    /// # Correctness
    ///
    /// `modulus` should be at most
    /// [`MODULUS_BIT_COUNT_MAX`](crate::constants::MODULUS_BIT_COUNT_MAX) bits,
    /// and `rhs.value` must be less than `modulus`.
    fn mul_modulo(self, rhs: MulModuloFactor, modulus: u64) -> Self::Output {
        let (_, hw64) = self.widen_mul(rhs.quotient);
        let tmp = self.wrapping_mul(rhs.value) - hw64.wrapping_mul(modulus);

        if tmp >= modulus {
            tmp - modulus
        } else {
            tmp
        }
    }
}

impl MulModulo<u64, u64> for MulModuloFactor {
    type Output = u64;

    /// Calculates `self.value * rhs mod modulus`.
    ///
    /// The result is in `[0, modulus)`.
    ///
    /// # Correctness
    ///
    /// `modulus` should be at most
    /// [`MODULUS_BIT_COUNT_MAX`](crate::constants::MODULUS_BIT_COUNT_MAX) bits,
    /// and `self.value` must be less than `modulus`.
    fn mul_modulo(self, rhs: u64, modulus: u64) -> Self::Output {
        let (_, hw64) = self.quotient.widen_mul(rhs);
        let tmp = self.value.wrapping_mul(rhs) - hw64.wrapping_mul(modulus);

        if tmp >= modulus {
            tmp - modulus
        } else {
            tmp
        }
    }
}

/// The modular multiplication assignment.
pub trait MulModuloAssign<Modulus, Rhs = Self> {
    /// Calculates `self *= rhs mod modulus`.
    fn mul_modulo_assign(&mut self, rhs: Rhs, modulus: Modulus);
}

impl MulModuloAssign<u64, MulModuloFactor> for u64 {
    /// Calculates `self *= rhs mod modulus`.
    ///
    /// The result is in `[0, modulus)`.
    ///
    /// # Correctness
    ///
    /// `modulus` should be at most
    /// [`MODULUS_BIT_COUNT_MAX`](crate::constants::MODULUS_BIT_COUNT_MAX) bits,
    /// and `rhs.value` must be less than `modulus`.
    fn mul_modulo_assign(&mut self, rhs: MulModuloFactor, modulus: u64) {
        let (_, hw64) = self.widen_mul(rhs.quotient);
        let tmp = self.wrapping_mul(rhs.value) - hw64.wrapping_mul(modulus);
        *self = if tmp >= modulus { tmp - modulus } else { tmp };
    }
}
