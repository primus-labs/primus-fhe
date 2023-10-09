use crate::modulo::{Modulo, MulModulo, MulModuloFactor, MulModuloAssign};
use crate::primitive::BigIntHelperMethods;

use super::Modulus;

impl MulModulo<&Modulus> for u64 {
    type Output = Self;

    fn mul_modulo(self, rhs: Self, modulus: &Modulus) -> Self::Output {
        self.widen_mul(rhs).modulo(modulus)
    }
}

impl MulModulo<&Modulus, MulModuloFactor> for u64 {
    type Output = Self;

    /// Calculates `self * rhs mod modulus`
    ///
    /// The result is in `[0, modulus)`
    ///
    /// # Correctness
    ///
    /// `rhs.value` must be less than `modulus`.
    fn mul_modulo(self, rhs: MulModuloFactor, modulus: &Modulus) -> Self::Output {
        let modulus = modulus.value();

        let (_, hw64) = self.widen_mul(rhs.quotient);
        let tmp = self.wrapping_mul(rhs.value) - hw64.wrapping_mul(modulus);

        if tmp >= modulus {
            tmp - modulus
        } else {
            tmp
        }
    }
}

impl MulModulo<&Modulus, u64> for MulModuloFactor {
    type Output = u64;

    /// Calculates `self.value * rhs mod modulus`.
    ///
    /// The result is in `[0, modulus)`.
    ///
    /// # Correctness
    ///
    /// `self.value` must be less than `modulus`.
    fn mul_modulo(self, rhs: u64, modulus: &Modulus) -> Self::Output {
        let modulus = modulus.value();

        let (_, hw64) = self.quotient.widen_mul(rhs);
        let tmp = self
            .value
            .wrapping_mul(rhs)
            .wrapping_sub(hw64.wrapping_mul(modulus));

        if tmp >= modulus {
            tmp - modulus
        } else {
            tmp
        }
    }
}

impl MulModuloAssign<&Modulus> for u64 {
    fn mul_modulo_assign(&mut self, rhs: Self, modulus: &Modulus) {
        *self = self.widen_mul(rhs).modulo(modulus);
    }
}

impl MulModuloAssign<&Modulus, MulModuloFactor> for u64 {
    /// Calculates `self *= rhs mod modulus`.
    ///
    /// The result is in `[0, modulus)`.
    ///
    /// # Correctness
    ///
    /// `rhs.value` must be less than `modulus`.
    fn mul_modulo_assign(&mut self, rhs: MulModuloFactor, modulus: &Modulus) {
        let (_, hw64) = self.widen_mul(rhs.quotient);
        let tmp = self.wrapping_mul(rhs.value) - hw64.wrapping_mul(modulus.value());

        *self = if tmp >= modulus.value() {
            tmp - modulus.value()
        } else {
            tmp
        };
    }
}
