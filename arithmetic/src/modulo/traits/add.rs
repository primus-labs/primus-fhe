/// The modular addition.
pub trait FastAddModulo<Modulus, Rhs = Self> {
    type Output;

    /// Calculates `self + rhs mod modulus`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `rhs < modulus`
    fn add_modulo(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

impl FastAddModulo<u64> for u64 {
    type Output = u64;

    fn add_modulo(self, rhs: Self, modulus: u64) -> Self::Output {
        let r = self + rhs;
        if r >= modulus || r < self {
            r - modulus
        } else {
            r
        }
    }
}

/// The modular addition assignment.
pub trait FastAddModuloAssign<Modulus, Rhs = Self> {
    /// Calculates `self += rhs mod modulus`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `rhs < modulus`
    fn add_modulo_assign(&mut self, rhs: Rhs, modulus: Modulus);
}

impl FastAddModuloAssign<u64> for u64 {
    fn add_modulo_assign(&mut self, rhs: Self, modulus: u64) {
        let r = *self + rhs;
        *self = if r >= modulus || r < *self {
            r - modulus
        } else {
            r
        };
    }
}
