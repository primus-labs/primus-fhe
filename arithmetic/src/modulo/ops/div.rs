/// The modular division.
pub trait DivModulo<Modulus, Rhs = Self> {
    type Output;

    /// Calculates `self / rhs mod modulus`.
    ///
    /// The result is in `[0, modulus)`.
    fn div_modulo(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The modular division assignment.
pub trait DivModuloAssign<Modulus, Rhs = Self> {
    /// Calculates `self /= rhs mod modulus`.
    fn div_modulo_assign(&mut self, rhs: Rhs, modulus: Modulus);
}
