/// The modular multiplication.
pub trait MulModulo<Modulus, Rhs = Self> {
    type Output;

    /// Calculates `self * rhs mod modulus`.
    ///
    /// The result is in `[0, modulus)`.
    fn mul_modulo(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The modular multiplication assignment.
pub trait MulModuloAssign<Modulus, Rhs = Self> {
    /// Calculates `self *= rhs mod modulus`.
    fn mul_modulo_assign(&mut self, rhs: Rhs, modulus: Modulus);
}
