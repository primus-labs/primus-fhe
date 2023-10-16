/// The modular addition.
pub trait AddModulo<Modulus, Rhs = Self> {
    /// Output type.
    type Output;

    /// Calculates `self + rhs mod modulus`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `rhs < modulus`
    fn add_modulo(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The modular addition assignment.
pub trait AddModuloAssign<Modulus, Rhs = Self> {
    /// Calculates `self += rhs mod modulus`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `rhs < modulus`
    fn add_modulo_assign(&mut self, rhs: Rhs, modulus: Modulus);
}
