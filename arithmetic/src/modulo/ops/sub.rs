/// The modular subtraction.
pub trait FastSubModulo<Modulus, Rhs = Self> {
    type Output;

    /// Calculates `self - rhs mod modulus`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `rhs < modulus`
    fn sub_modulo(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The modular subtraction assignment.
pub trait FastSubModuloAssign<Modulus, Rhs = Self> {
    /// Calculates `self -= rhs mod modulus`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `rhs < modulus`
    fn sub_modulo_assign(&mut self, rhs: Rhs, modulus: Modulus);
}
