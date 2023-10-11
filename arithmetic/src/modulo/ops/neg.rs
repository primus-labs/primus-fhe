/// The modular negation.
pub trait NegModulo<Modulus> {
    type Output;

    /// Calculates `(-self) mod modulus`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn neg_modulo(self, modulus: Modulus) -> Self::Output;
}

/// The modular negation assignment.
pub trait NegModuloAssign<Modulus> {
    /// Calculates `(-self) mod modulus`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn neg_modulo_assign(&mut self, modulus: Modulus);
}
