/// Calculate the inverse element for a field.
pub trait InvModulo<Modulus = Self>: Sized {
    /// Calculate the multiplicative inverse of `self modulo modulus`.
    fn inv_modulo(self, modulus: Modulus) -> Self;
}

/// The modular inversion assignment for a field.
pub trait InvModuloAssign<Modulus = Self> {
    /// Calculates `self^(-1) mod modulus`
    fn inv_modulo_assign(&mut self, modulus: Modulus);
}

/// Try to calculate the inverse element when there is not a field.
pub trait TryInvModulo<Modulus = Self>: Sized {
    /// Try to calculate the multiplicative inverse of `self modulo modulus`.
    ///
    /// # Errors
    ///
    /// If there dose not exist the such inverse, a [`ModuloError`] will be returned.
    fn try_inv_modulo(self, modulus: Modulus) -> Result<Self, crate::AlgebraError>;
}
