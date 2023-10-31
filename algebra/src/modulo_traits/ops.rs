/// The modulo operation.
pub trait Modulo<Modulus>: Sized {
    /// Output type.
    type Output;

    /// Caculates `self (mod modulus)`.
    fn reduce(self, modulus: Modulus) -> Self::Output;
}

/// The modulo assignment operation.
pub trait ModuloAssign<Modulus>: Sized {
    /// Caculates `self (mod modulus)`.
    fn reduce_assign(&mut self, modulus: Modulus);
}

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
    fn add_reduce(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The modular addition assignment.
pub trait AddModuloAssign<Modulus, Rhs = Self> {
    /// Calculates `self += rhs mod modulus`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `rhs < modulus`
    fn add_reduce_assign(&mut self, rhs: Rhs, modulus: Modulus);
}

/// The modular subtraction.
pub trait SubModulo<Modulus, Rhs = Self> {
    /// Output type.
    type Output;

    /// Calculates `self - rhs mod modulus`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `rhs < modulus`
    fn sub_reduce(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The modular subtraction assignment.
pub trait SubModuloAssign<Modulus, Rhs = Self> {
    /// Calculates `self -= rhs mod modulus`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `rhs < modulus`
    fn sub_reduce_assign(&mut self, rhs: Rhs, modulus: Modulus);
}

/// The modular negation.
pub trait NegModulo<Modulus> {
    /// Output type.
    type Output;

    /// Calculates `(-self) mod modulus`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn neg_reduce(self, modulus: Modulus) -> Self::Output;
}

/// The modular negation assignment.
pub trait NegModuloAssign<Modulus> {
    /// Calculates `(-self) mod modulus`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn neg_reduce_assign(&mut self, modulus: Modulus);
}

/// The modular multiplication.
pub trait MulModulo<Modulus, Rhs = Self> {
    /// Output type.
    type Output;

    /// Calculates `self * rhs mod modulus`.
    ///
    /// The result is in `[0, modulus)`.
    fn mul_reduce(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The modular multiplication assignment.
pub trait MulModuloAssign<Modulus, Rhs = Self> {
    /// Calculates `self *= rhs mod modulus`.
    fn mul_reduce_assign(&mut self, rhs: Rhs, modulus: Modulus);
}

/// The modular exponentiation.
pub trait PowModulo<Modulus, Exponent> {
    /// Calcualtes `self^exp (mod modulus)`.
    fn pow_reduce(self, exp: Exponent, modulus: Modulus) -> Self;
}

/// Calculate the inverse element for a field.
pub trait InvModulo<Modulus = Self>: Sized {
    /// Calculate the multiplicative inverse of `self modulo modulus`.
    fn inv_reduce(self, modulus: Modulus) -> Self;
}

/// The modular inversion assignment for a field.
pub trait InvModuloAssign<Modulus = Self> {
    /// Calculates `self^(-1) mod modulus`
    fn inv_reduce_assign(&mut self, modulus: Modulus);
}

/// Try to calculate the inverse element when there is not a field.
pub trait TryInvModulo<Modulus = Self>: Sized {
    /// Try to calculate the multiplicative inverse of `self modulo modulus`.
    ///
    /// # Errors
    ///
    /// If there dose not exist the such inverse, a [`ModuloError`] will be returned.
    fn try_inv_reduce(self, modulus: Modulus) -> Result<Self, crate::AlgebraError>;
}

/// The modular division.
pub trait DivModulo<Modulus, Rhs = Self> {
    /// Output type.
    type Output;

    /// Calculates `self / rhs mod modulus`.
    ///
    /// The result is in `[0, modulus)`.
    fn div_reduce(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The modular division assignment.
pub trait DivModuloAssign<Modulus, Rhs = Self> {
    /// Calculates `self /= rhs mod modulus`.
    fn div_reduce_assign(&mut self, rhs: Rhs, modulus: Modulus);
}
