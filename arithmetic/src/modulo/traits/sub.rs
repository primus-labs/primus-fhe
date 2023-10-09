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

impl FastSubModulo<u64> for u64 {
    type Output = u64;

    fn sub_modulo(self, rhs: Self, modulus: u64) -> Self::Output {
        if self >= rhs {
            self - rhs
        } else {
            modulus - rhs + self
        }
    }
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

impl FastSubModuloAssign<u64> for u64 {
    fn sub_modulo_assign(&mut self, rhs: Self, modulus: u64) {
        if *self >= rhs {
            *self -= rhs;
        } else {
            *self += modulus - rhs;
        }
    }
}
