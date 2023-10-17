/// The modular exponentiation.
pub trait PowModulo<Modulus> {
    /// Exponent type.
    type Exponent;

    /// Calcualtes `self^exp (mod modulus)`.
    fn pow_modulo(self, exp: Self::Exponent, modulus: Modulus) -> Self;
}
