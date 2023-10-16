/// The modular exponentiation.
pub trait PowModulo<Modulus> {
    type Exponent;

    /// Calcualtes `self^exp (mod modulus)`.
    fn pow_modulo(self, exp: Self::Exponent, modulus: Modulus) -> Self;
}
