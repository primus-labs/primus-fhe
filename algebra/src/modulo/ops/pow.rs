/// The modular exponentiation.
pub trait PowModulo<Modulus, Exponent> {
    /// Calcualtes `self^exp (mod modulus)`.
    fn pow_modulo(self, exp: Exponent, modulus: Modulus) -> Self;
}
