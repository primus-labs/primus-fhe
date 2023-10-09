/// The modular exponentiation.
pub trait PowerModulo<Modulus> {
    type Exponent;

    /// Calcualtes `self^exponent (mod modulus)`.
    fn pow_modulo(self, exponent: Self::Exponent, modulus: &Modulus) -> Self;
}
