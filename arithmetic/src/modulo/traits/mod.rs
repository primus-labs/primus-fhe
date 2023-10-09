mod add;
mod add_mul;
mod dot_product;
mod inverse;
mod multiply;
mod neg;
mod pow;
mod sub;

pub use add::{FastAddModulo, FastAddModuloAssign};
// pub use add_mul::{AddMulModulo, AddMulModuloAssign};
// pub use dot_product::DotProductModulo;
pub use pow::PowerModulo;
// pub use inverse::TryInverse;
pub use multiply::{MulModulo, MulModuloAssign, MulModuloFactor};
pub use neg::{NegModulo, NegModuloAssign};
pub use sub::{FastSubModulo, FastSubModuloAssign};

/// The modulo operation.
pub trait Modulo<Modulus>: Sized {
    type Output;

    /// Caculates `self (mod modulus)`.
    fn modulo(self, modulus: Modulus) -> Self::Output;
}

/// The modulo assignment operation.
pub trait ModuloAssign<Modulus>: Sized {
    /// Caculates `self (mod modulus)`.
    fn modulo_assign(&mut self, modulus: Modulus);
}
