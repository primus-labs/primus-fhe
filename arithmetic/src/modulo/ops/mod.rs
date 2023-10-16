mod add;
mod div;
mod inv;
mod mul;
mod neg;
mod pow;
mod sub;

pub use add::{AddModulo, AddModuloAssign};
pub use div::{DivModulo, DivModuloAssign};
pub use inv::{InvModulo, InvModuloAssign, TryInvModulo};
pub use mul::{MulModulo, MulModuloAssign};
pub use neg::{NegModulo, NegModuloAssign};
pub use pow::PowModulo;
pub use sub::{SubModulo, SubModuloAssign};

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
