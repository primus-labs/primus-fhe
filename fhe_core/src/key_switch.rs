use algebra::NTTField;

pub use lwe::KeySwitchingLWEKey;
pub use rlwe::KeySwitchingRLWEKey;

use crate::LWEModulusType;

mod lwe;
mod rlwe;

/// A enum type for different key switching purposes.
#[derive(Debug, Clone)]
pub enum KeySwitchingKeyEnum<C: LWEModulusType, Q: NTTField> {
    /// The key switching is based on rlwe multiply with gadget rlwe.
    RLWE(KeySwitchingRLWEKey<Q>),
    /// The key switching is based on LWE constant multiplication.
    LWE(KeySwitchingLWEKey<C>),
    /// No key switching.
    None,
}
