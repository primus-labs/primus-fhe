use algebra::{AsInto, DecomposableField};
use lattice::LWE;

use crate::{LWECiphertext, LWEModulusType};

/// Modulus Switch round method.
#[derive(Debug, Clone, Copy)]
pub enum ModulusSwitchRoundMethod {
    /// round
    Round,
    /// floor
    Floor,
    /// ceil
    Ceil,
}

/// Implementation of modulus switching.
pub fn lwe_modulus_switch<F: Field>(
    c: LWE<F>,
    modulus_after: LWEModulusType,
    round_method: ModulusSwitchRoundMethod,
) -> LWECiphertext {
    let modulus_before_f64: f64 = F::MODULUS_VALUE.as_into();
    let modulus_after_f64: f64 = modulus_after.as_into();

    let switch: Box<dyn Fn(F) -> LWEModulusType> = match round_method {
        ModulusSwitchRoundMethod::Round => Box::new(|v: F| {
            (v.get().as_into() * modulus_after_f64 / modulus_before_f64).round() as LWEModulusType
        }),
        ModulusSwitchRoundMethod::Floor => Box::new(|v: F| {
            (v.get().as_into() * modulus_after_f64 / modulus_before_f64).floor() as LWEModulusType
        }),
        ModulusSwitchRoundMethod::Ceil => Box::new(|v: F| {
            (v.get().as_into() * modulus_after_f64 / modulus_before_f64).ceil() as LWEModulusType
        }),
    };

    let a: Vec<LWEModulusType> = c.a().iter().copied().map(&switch).collect();
    let b = switch(c.b());

    LWECiphertext::new(a, b)
}

/// Implementation of modulus switching.
pub fn lwe_modulus_switch_inplace<F: DecomposableField>(
    c: LWE<F>,
    modulus_after: LWEModulusType,
    round_method: ModulusSwitchRoundMethod,
    destination: &mut LWECiphertext,
) {
    let modulus_before_f64: f64 = F::MODULUS_VALUE.as_into();
    let modulus_after_f64: f64 = modulus_after.as_into();

    let switch: Box<dyn Fn(F) -> LWEModulusType> = match round_method {
        ModulusSwitchRoundMethod::Round => Box::new(|v: F| {
            (v.get().as_into() * modulus_after_f64 / modulus_before_f64).round() as LWEModulusType
        }),
        ModulusSwitchRoundMethod::Floor => Box::new(|v: F| {
            (v.get().as_into() * modulus_after_f64 / modulus_before_f64).floor() as LWEModulusType
        }),
        ModulusSwitchRoundMethod::Ceil => Box::new(|v: F| {
            (v.get().as_into() * modulus_after_f64 / modulus_before_f64).ceil() as LWEModulusType
        }),
    };

    destination
        .a_mut()
        .iter_mut()
        .zip(c.a())
        .for_each(|(des, &inp)| *des = switch(inp));

    *destination.b_mut() = switch(c.b());
}
