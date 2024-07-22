use algebra::{AsInto, DecomposableField, FheField};
use lattice::LWE;

use crate::{LWECipherValueContainer, LWECiphertext};

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
pub fn lwe_modulus_switch<C: LWECipherValueContainer, F: FheField>(
    c: LWE<F>,
    modulus_after: C,
    round_method: ModulusSwitchRoundMethod,
) -> LWECiphertext<C> {
    let modulus_before_f64: f64 = F::MODULUS_VALUE.as_into();
    let modulus_after_f64: f64 = modulus_after.as_into();

    let switch: Box<dyn Fn(F) -> C> = match round_method {
        ModulusSwitchRoundMethod::Round => Box::new(|v: F| {
            C::as_from((v.value().as_into() * modulus_after_f64 / modulus_before_f64).round())
        }),
        ModulusSwitchRoundMethod::Floor => Box::new(|v: F| {
            C::as_from((v.value().as_into() * modulus_after_f64 / modulus_before_f64).floor())
        }),
        ModulusSwitchRoundMethod::Ceil => Box::new(|v: F| {
            C::as_from((v.value().as_into() * modulus_after_f64 / modulus_before_f64).ceil())
        }),
    };

    let a: Vec<C> = c.a().iter().copied().map(&switch).collect();
    let b = switch(c.b());

    LWECiphertext::new(a, b)
}

/// Implementation of modulus switching.
pub fn lwe_modulus_switch_inplace<C: LWECipherValueContainer, F: DecomposableField>(
    c: LWE<F>,
    modulus_after: C,
    round_method: ModulusSwitchRoundMethod,
    destination: &mut LWECiphertext<C>,
) {
    let modulus_before_f64: f64 = F::MODULUS_VALUE.as_into();
    let modulus_after_f64: f64 = modulus_after.as_into();

    let switch: Box<dyn Fn(F) -> C> = match round_method {
        ModulusSwitchRoundMethod::Round => Box::new(|v: F| {
            C::as_from((v.value().as_into() * modulus_after_f64 / modulus_before_f64).round())
        }),
        ModulusSwitchRoundMethod::Floor => Box::new(|v: F| {
            C::as_from((v.value().as_into() * modulus_after_f64 / modulus_before_f64).floor())
        }),
        ModulusSwitchRoundMethod::Ceil => Box::new(|v: F| {
            C::as_from((v.value().as_into() * modulus_after_f64 / modulus_before_f64).ceil())
        }),
    };

    destination
        .a_mut()
        .iter_mut()
        .zip(c.a())
        .for_each(|(des, &inp)| *des = switch(inp));

    *destination.b_mut() = switch(c.b());
}
