use algebra::{AsFrom, AsInto, DecomposableField, FheField, NTTField, Polynomial};
use lattice::{LWE, RLWE};

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
pub fn lwe_modulus_switch<C: LWEModulusType, F: FheField>(
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
pub fn lwe_modulus_switch_inplace<C: LWEModulusType, F: DecomposableField>(
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

/// Implementation of modulus switching.
pub fn lwe_modulus_switch_between_field<Q: FheField, Qks: FheField>(
    c: LWE<Q>,
    round_method: ModulusSwitchRoundMethod,
) -> LWECiphertext<Qks> {
    let modulus_before_f64: f64 = Q::MODULUS_VALUE.as_into();
    let modulus_after_f64: f64 = Qks::MODULUS_VALUE.as_into();

    let switch: Box<dyn Fn(Q) -> Qks> = match round_method {
        ModulusSwitchRoundMethod::Round => Box::new(|v: Q| {
            Qks::lazy_new(Qks::Value::as_from(
                (v.value().as_into() * modulus_after_f64 / modulus_before_f64).round(),
            ))
        }),
        ModulusSwitchRoundMethod::Floor => Box::new(|v: Q| {
            Qks::lazy_new(Qks::Value::as_from(
                (v.value().as_into() * modulus_after_f64 / modulus_before_f64).floor(),
            ))
        }),
        ModulusSwitchRoundMethod::Ceil => Box::new(|v: Q| {
            Qks::lazy_new(Qks::Value::as_from(
                (v.value().as_into() * modulus_after_f64 / modulus_before_f64).ceil(),
            ))
        }),
    };

    let a: Vec<Qks> = c.a().iter().copied().map(&switch).collect();
    let b = switch(c.b());

    LWECiphertext::new(a, b)
}

/// Implementation of modulus switching.
pub fn rlwe_modulus_switch_between_field<Q: NTTField, Qks: NTTField>(
    c: RLWE<Q>,
    round_method: ModulusSwitchRoundMethod,
) -> RLWE<Qks> {
    let modulus_before_f64: f64 = Q::MODULUS_VALUE.as_into();
    let modulus_after_f64: f64 = Qks::MODULUS_VALUE.as_into();

    let switch: Box<dyn Fn(Q) -> Qks> = match round_method {
        ModulusSwitchRoundMethod::Round => Box::new(|v: Q| {
            Qks::lazy_new(Qks::Value::as_from(
                (v.value().as_into() * modulus_after_f64 / modulus_before_f64).round(),
            ))
        }),
        ModulusSwitchRoundMethod::Floor => Box::new(|v: Q| {
            Qks::lazy_new(Qks::Value::as_from(
                (v.value().as_into() * modulus_after_f64 / modulus_before_f64).floor(),
            ))
        }),
        ModulusSwitchRoundMethod::Ceil => Box::new(|v: Q| {
            Qks::lazy_new(Qks::Value::as_from(
                (v.value().as_into() * modulus_after_f64 / modulus_before_f64).ceil(),
            ))
        }),
    };

    let a: Vec<Qks> = c.a().iter().copied().map(&switch).collect();
    let b: Vec<Qks> = c.b().iter().copied().map(&switch).collect();

    RLWE::new(Polynomial::new(a), Polynomial::new(b))
}
