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
///
/// This function performs on a `LWE<F>`, returns a `LWE<C>` with desired modulus `modulus_after`.
pub fn lwe_modulus_switch<C: LWEModulusType, F: DecomposableField>(
    c: LWE<F>,
    modulus_after: C,
    round_method: ModulusSwitchRoundMethod,
) -> LWECiphertext<C> {
    let modulus_before_f64: f64 = F::MODULUS_VALUE.as_into();
    let modulus_after_f64: f64 = modulus_after.as_into();

    let reduce = |v: C| {
        if v < modulus_after {
            v
        } else {
            v - modulus_after
        }
    };

    let switch: Box<dyn Fn(F) -> C> = match round_method {
        ModulusSwitchRoundMethod::Round => Box::new(|v: F| {
            reduce(C::as_from(
                (AsInto::<f64>::as_into(v.value()) * modulus_after_f64 / modulus_before_f64)
                    .round(),
            ))
        }),
        ModulusSwitchRoundMethod::Floor => Box::new(|v: F| {
            reduce(C::as_from(
                (AsInto::<f64>::as_into(v.value()) * modulus_after_f64 / modulus_before_f64)
                    .floor(),
            ))
        }),
        ModulusSwitchRoundMethod::Ceil => Box::new(|v: F| {
            reduce(C::as_from(
                (AsInto::<f64>::as_into(v.value()) * modulus_after_f64 / modulus_before_f64).ceil(),
            ))
        }),
    };

    let a: Vec<C> = c.a().iter().copied().map(&switch).collect();
    let b = switch(c.b());

    LWECiphertext::new(a, b)
}

/// Implementation of modulus switching.
///
/// This function performs on a `LWE<F>`, puts the result `LWE<C>` with desired modulus `modulus_after`
/// into `destination`.
pub fn lwe_modulus_switch_inplace<C: LWEModulusType, F: DecomposableField>(
    c: LWE<F>,
    modulus_after: C,
    round_method: ModulusSwitchRoundMethod,
    destination: &mut LWECiphertext<C>,
) {
    let modulus_before_f64: f64 = F::MODULUS_VALUE.as_into();
    let modulus_after_f64: f64 = modulus_after.as_into();

    let reduce = |v: C| {
        if v < modulus_after {
            v
        } else {
            v - modulus_after
        }
    };

    let switch: Box<dyn Fn(F) -> C> = match round_method {
        ModulusSwitchRoundMethod::Round => Box::new(|v: F| {
            reduce(C::as_from(
                (AsInto::<f64>::as_into(v.value()) * modulus_after_f64 / modulus_before_f64)
                    .round(),
            ))
        }),
        ModulusSwitchRoundMethod::Floor => Box::new(|v: F| {
            reduce(C::as_from(
                (AsInto::<f64>::as_into(v.value()) * modulus_after_f64 / modulus_before_f64)
                    .floor(),
            ))
        }),
        ModulusSwitchRoundMethod::Ceil => Box::new(|v: F| {
            reduce(C::as_from(
                (AsInto::<f64>::as_into(v.value()) * modulus_after_f64 / modulus_before_f64).ceil(),
            ))
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
///
/// This function performs on a `LWE<C>` with modulus `modulus_before`, puts the result `LWE<C>` with desired modulus `modulus_after`
/// back to `c`.
pub fn lwe_modulus_switch_assign_between_modulus<C: LWEModulusType>(
    c: &mut LWE<C>,
    modulus_before: C,
    modulus_after: C,
    round_method: ModulusSwitchRoundMethod,
) {
    let modulus_before_f64: f64 = modulus_before.as_into();
    let modulus_after_f64: f64 = modulus_after.as_into();

    let reduce = |v: C| {
        if v < modulus_after {
            v
        } else {
            v - modulus_after
        }
    };

    let switch: Box<dyn Fn(C) -> C> = match round_method {
        ModulusSwitchRoundMethod::Round => Box::new(|v: C| {
            reduce(C::as_from(
                (AsInto::<f64>::as_into(v) * modulus_after_f64 / modulus_before_f64).round(),
            ))
        }),
        ModulusSwitchRoundMethod::Floor => Box::new(|v: C| {
            reduce(C::as_from(
                (AsInto::<f64>::as_into(v) * modulus_after_f64 / modulus_before_f64).floor(),
            ))
        }),
        ModulusSwitchRoundMethod::Ceil => Box::new(|v: C| {
            reduce(C::as_from(
                (AsInto::<f64>::as_into(v) * modulus_after_f64 / modulus_before_f64).ceil(),
            ))
        }),
    };

    c.a_mut().iter_mut().for_each(|v| *v = switch(*v));
    *c.b_mut() = switch(c.b());
}
