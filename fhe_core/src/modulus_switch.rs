use algebra::{AsInto, Field};
use lattice::LWE;

use crate::{LWECiphertext, LWEModulusType};

/// Implementation of modulus switching.
///
/// This function performs on a `LWE<F>`, returns a `LWE<C>` with desired modulus `modulus_after`.
pub fn lwe_modulus_switch<C: LWEModulusType, F: Field>(
    c: LWE<F>,
    modulus_after: C,
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

    let switch = Box::new(|v: F| {
        reduce(C::as_from(
            (AsInto::<f64>::as_into(v.value()) * modulus_after_f64 / modulus_before_f64).round(),
        ))
    });

    let a: Vec<C> = c.a().iter().copied().map(&switch).collect();
    let b = switch(c.b());

    LWECiphertext::new(a, b)
}

/// Implementation of modulus switching.
///
/// This function performs on a `LWE<F>`, puts the result `LWE<C>` with desired modulus `modulus_after`
/// into `destination`.
pub fn lwe_modulus_switch_inplace<C: LWEModulusType, F: Field>(
    c: LWE<F>,
    modulus_after: C,
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

    let switch = Box::new(|v: F| {
        reduce(C::as_from(
            (AsInto::<f64>::as_into(v.value()) * modulus_after_f64 / modulus_before_f64).round(),
        ))
    });

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

    let switch = Box::new(|v: C| {
        reduce(C::as_from(
            (AsInto::<f64>::as_into(v) * modulus_after_f64 / modulus_before_f64).round(),
        ))
    });

    c.a_mut().iter_mut().for_each(|v| *v = switch(*v));
    *c.b_mut() = switch(c.b());
}
