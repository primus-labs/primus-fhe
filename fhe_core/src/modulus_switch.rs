use algebra::{AsInto, DecomposableField};
use lattice::LWE;

use crate::{LWECiphertext, LWEModulusType};

/// Implementation of modulus switching.
pub fn lwe_modulus_switch<F: DecomposableField>(
    c: LWE<F>,
    modulus_after: LWEModulusType,
) -> LWECiphertext {
    let modulus_before_f64: f64 = F::MODULUS_VALUE.as_into();
    let modulus_after_f64: f64 = modulus_after.as_into();

    let switch = |v: F| {
        (v.value().as_into() * modulus_after_f64 / modulus_before_f64).floor() as LWEModulusType
    };

    let a: Vec<LWEModulusType> = c.a().iter().copied().map(switch).collect();
    let b = switch(c.b());

    LWECiphertext::new(a, b)
}

/// Implementation of modulus switching.
pub fn lwe_modulus_switch_inplace<F: DecomposableField>(
    c: LWE<F>,
    modulus_after: LWEModulusType,
    destination: &mut LWECiphertext,
) {
    let modulus_before_f64: f64 = F::MODULUS_VALUE.as_into();
    let modulus_after_f64: f64 = modulus_after.as_into();

    let switch = |v: F| {
        (v.value().as_into() * modulus_after_f64 / modulus_before_f64).floor() as LWEModulusType
    };

    destination
        .a_mut()
        .iter_mut()
        .zip(c.a())
        .for_each(|(des, &inp)| *des = switch(inp));

    *destination.b_mut() = switch(c.b());
}
