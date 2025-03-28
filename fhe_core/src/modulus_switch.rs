use algebra::{integer::UnsignedInteger, reduce::ModulusValue};
use bigdecimal::{BigDecimal, RoundingMode};
use num_traits::FromPrimitive;

use crate::LweCiphertext;

/// Implementation of modulus switching.
///
/// This function performs on a [`LweCiphertext<CIn>`],
/// returns a [`LweCiphertext<COut>`] with desired modulus `modulus_out`.
pub fn lwe_modulus_switch<CIn: UnsignedInteger, COut: UnsignedInteger>(
    c_in: &LweCiphertext<CIn>,
    modulus_in: CIn,
    modulus_out: ModulusValue<COut>,
) -> LweCiphertext<COut> {
    match modulus_out {
        ModulusValue::Native => lwe_modulus_switch_to_native(c_in, modulus_in),
        ModulusValue::PowerOf2(modulus_out) => {
            lwe_modulus_switch_to_pow_of_2(c_in, modulus_in, modulus_out)
        }
        ModulusValue::Prime(_) | ModulusValue::Others(_) => unimplemented!(),
    }
}

/// Implementation of modulus switching.
///
/// This function performs on a [`LweCiphertext<CIn>`],
/// returns a [`LweCiphertext<COut>`] with desired modulus `modulus_out`.
pub fn lwe_modulus_switch_to_pow_of_2<CIn: UnsignedInteger, COut: UnsignedInteger>(
    c_in: &LweCiphertext<CIn>,
    modulus_in: CIn,
    modulus_out: COut,
) -> LweCiphertext<COut> {
    let modulus_in_dec = modulus_in.to_decimal();
    let modulus_out_dec = modulus_out.to_decimal();

    let reduce = |v: COut| {
        if v < modulus_out {
            v
        } else {
            v - modulus_out
        }
    };

    let switch = |v: CIn| {
        reduce(COut::from_decimal(
            &(v.to_decimal() * &modulus_out_dec / &modulus_in_dec)
                .with_scale_round(0, RoundingMode::HalfUp),
        ))
    };

    let a: Vec<COut> = c_in.a().iter().copied().map(&switch).collect();
    let b = switch(c_in.b());

    LweCiphertext::new(a, b)
}

/// Implementation of modulus switching.
///
/// This function performs on a [`LweCiphertext<CIn>`],
/// returns a [`LweCiphertext<COut>`] with desired modulus `modulus_out`.
pub fn lwe_modulus_switch_to_native<CIn: UnsignedInteger, COut: UnsignedInteger>(
    c_in: &LweCiphertext<CIn>,
    modulus_in: CIn,
) -> LweCiphertext<COut> {
    let modulus_in_dec = modulus_in.to_decimal();
    let modulus_out_dec = BigDecimal::from_u128(1_u128 << (COut::BITS - 1))
        .unwrap()
        .double();

    let switch = |v: CIn| {
        COut::from_decimal(
            &(v.to_decimal() * &modulus_out_dec / &modulus_in_dec)
                .with_scale_round(0, RoundingMode::HalfUp),
        )
    };

    let a: Vec<COut> = c_in.a().iter().copied().map(&switch).collect();
    let b = switch(c_in.b());

    LweCiphertext::new(a, b)
}

/// Implementation of modulus switching.
///
/// This function performs on a [`LweCiphertext<CIn>`],
/// puts the result [`LweCiphertext<COut>`] with desired modulus `modulus_out`
/// into `c_out`.
pub fn lwe_modulus_switch_inplace<CIn: UnsignedInteger, COut: UnsignedInteger>(
    c_in: LweCiphertext<CIn>,
    modulus_in: CIn,
    modulus_out: ModulusValue<COut>,
    c_out: &mut LweCiphertext<COut>,
) {
    match modulus_out {
        ModulusValue::Native => lwe_modulus_switch_inplace_to_native(c_in, modulus_in, c_out),
        ModulusValue::PowerOf2(modulus_out) => {
            lwe_modulus_switch_inplace_to_pow_of_2(c_in, modulus_in, modulus_out, c_out)
        }
        ModulusValue::Prime(_) | ModulusValue::Others(_) => unimplemented!(),
    }
}

/// Implementation of modulus switching.
///
/// This function performs on a [`LweCiphertext<CIn>`],
/// puts the result [`LweCiphertext<COut>`] with desired modulus `modulus_out`
/// into `c_out`.
pub fn lwe_modulus_switch_inplace_to_pow_of_2<CIn: UnsignedInteger, COut: UnsignedInteger>(
    c_in: LweCiphertext<CIn>,
    modulus_in: CIn,
    modulus_out: COut,
    c_out: &mut LweCiphertext<COut>,
) {
    let modulus_in_dec = modulus_in.to_decimal();
    let modulus_out_dec = modulus_out.to_decimal();

    let reduce = |v: COut| {
        if v < modulus_out {
            v
        } else {
            v - modulus_out
        }
    };

    let switch = |v: CIn| {
        reduce(COut::from_decimal(
            &(v.to_decimal() * &modulus_out_dec / &modulus_in_dec)
                .with_scale_round(0, RoundingMode::HalfUp),
        ))
    };

    c_out
        .a_mut()
        .iter_mut()
        .zip(c_in.a())
        .for_each(|(des, &inp)| *des = switch(inp));
    *c_out.b_mut() = switch(c_in.b());
}

/// Implementation of modulus switching.
///
/// This function performs on a [`LweCiphertext<CIn>`],
/// puts the result [`LweCiphertext<COut>`] with desired modulus `modulus_out`
/// into `c_out`.
pub fn lwe_modulus_switch_inplace_to_native<CIn: UnsignedInteger, COut: UnsignedInteger>(
    c_in: LweCiphertext<CIn>,
    modulus_in: CIn,
    c_out: &mut LweCiphertext<COut>,
) {
    let modulus_in_dec = modulus_in.to_decimal();
    let modulus_out_dec = BigDecimal::from_u128(1_u128 << (COut::BITS - 1))
        .unwrap()
        .double();

    let switch = |v: CIn| {
        COut::from_decimal(
            &(v.to_decimal() * &modulus_out_dec / &modulus_in_dec)
                .with_scale_round(0, RoundingMode::HalfUp),
        )
    };

    c_out
        .a_mut()
        .iter_mut()
        .zip(c_in.a())
        .for_each(|(des, &inp)| *des = switch(inp));
    *c_out.b_mut() = switch(c_in.b());
}

/// Implementation of modulus switching.
///
/// This function performs on a [`LweCiphertext<C>`] with modulus `modulus_in`,
/// puts the result [`LweCiphertext<C>`] with desired modulus `modulus_out`
/// back to `c`.
pub fn lwe_modulus_switch_assign<C: UnsignedInteger>(
    c: &mut LweCiphertext<C>,
    modulus_in: ModulusValue<C>,
    modulus_out: C,
) {
    match modulus_in {
        ModulusValue::Native => lwe_modulus_switch_assign_native(c, modulus_out),
        ModulusValue::PowerOf2(modulus_in)
        | ModulusValue::Prime(modulus_in)
        | ModulusValue::Others(modulus_in) => {
            lwe_modulus_switch_assign_normal(c, modulus_in, modulus_out)
        }
    }
}

/// Implementation of modulus switching.
///
/// This function performs on a [`LweCiphertext<C>`] with modulus `modulus_in`,
/// puts the result [`LweCiphertext<C>`] with desired modulus `modulus_out`
/// back to `c`.
pub fn lwe_modulus_switch_assign_normal<C: UnsignedInteger>(
    c: &mut LweCiphertext<C>,
    modulus_in: C,
    modulus_out: C,
) {
    let modulus_in_dec = modulus_in.to_decimal();
    let modulus_out_dec = modulus_out.to_decimal();

    let reduce = |v: C| {
        if v < modulus_out {
            v
        } else {
            v - modulus_out
        }
    };

    let switch = |v: C| {
        reduce(C::from_decimal(
            &(v.to_decimal() * &modulus_out_dec / &modulus_in_dec)
                .with_scale_round(0, RoundingMode::HalfUp),
        ))
    };

    c.a_mut().iter_mut().for_each(|v| *v = switch(*v));
    *c.b_mut() = switch(c.b());
}

/// Implementation of modulus switching.
///
/// This function performs on a [`LweCiphertext<C>`] with modulus `modulus_in`,
/// puts the result [`LweCiphertext<C>`] with desired modulus `modulus_out`
/// back to `c`.
pub fn lwe_modulus_switch_assign_native<C: UnsignedInteger>(
    c: &mut LweCiphertext<C>,
    modulus_out: C,
) {
    let modulus_in_dec = BigDecimal::from_u128(1_u128 << (C::BITS - 1))
        .unwrap()
        .double();
    let modulus_out_dec = modulus_out.to_decimal();

    let reduce = |v: C| {
        if v < modulus_out {
            v
        } else {
            v - modulus_out
        }
    };

    let switch = |v: C| {
        reduce(C::from_decimal(
            &(v.to_decimal() * &modulus_out_dec / &modulus_in_dec)
                .with_scale_round(0, RoundingMode::HalfUp),
        ))
    };

    c.a_mut().iter_mut().for_each(|v| *v = switch(*v));
    *c.b_mut() = switch(c.b());
}
