use primus_data::{Data, DataMut};
use primus_reduce::ReduceAdd;

use crate::correction;
use crate::quadratic::BgvQuadraticCiphertext;
use crate::{BgvCiphertext, BgvContext};

/// Writes `[l0*r0, l0*r1+l1*r0, l1*r1]` and the product correction factor.
///
/// The quadratic phase is the product of the input phases at the selected Q.
/// Apply a prepared relinearizer to obtain a degree-one ciphertext.
/// This operation needs no key or scratch.
///
/// # Correctness
/// Both inputs must use the selected ordered Q, the same actual secret and the
/// context's NTT convention. The complete product phase must fit the centered
/// recovery interval.
///
/// # Panics
/// Rejects an unprepared level, recorded context/level conflicts or incomplete
/// storage before writing output.
pub fn tensor_to<A, B, C>(
    context: &BgvContext,
    level: usize,
    lhs: &BgvCiphertext<A>,
    rhs: &BgvCiphertext<B>,
    output: &mut BgvQuadraticCiphertext<C>,
) where
    A: Data<Elem = u64>,
    B: Data<Elem = u64>,
    C: DataMut<Elem = u64>,
{
    output.check_binding(context, level);
    tensor_at_level_to(context, level, lhs, rhs, output);
}

/// Writes `[c0², 2*c0*c1, c1²]` using three polynomial products.
///
/// See [`tensor_to`] for the representation, recovery and panic contracts.
pub fn square_to<A, B>(
    context: &BgvContext,
    level: usize,
    input: &BgvCiphertext<A>,
    output: &mut BgvQuadraticCiphertext<B>,
) where
    A: Data<Elem = u64>,
    B: DataMut<Elem = u64>,
{
    output.check_binding(context, level);
    square_at_level_to(context, level, input, output);
}

// The caller has bound the output to this level or supplied its own scratch.
pub(super) fn tensor_at_level_to<A, B, C>(
    context: &BgvContext,
    level: usize,
    lhs: &BgvCiphertext<A>,
    rhs: &BgvCiphertext<B>,
    output: &mut BgvQuadraticCiphertext<C>,
) where
    A: Data<Elem = u64>,
    B: Data<Elem = u64>,
    C: DataMut<Elem = u64>,
{
    lhs.check_binding(context, level);
    rhs.check_binding(context, level);
    let length = context.rns_poly_len(level);
    let (l0, l1) = lhs.c0_c1(length);
    let (r0, r1) = rhs.c0_c1(length);
    let (mut o0, mut o1, mut o2) = output.c0_c1_c2_mut(length);
    let n = context.parameters().poly_length().get();
    let moduli = context.base_q(level).moduli();
    l0.mul_to(&r0, &mut o0, n, moduli);
    l0.mul_to(&r1, &mut o1, n, moduli);
    o1.add_mul_assign(&l1, &r0, n, moduli);
    l1.mul_to(&r1, &mut o2, n, moduli);
    output.set_correction_factor(correction::multiply(
        lhs.correction_factor(),
        rhs.correction_factor(),
        context.parameters().plain_modulus().value(),
    ));
}

pub(super) fn square_at_level_to<A, B>(
    context: &BgvContext,
    level: usize,
    input: &BgvCiphertext<A>,
    output: &mut BgvQuadraticCiphertext<B>,
) where
    A: Data<Elem = u64>,
    B: DataMut<Elem = u64>,
{
    input.check_binding(context, level);
    let length = context.rns_poly_len(level);
    let (c0, c1) = input.c0_c1(length);
    let (mut o0, mut o1, mut o2) = output.c0_c1_c2_mut(length);
    let n = context.parameters().poly_length().get();
    let moduli = context.base_q(level).moduli();
    c0.mul_to(&c0, &mut o0, n, moduli);
    c0.mul_to(&c1, &mut o1, n, moduli);
    for (limb, q) in o1.as_mut().chunks_exact_mut(n).zip(moduli) {
        for value in limb {
            *value = q.reduce_add(*value, *value);
        }
    }
    c1.mul_to(&c1, &mut o2, n, moduli);
    output.set_correction_factor(correction::multiply(
        input.correction_factor(),
        input.correction_factor(),
        context.parameters().plain_modulus().value(),
    ));
}
