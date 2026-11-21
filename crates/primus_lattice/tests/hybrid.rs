//! Independent integer oracle for native plus Hybrid products and both reductions.
use dashu_int::IBig;
use primus_lattice::hybrid::{
    HybridModDown, NativeHybridAuxiliary, NativeHybridError, NativeHybridParameters,
    NativeHybridProduct,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64DcrtTable};
use primus_rns::RNSBase;
use primus_shape::PolyLength;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

const N: usize = 32;
fn modulo(x: &IBig, m: &IBig) -> IBig {
    let r = x % m;
    if r < IBig::ZERO { r + m } else { r }
}
fn center(x: &IBig, m: &IBig) -> IBig {
    let r = modulo(x, m);
    if r > m / 2u64 { r - m } else { r }
}
fn product(values: &[u64]) -> IBig {
    values.iter().fold(IBig::ONE, |p, &v| p * v)
}
// One extended GCD suffices for both the prime limbs and the full auxiliary product.
fn inverse(a: IBig, m: &IBig) -> IBig {
    let (mut r0, mut r1, mut s0, mut s1) = (m.clone(), a, IBig::ZERO, IBig::ONE);
    while r1 != IBig::ZERO {
        let q = &r0 / &r1;
        let remainder = r0 - &q * &r1;
        let coefficient = s0 - q * &s1;
        (r0, r1) = (r1, remainder);
        (s0, s1) = (s1, coefficient);
    }
    assert_eq!(r0, IBig::ONE);
    modulo(&s0, m)
}
fn convolution(a: &[IBig], b: &[IBig]) -> Vec<IBig> {
    let mut out = vec![IBig::ZERO; N];
    for (i, a) in a.iter().enumerate() {
        for (j, b) in b.iter().enumerate() {
            if i + j < N {
                out[i + j] += a * b;
            } else {
                out[i + j - N] -= a * b;
            }
        }
    }
    out
}
fn residues(values: &[IBig], moduli: &[u64]) -> Vec<u64> {
    moduli
        .iter()
        .flat_map(|&q| {
            values
                .iter()
                .map(move |x| u64::try_from(modulo(x, &IBig::from(q))).unwrap())
        })
        .collect()
}
fn make_base(values: &[u64]) -> RNSBase<u64, BarrettModulus<u64>> {
    RNSBase::new(
        &values
            .iter()
            .copied()
            .map(BarrettModulus::new)
            .collect::<Vec<_>>(),
    )
    .unwrap()
}
fn input_coefficients(q: &IBig) -> Vec<IBig> {
    let mut x = vec![
        q / 2u64,
        -(q / 2u64),
        IBig::ONE,
        -IBig::ONE,
        q / 3u64,
        -(q / 3u64),
        IBig::ZERO,
        IBig::from(7),
    ];
    x.resize(N, IBig::ZERO);
    x
}

// Keep the full CRT lift. Reducing by the partition product would change its P limbs.
fn partition_digit(input: &[IBig], moduli: &[u64]) -> (Vec<IBig>, IBig) {
    let partition_product = product(moduli);
    let weights: Vec<_> = moduli
        .iter()
        .map(|&qi| {
            let modulus = IBig::from(qi);
            let hat = &partition_product / qi;
            let hat_inverse = inverse(&hat % &modulus, &modulus);
            (modulus, hat, hat_inverse)
        })
        .collect();
    let support = weights
        .iter()
        .fold(IBig::ZERO, |sum, (qi, hat, _)| sum + hat * (qi - 1u64));
    let digit: Vec<_> = input
        .iter()
        .map(|x| {
            weights
                .iter()
                .fold(IBig::ZERO, |sum, (qi, hat, hat_inverse)| {
                    sum + modulo(&(x * hat_inverse), qi) * hat
                })
        })
        .collect();
    assert!(digit.iter().all(|x| x >= &IBig::ZERO && x <= &support));
    (digit, support)
}

fn projection_weight(moduli: &[u64], q: &IBig) -> IBig {
    let weight = moduli.iter().fold(IBig::ZERO, |sum, &qi| {
        let qi = IBig::from(qi);
        let hat = q / &qi;
        let inv = inverse(&hat % &qi, &qi);
        sum + hat * inv
    });
    // This idempotent is one in the current partition and zero in every other Q limb.
    modulo(&weight, q)
}

fn key_column(
    index: usize,
    qp: &IBig,
    weight: &IBig,
    secret: &[IBig],
    message: &[IBig],
    t: u64,
) -> [Vec<IBig>; 2] {
    let half = qp / 2u64;
    let mask: Vec<_> = (0..N)
        .map(|i| {
            if i % 2 == 0 {
                &half - IBig::from(i * 13 + index)
            } else {
                -&half + IBig::from(i * 7 + index)
            }
        })
        .collect();
    // Phase = weight * message + t * error. Alternate mask signs near QP/2.
    let body = message
        .iter()
        .zip(convolution(&mask, secret))
        .enumerate()
        .map(|(i, (m, masked))| {
            let error = IBig::from((i + index) as i32 % 5 - 2) * t;
            weight * m - masked + error
        })
        .collect();
    [body, mask]
}

fn add_convolution(accumulator: &mut [IBig], lhs: &[IBig], rhs: &[IBig]) {
    for (out, term) in accumulator.iter_mut().zip(convolution(lhs, rhs)) {
        *out += term;
    }
}

fn mod_down(tensor: [Vec<IBig>; 2], p: &IBig, t: u64) -> [Vec<IBig>; 2] {
    let t_inverse = inverse(IBig::from(t), p);
    tensor.map(|component| {
        component
            .iter()
            .map(|x| {
                // Subtract the centered multiple of t that makes x divisible by P.
                let correction = center(&(x * &t_inverse), p) * t;
                let numerator = x - correction;
                assert_eq!(&numerator % p, IBig::ZERO);
                numerator / p
            })
            .collect()
    })
}

fn assert_phase_bound(
    reduced: &[Vec<IBig>; 2],
    signal: &[IBig],
    secret: &[IBig],
    digit_support: &IBig,
    p: &IBig,
    t: u64,
) {
    let [body, mask] = reduced;
    let mut phase = body.clone();
    add_convolution(&mut phase, mask, secret);

    // In units of t, row errors contribute at most 2 N digit_support / P.
    // The body and both nonzero secret coefficients each contribute at most 1/2 from centering.
    let numerator = 4u64 * IBig::from(N) * digit_support + p * 3u64;
    let denominator = 2u64 * p;
    let bound = (&numerator + &denominator - 1u64) / &denominator;
    for (phase, signal) in phase.iter().zip(signal) {
        let error = phase - signal;
        assert_eq!(&error % t, 0u64);
        let noise = error / t;
        assert!(noise >= -&bound && noise <= bound);
    }
}

struct IntegerHybridProduct {
    columns: Vec<[Vec<IBig>; 2]>,
    reduced: [Vec<IBig>; 2],
}

fn integer_product<'a>(
    input: &[IBig],
    partitions: impl Iterator<Item = &'a [u64]>,
    q: &IBig,
    p: &IBig,
    secret: &[IBig],
    message: &[IBig],
    t: u64,
) -> IntegerHybridProduct {
    let qp = q * p;
    let mut columns = Vec::new();
    let mut tensor = [vec![IBig::ZERO; N], vec![IBig::ZERO; N]];
    let mut signal = vec![IBig::ZERO; N];
    let mut digit_support = IBig::ZERO;
    for (index, moduli) in partitions.enumerate() {
        let (digit, support) = partition_digit(input, moduli);
        digit_support += support;
        let idempotent = projection_weight(moduli, q);
        let column = key_column(index, &qp, &(p * &idempotent), secret, message, t);
        for (accumulator, component) in tensor.iter_mut().zip(&column) {
            add_convolution(accumulator, &digit, component);
        }
        let weighted_message: Vec<_> = message.iter().map(|m| m * &idempotent).collect();
        add_convolution(&mut signal, &digit, &weighted_message);
        columns.push(column);
    }
    let reduced = mod_down(tensor, p, t);
    assert_phase_bound(&reduced, &signal, secret, &digit_support, p, t);
    IntegerHybridProduct { columns, reduced }
}

#[test]
fn native_hybrid_matches_integer_tensors_and_phase_bounds_at_all_prefixes() {
    let poly_length = PolyLength::new(N);
    let mut secret = vec![IBig::ZERO; N];
    secret[0] = IBig::ONE;
    secret[2] = -IBig::ONE;
    let mut message = vec![IBig::ZERO; N];
    message[0] = IBig::from(2);
    message[1] = -IBig::ONE;
    message[3] = IBig::ONE;
    for (q_values, p_values, dnum) in [
        (vec![193, 257, 449], vec![577], 3),
        (
            vec![1_152_921_422_732_787_713, 1_152_921_409_847_689_217],
            vec![1_152_921_504_606_584_833],
            2,
        ),
        (
            vec![1_152_921_422_732_787_713, 1_125_874_136_383_489],
            vec![1_125_899_904_679_937],
            2,
        ),
        (
            vec![
                1_125_899_906_248_961,
                1_125_899_906_051_329,
                1_125_899_904_322_049,
            ],
            vec![1_099_510_054_913],
            3,
        ),
        (
            vec![
                1_125_899_906_248_961,
                1_125_899_906_051_329,
                1_125_899_904_322_049,
                1_125_899_906_826_241,
            ],
            vec![1_152_921_504_606_830_593, 1_152_921_504_606_748_673],
            2,
        ),
    ] {
        let auxiliary = Arc::new(NativeHybridAuxiliary::try_new(poly_length, &p_values).unwrap());
        let p = product(&p_values);
        let full_base = make_base(&q_values);
        let table = U64DcrtTable::new(poly_length, full_base.moduli()).unwrap();
        for count in 1..=q_values.len() {
            let q_moduli = &q_values[..count];
            let q = product(q_moduli);
            let parameters = Arc::new(
                NativeHybridParameters::try_with_auxiliary(
                    &make_base(q_moduli),
                    q_values.len(),
                    Arc::clone(&auxiliary),
                    dnum,
                )
                .unwrap(),
            );
            assert!(Arc::ptr_eq(parameters.auxiliary(), &auxiliary));
            let qp_moduli: Vec<_> = q_moduli.iter().chain(&p_values).copied().collect();
            let input = input_coefficients(&q);
            let mut input_ntt = residues(&input, q_moduli);
            for (table, limb) in table
                .iter()
                .zip(input_ntt.as_chunks_mut::<N>().0.iter_mut())
            {
                table.transform_slice(limb);
            }
            for mode in [
                HybridModDown::Centered,
                HybridModDown::PlaintextPreserving(17),
                HybridModDown::PlaintextPreserving(65537),
                HybridModDown::PlaintextPreserving(q_values[0]),
                HybridModDown::PlaintextPreserving(u64::MAX),
            ] {
                let t = match mode {
                    HybridModDown::Centered => 1,
                    HybridModDown::PlaintextPreserving(t) => t,
                };
                let partitions = parameters
                    .hybrid_rns()
                    .partitions()
                    .map(|partition| &q_moduli[partition.q_range()]);
                let reference = integer_product(&input, partitions, &q, &p, &secret, &message, t);

                let mut columns = Vec::with_capacity(parameters.key_len());
                for component in reference.columns.iter().flatten() {
                    let mut residues = residues(component, &qp_moduli);
                    parameters.transform_qp_assign(&table, &mut residues);
                    columns.extend(residues);
                }
                let mut evaluator =
                    NativeHybridProduct::try_new(&parameters, &table, mode).unwrap();
                let mut output = vec![0; 2 * parameters.q_poly_len()];
                evaluator.product_to(&input_ntt, &columns, &mut output);
                for (actual, expected) in output
                    .chunks_exact_mut(parameters.q_poly_len())
                    .zip(&reference.reduced)
                {
                    for (table, limb) in table.iter().zip(actual.as_chunks_mut::<N>().0.iter_mut())
                    {
                        table.inverse_transform_slice(limb);
                    }
                    assert_eq!(actual, residues(expected, q_moduli));
                }
            }
        }
    }
}

#[test]
fn native_hybrid_parameter_binding_and_complete_shapes_reject_before_writes() {
    let base = make_base(&[193, 257]);
    let table = U64DcrtTable::new(PolyLength::new(N), base.moduli()).unwrap();
    let params =
        Arc::new(NativeHybridParameters::try_new(PolyLength::new(N), &base, 2, &[449], 2).unwrap());
    assert!(NativeHybridParameters::try_new(PolyLength::new(N), &base, 2, &[193], 2).is_err());
    assert!(matches!(
        NativeHybridAuxiliary::try_new(PolyLength::new(N), &[49_601]),
        Err(NativeHybridError::PrimeBasis(
            primus_ntt::U64NttPrimeBasisError::NotPrime { modulus: 49_601 }
        ))
    ));
    assert!(NativeHybridParameters::try_new(PolyLength::new(N), &base, 2, &[449], 0).is_err());
    assert!(NativeHybridParameters::try_new(PolyLength::new(N), &base, 1, &[449], 1).is_err());
    assert!(
        params
            .validate_mod_down(HybridModDown::PlaintextPreserving(0))
            .is_err()
    );
    assert!(
        params
            .validate_mod_down(HybridModDown::PlaintextPreserving(449))
            .is_err()
    );
    for index in [params.partition_count(), usize::MAX / 2 + 1, usize::MAX] {
        assert!(catch_unwind(AssertUnwindSafe(|| params.key_weights(index))).is_err());
    }
    let wrong =
        U64DcrtTable::new(PolyLength::new(N), &[257, 193].map(BarrettModulus::new)).unwrap();
    assert!(NativeHybridProduct::try_new(&params, &wrong, HybridModDown::Centered).is_err());
    let mut product =
        NativeHybridProduct::try_new(&params, &table, HybridModDown::Centered).unwrap();
    let input = vec![0; params.q_poly_len()];
    let key = vec![0; params.key_len()];
    for (a, k, o) in [
        (input.len() - 1, key.len(), 2 * input.len()),
        (input.len() + 1, key.len(), 2 * input.len()),
        (input.len(), key.len() - 1, 2 * input.len()),
        (input.len(), key.len() + 1, 2 * input.len()),
        (input.len(), key.len(), 2 * input.len() + 1),
    ] {
        let mut output = vec![77; o];
        assert!(
            catch_unwind(AssertUnwindSafe(|| product.product_to(
                &vec![0; a],
                &vec![0; k],
                &mut output
            )))
            .is_err()
        );
        assert!(output.iter().all(|&x| x == 77));
    }
}

#[test]
fn bounded_secret_extension_uses_highest_q_and_rejects_ambiguous_or_incoherent_lifts() {
    let full_q = [449, 577];
    let base = make_base(&full_q);
    let table = U64DcrtTable::new(PolyLength::new(N), base.moduli()).unwrap();
    let source = |values: &[IBig]| {
        let mut words = residues(values, &full_q);
        table.transform_slice(&mut words);
        words
    };
    let mut large = vec![IBig::ZERO; N];
    large[..7].clone_from_slice(&[
        IBig::from(250),
        IBig::from(-250),
        IBig::ONE,
        -IBig::ONE,
        IBig::ZERO,
        IBig::from(300),
        IBig::from(-300),
    ]);
    let input = source(&large);
    // Source and target chains may have different high-level inventories;
    // only the actual active Q prefix must coincide for integer extension.
    let different_full =
        NativeHybridParameters::try_new(PolyLength::new(N), &make_base(&[449]), 3, &[193], 3)
            .unwrap();
    assert!(
        different_full
            .extend_bounded_secret_to_qp(&input, &base, &table, 300)
            .is_ok()
    );
    for count in [1, 2] {
        let params = NativeHybridParameters::try_new(
            PolyLength::new(N),
            &make_base(&full_q[..count]),
            2,
            &[193],
            2,
        )
        .unwrap();
        let output = params
            .extend_bounded_secret_to_qp(&input, &base, &table, 300)
            .unwrap();
        let mut expected = residues(
            &large,
            &full_q[..count]
                .iter()
                .chain(&[193])
                .copied()
                .collect::<Vec<_>>(),
        );
        params.transform_qp_assign(&table, &mut expected);
        assert_eq!(output.as_slice(), expected);
        let mut outside = large.clone();
        outside[0] = IBig::from(301);
        assert!(matches!(
            params.extend_bounded_secret_to_qp(&source(&outside), &base, &table, 300),
            Err(NativeHybridError::SecretSupport { bound: 300 })
        ));
    }
    let params = NativeHybridParameters::try_new(PolyLength::new(N), &base, 2, &[193], 2).unwrap();
    let mut small = vec![IBig::ZERO; N];
    small[0] = IBig::from(3);
    small[2] = IBig::from(-7);
    let mut coherent = source(&small);
    assert!(
        params
            .extend_bounded_secret_to_qp(&coherent, &base, &table, 7)
            .is_ok()
    );
    coherent[N] = (coherent[N] + 1) % full_q[1];
    assert!(matches!(
        params.extend_bounded_secret_to_qp(&coherent, &base, &table, 7),
        Err(NativeHybridError::SecretRepresentation)
    ));
    coherent[0] = full_q[0];
    assert!(matches!(
        params.extend_bounded_secret_to_qp(&coherent, &base, &table, 7),
        Err(NativeHybridError::SecretRepresentation)
    ));
    assert!(
        params
            .extend_bounded_secret_to_qp(&input[..input.len() - 1], &base, &table, 300)
            .is_err()
    );
    let single = make_base(&[449]);
    let single_table = U64DcrtTable::new(PolyLength::new(N), single.moduli()).unwrap();
    let single_params =
        NativeHybridParameters::try_new(PolyLength::new(N), &single, 1, &[193], 1).unwrap();
    let ambiguous = &input[..N];
    assert!(matches!(
        single_params.extend_bounded_secret_to_qp(ambiguous, &single, &single_table, 300),
        Err(NativeHybridError::AmbiguousSecret { bound: 300 })
    ));
    // Q<=2B need not make every actual coefficient ambiguous. x=1 has only
    // one lift in [-300,300] under Q=449; a blanket modulus test would reject it.
    let mut unique = vec![IBig::ZERO; N];
    unique[0] = IBig::ONE;
    let mut unique_words = residues(&unique, &[449]);
    single_table.transform_slice(&mut unique_words);
    assert!(
        single_params
            .extend_bounded_secret_to_qp(&unique_words, &single, &single_table, 300)
            .is_ok()
    );
    assert!(matches!(
        single_params.extend_bounded_secret_to_qp(&unique_words, &single, &single_table, 449),
        Err(NativeHybridError::AmbiguousSecret { bound: 449 })
    ));
    // Full-width magnitudes do not pass through i64 or a one-prime centered lift.
    let wide_q = [1_152_921_504_606_830_593, 1_152_921_504_606_748_673];
    let wide = make_base(&wide_q);
    let wide_table = U64DcrtTable::new(PolyLength::new(N), wide.moduli()).unwrap();
    let wide_params =
        NativeHybridParameters::try_new(PolyLength::new(N), &make_base(&wide_q[..1]), 2, &[193], 2)
            .unwrap();
    let mut maximal = vec![IBig::ZERO; N];
    maximal[0] = IBig::from(u64::MAX);
    maximal[1] = -IBig::from(u64::MAX);
    let mut maximal_ntt = residues(&maximal, &wide_q);
    wide_table.transform_slice(&mut maximal_ntt);
    let output = wide_params
        .extend_bounded_secret_to_qp(&maximal_ntt, &wide, &wide_table, u64::MAX)
        .unwrap();
    let mut expected = residues(&maximal, &[wide_q[0], 193]);
    wide_params.transform_qp_assign(&wide_table, &mut expected);
    assert_eq!(output.as_slice(), expected);
}
