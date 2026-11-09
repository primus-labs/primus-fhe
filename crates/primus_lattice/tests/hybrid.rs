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
fn inverse(a: u64, m: u64) -> u64 {
    let (mut r0, mut r1, mut s0, mut s1) = (m as i128, a as i128, 0i128, 1i128);
    while r1 != 0 {
        let q = r0 / r1;
        (r0, r1) = (r1, r0 - q * r1);
        (s0, s1) = (s1, s0 - q * s1);
    }
    assert_eq!(r0, 1);
    s0.rem_euclid(m as i128) as u64
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

#[test]
fn native_hybrid_matches_integer_tensors_and_phase_bounds_at_all_prefixes() {
    for (q_values, p_values, dnum) in [
        (vec![193, 257, 449], vec![577], 3),
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
        let auxiliary =
            Arc::new(NativeHybridAuxiliary::try_new(PolyLength::new(N), &p_values).unwrap());
        for count in 1..=q_values.len() {
            let q_moduli = &q_values[..count];
            let q = product(q_moduli);
            let p = product(&p_values);
            let qp = &q * &p;
            let table = U64DcrtTable::new(
                PolyLength::new(N),
                &q_values
                    .iter()
                    .copied()
                    .map(BarrettModulus::new)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
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
            let a = input_coefficients(&q);
            let mut a_ntt = residues(&a, q_moduli);
            for (table, limb) in table.iter().zip(a_ntt.as_chunks_mut::<N>().0.iter_mut()) {
                table.transform_slice(limb);
            }
            let mut secret = vec![IBig::ZERO; N];
            secret[0] = IBig::ONE;
            secret[2] = -IBig::ONE;
            let mut h = vec![IBig::ZERO; N];
            h[0] = IBig::from(2);
            h[1] = -IBig::ONE;
            h[3] = IBig::ONE;
            for mode in [
                HybridModDown::Centered,
                HybridModDown::PlaintextPreserving(17),
            ] {
                let t = match mode {
                    HybridModDown::Centered => 1,
                    HybridModDown::PlaintextPreserving(t) => t,
                };
                let mut columns = Vec::new();
                let mut z = [vec![IBig::ZERO; N], vec![IBig::ZERO; N]];
                let mut signal = vec![IBig::ZERO; N];
                let mut digit_support = IBig::ZERO;
                for (column_index, partition) in parameters.hybrid_rns().partitions().enumerate() {
                    let range = partition.q_range();
                    let part_moduli = &q_moduli[range.start..range.end];
                    let part = product(part_moduli);
                    let digit: Vec<_> = a
                        .iter()
                        .map(|x| {
                            part_moduli.iter().fold(IBig::ZERO, |sum, &qi| {
                                let hat = &part / qi;
                                let inv = inverse(&hat % qi, qi);
                                sum + modulo(&(x * inv), &IBig::from(qi)) * hat
                            })
                        })
                        .collect();
                    let max_digit = part_moduli
                        .iter()
                        .fold(IBig::ZERO, |sum, &qi| sum + (&part / qi) * (qi - 1));
                    assert!(digit.iter().all(|x| x >= &IBig::ZERO && x <= &max_digit));
                    digit_support += max_digit;
                    let idempotent = part_moduli.iter().fold(IBig::ZERO, |sum, &qi| {
                        let hat = &q / qi;
                        let inv = inverse(&hat % qi, qi);
                        sum + hat * inv
                    });
                    let idempotent = modulo(&idempotent, &q);
                    let weight = &p * &idempotent;
                    let mask: Vec<_> = (0..N)
                        .map(|i| {
                            if i % 2 == 0 {
                                &qp / 2u64 - IBig::from(i * 13 + column_index)
                            } else {
                                -(&qp / 2u64) + IBig::from(i * 7 + column_index)
                            }
                        })
                        .collect();
                    let error: Vec<_> = (0..N)
                        .map(|i| IBig::from((i + column_index) as i32 % 5 - 2) * t)
                        .collect();
                    let masked = convolution(&mask, &secret);
                    let body: Vec<_> = h
                        .iter()
                        .zip(&masked)
                        .zip(&error)
                        .map(|((h, m), e)| &weight * h - m + e)
                        .collect();
                    for (acc, input) in z.iter_mut().zip([&body, &mask]) {
                        for (out, term) in acc.iter_mut().zip(convolution(&digit, input)) {
                            *out += term;
                        }
                    }
                    let weighted_h: Vec<_> = h.iter().map(|h| h * &idempotent).collect();
                    for (out, term) in signal.iter_mut().zip(convolution(&digit, &weighted_h)) {
                        *out += term;
                    }
                    for component in [&body, &mask] {
                        let mut r = residues(component, &qp_moduli);
                        parameters.transform_qp_assign(&table, &mut r);
                        columns.extend(r);
                    }
                }
                let t_inverse_p = {
                    let mut r0 = p.clone();
                    let mut r1 = IBig::from(t);
                    let mut s0 = IBig::ZERO;
                    let mut s1 = IBig::ONE;
                    while r1 != IBig::ZERO {
                        let q = &r0 / &r1;
                        (r0, r1) = (r1.clone(), r0 - &q * &r1);
                        (s0, s1) = (s1.clone(), s0 - q * s1);
                    }
                    assert_eq!(r0, IBig::ONE);
                    modulo(&s0, &p)
                };
                let expected: Vec<Vec<_>> = z
                    .iter()
                    .map(|component| {
                        component
                            .iter()
                            .map(|x| {
                                let correction = center(&(x * &t_inverse_p), &p) * t;
                                let numerator = x - correction;
                                assert_eq!(&numerator % &p, IBig::ZERO);
                                numerator / &p
                            })
                            .collect()
                    })
                    .collect();
                let mut evaluator =
                    NativeHybridProduct::try_new(&parameters, &table, mode).unwrap();
                let mut output = vec![0; 2 * parameters.q_poly_len()];
                evaluator.product_to(&a_ntt, &columns, &mut output);
                for (actual, expected) in output
                    .chunks_exact_mut(parameters.q_poly_len())
                    .zip(&expected)
                {
                    for (table, limb) in table.iter().zip(actual.as_chunks_mut::<N>().0.iter_mut())
                    {
                        table.inverse_transform_slice(limb);
                    }
                    assert_eq!(actual, residues(expected, q_moduli));
                }
                let mut phase = expected[0].clone();
                for (out, term) in phase.iter_mut().zip(convolution(&expected[1], &secret)) {
                    *out += term;
                }
                let bound_numerator = 2u64 * IBig::from(N) * &digit_support * 2u64 + &p * 3u64;
                let denominator = 2u64 * &p;
                let bound = (&bound_numerator + &denominator - 1u64) / &denominator;
                for (phase, signal) in phase.iter().zip(&signal) {
                    let error = phase - signal;
                    assert_eq!(&error % t, 0u64);
                    let noise = error / t;
                    assert!(noise >= -&bound && noise <= bound);
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
