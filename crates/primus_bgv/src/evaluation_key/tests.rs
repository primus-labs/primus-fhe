//! Independent DFT/CRT phases and integer signed-digit residuals for BGV keys.

use crate::{
    BgvAutomorphism, BgvCiphertext, BgvClient, BgvContext, BgvKeySwitcher, BgvParameters,
    BgvQuadraticCiphertext, BgvRelinearizer,
};
use dashu_int::IBig;
use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 32;
const P: u64 = 193;
const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];

#[test]
fn p_scaling_overwrites_dirty_columns_and_matches_wide_percent_reference() {
    // The small first prime checks that p is reduced even in an auxiliary
    // modulus below p. This is a private arithmetic test, not a scheme preset.
    let base = super::KeyBase::new(&[97, 65537, Q[0]].map(BarrettModulus::new)).unwrap();
    for components in [1, 3] {
        let mut input = vec![0; components * N * base.moduli_count()];
        for (index, limb) in input.as_chunks_mut::<N>().0.iter_mut().enumerate() {
            let q = base.moduli_values()[index % base.moduli_count()];
            let boundary = [0, 1, q - 1, q, q + 1, 2 * q, 4 * q - 1, u64::MAX];
            for (i, value) in limb.iter_mut().enumerate() {
                *value = boundary[(i + index) % boundary.len()];
            }
        }
        let mut output = vec![u64::MAX; input.len()];
        for p in [0, 1, 193, 65537, u64::MAX] {
            let expected = input
                .as_chunks::<N>()
                .0
                .iter()
                .enumerate()
                .flat_map(|(index, limb)| {
                    let q = base.moduli_values()[index % base.moduli_count()];
                    limb.iter().map(move |&value| multiply(value, p, q))
                })
                .collect::<Vec<_>>();
            super::scale_with_p_to(p, N, &base, &input, &mut output);
            assert_eq!(output, expected);
            let mut assigned = input.clone();
            super::scale_with_p(p, N, &base, &mut assigned);
            assert_eq!(assigned, expected);
            output.fill(17);
        }
    }
}

fn make_context(p: u64, moduli: &[u64], n: usize) -> BgvContext {
    BgvContext::try_with_levels(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(n),
            BarrettModulus::new(p),
            &moduli
                .iter()
                .copied()
                .map(BarrettModulus::new)
                .collect::<Vec<_>>(),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
        moduli.len(),
    )
    .unwrap()
}

fn client<'a>(context: &'a BgvContext, secret: &[i64]) -> BgvClient<'a> {
    let coefficient_key = GlweSecretKey::new(
        secret.to_vec(),
        context.parameters().size().glwe_size(),
        SecretKeyDistr::SparseTernary,
    );
    BgvClient::try_from_secret_key(
        context,
        DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, context.table()),
    )
    .unwrap()
}

fn multiply(a: u64, b: u64, q: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(q)) as u64
}

fn power(mut value: u64, mut exponent: u64, q: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, value, q);
        }
        value = multiply(value, value, q);
        exponent >>= 1;
    }
    result
}

fn modulo(value: &IBig, modulus: &IBig) -> IBig {
    let remainder = value % modulus;
    if remainder < IBig::ZERO {
        remainder + modulus
    } else {
        remainder
    }
}

fn centered(value: &IBig, modulus: &IBig) -> IBig {
    let residue = modulo(value, modulus);
    if residue > modulus / 2 {
        residue - modulus
    } else {
        residue
    }
}

fn total_modulus(count: usize) -> IBig {
    Q[..count]
        .iter()
        .fold(IBig::ONE, |value, &q| value * IBig::from(q))
}

fn points(q: u64) -> Vec<u64> {
    let witness = (2..)
        .map(|candidate| power(candidate, (q - 1) / (2 * N) as u64, q))
        .find(|&root| power(root, N as u64, q) == q - 1)
        .unwrap();
    let root = (0..N)
        .map(|i| power(witness, (2 * i + 1) as u64, q))
        .min()
        .unwrap();
    (0usize..N)
        .map(|i| {
            let reversed = i.reverse_bits() >> (usize::BITS - N.ilog2());
            power(root, (2 * reversed + 1) as u64, q)
        })
        .collect()
}

fn dft(coefficients: &[IBig], q: u64) -> Vec<u64> {
    let coefficients: Vec<_> = coefficients
        .iter()
        .map(|value| u64::try_from(modulo(value, &IBig::from(q))).unwrap())
        .collect();
    points(q)
        .iter()
        .map(|&point| {
            coefficients.iter().rev().fold(0, |value, &coefficient| {
                (multiply(value, point, q) + coefficient) % q
            })
        })
        .collect()
}

fn inverse(values: &[u64], q: u64) -> Vec<u64> {
    let points = points(q);
    (0..N)
        .map(|degree| {
            let sum = points
                .iter()
                .zip(values)
                .fold(0, |value, (&point, &coefficient)| {
                    (value + multiply(coefficient, power(point, q - 1 - degree as u64, q), q)) % q
                });
            multiply(sum, power(N as u64, q - 2, q), q)
        })
        .collect()
}

fn product(lhs: &[IBig], rhs: &[IBig]) -> Vec<IBig> {
    let mut output = vec![IBig::ZERO; N];
    for (i, left) in lhs.iter().enumerate() {
        for (j, right) in rhs.iter().enumerate() {
            if i + j < N {
                output[i + j] += left * right;
            } else {
                output[i + j - N] -= left * right;
            }
        }
    }
    output
}

fn add(lhs: &[IBig], rhs: &[IBig]) -> Vec<IBig> {
    lhs.iter()
        .zip(rhs)
        .map(|(left, right)| left + right)
        .collect()
}

fn automorphism(input: &[IBig], exponent: usize) -> Vec<IBig> {
    let mut output = vec![IBig::ZERO; N];
    for (degree, value) in input.iter().enumerate() {
        let target = degree * exponent % (2 * N);
        if target < N {
            output[target] += value;
        } else {
            output[target - N] -= value;
        }
    }
    output
}

fn encode(components: &[Vec<IBig>], count: usize) -> Vec<u64> {
    components
        .iter()
        .flat_map(|component| Q[..count].iter().flat_map(|&q| dft(component, q)))
        .collect()
}

fn phase(ciphertext: &[u64], secret: &[IBig], count: usize) -> Vec<IBig> {
    let length = N * count;
    assert_eq!(ciphertext.len() % length, 0);
    let residues: Vec<_> = Q[..count]
        .iter()
        .enumerate()
        .map(|(limb, &q)| {
            let secret = dft(secret, q);
            let values: Vec<_> = (0..N)
                .map(|i| {
                    let mut value = 0;
                    let mut secret_power = 1;
                    for component in ciphertext.chunks_exact(length) {
                        value = (value + multiply(component[limb * N + i], secret_power, q)) % q;
                        secret_power = multiply(secret_power, secret[i], q);
                    }
                    value
                })
                .collect();
            inverse(&values, q)
        })
        .collect();
    let total = total_modulus(count);
    (0..N)
        .map(|degree| {
            let mut value = IBig::ZERO;
            let mut product = IBig::ONE;
            for (limb, &q) in Q[..count].iter().enumerate() {
                let modulus = IBig::from(q);
                let remainder = u64::try_from(modulo(&value, &modulus)).unwrap();
                let difference = (residues[limb][degree] + q - remainder) % q;
                let product_mod_q = u64::try_from(modulo(&product, &modulus)).unwrap();
                let inverse = power(product_mod_q, q - 2, q);
                value += &product * IBig::from(multiply(difference, inverse, q));
                product *= modulus;
            }
            centered(&value, &total)
        })
        .collect()
}

fn config(count: usize, truncated: bool) -> DecompositionConfig {
    let width = format!("{:b}", total_modulus(count)).len();
    assert_eq!(width % 10, 0);
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(10),
        level_count: truncated.then(|| DecompositionLevelCount::new(width / 10 - 1)),
    }
}

// An integer interval/quotient formulation independent of the backend's bit
// masks, adjusted-input representation, carries and RNS decomposition.
fn decomposition(value: &IBig, count: usize, config: DecompositionConfig) -> (Vec<IBig>, IBig) {
    let modulus = total_modulus(count);
    let width = format!("{modulus:b}").len();
    let log = config.log_basis.get() as usize;
    let levels = config.level_count.map_or(width / log, |value| value.get());
    let scale = IBig::ONE << (width - levels * log);
    let radix = IBig::ONE << log;
    let sum = ((IBig::ONE << (levels * log)) - IBig::ONE) / (&radix - IBig::ONE);
    let maximum = (&radix / 2 - IBig::ONE) * sum;
    let threshold = &maximum * &scale
        + if scale == IBig::ONE {
            IBig::ONE
        } else {
            &scale / 2
        };
    let signed = if value >= &threshold {
        value - &modulus
    } else {
        value.clone()
    };
    // floor((signed + scale/2)/scale), including negative values and ties.
    let rounded = &signed + &scale / 2;
    let mut quotient = (&rounded - modulo(&rounded, &scale)) / &scale;
    let mut digits = Vec::with_capacity(levels);
    let mut reconstructed = IBig::ZERO;
    let mut weight = scale.clone();
    for _ in 0..levels {
        let digit = modulo(&(&quotient + &radix / 2), &radix) - &radix / 2;
        quotient = (&quotient - &digit) / &radix;
        reconstructed += &digit * &weight;
        digits.push(digit);
        weight *= &radix;
    }
    assert_eq!(quotient, IBig::ZERO);
    let residual = centered(&(value - reconstructed), &modulus);
    let bound = &scale / 2;
    assert!((-&bound..=bound).contains(&residual));
    (digits, residual)
}

fn errors<'a>(
    columns: impl IntoIterator<Item = BgvCiphertext<&'a [u64]>>,
    source_secret: &[IBig],
    target_secret: &[IBig],
    count: usize,
    config: DecompositionConfig,
    p: u64,
) -> Vec<Vec<IBig>> {
    let modulus = total_modulus(count);
    let width = format!("{modulus:b}").len();
    let log = config.log_basis.get() as usize;
    let levels = config.level_count.map_or(width / log, |value| value.get());
    let drop_bits = width - levels * log;
    let rows: Vec<_> = columns.into_iter().collect();
    assert_eq!(rows.len(), levels);
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            let weight = IBig::ONE << (drop_bits + index * log);
            phase(row.as_ref(), target_secret, count)
                .iter()
                .zip(source_secret)
                .map(|(actual, source)| {
                    let error = centered(&(actual - IBig::from(p) * &weight * source), &modulus);
                    assert_eq!(&error % IBig::from(p), IBig::ZERO);
                    let error = error / IBig::from(p);
                    assert!((-IBig::ONE..=IBig::ONE).contains(&error));
                    error
                })
                .collect()
        })
        .collect()
}

fn switched_phase(
    before: &[IBig],
    component: &[IBig],
    source_secret: &[IBig],
    errors: &[Vec<IBig>],
    count: usize,
    config: DecompositionConfig,
    p: u64,
) -> Vec<IBig> {
    let modulus = total_modulus(count);
    // Q=1 mod p gives this exact inverse; no production modular inverse used.
    let inverse_p = (IBig::ONE + IBig::from(p - 1) * &modulus) / IBig::from(p);
    assert_eq!(modulo(&(&inverse_p * IBig::from(p)), &modulus), IBig::ONE);
    let decomposed: Vec<_> = component
        .iter()
        .map(|value| decomposition(&modulo(&(value * &inverse_p), &modulus), count, config))
        .collect();
    let residual: Vec<_> = decomposed
        .iter()
        .map(|(_, residual)| residual.clone())
        .collect();
    let residual_phase = product(&residual, source_secret);
    let mut total_error: Vec<_> = residual_phase.iter().map(|value| -value).collect();
    for (level, errors) in errors.iter().enumerate() {
        let digits: Vec<_> = decomposed
            .iter()
            .map(|(digits, _)| digits[level].clone())
            .collect();
        total_error = add(&total_error, &product(&digits, errors));
    }
    before
        .iter()
        .zip(total_error)
        .map(|(phase, error)| centered(&(phase + IBig::from(p) * error), &modulus))
        .collect()
}

#[test]
fn exact_and_truncated_switch_keys_preserve_p_and_match_integer_residuals() {
    let source: Vec<i64> = (0..N).map(|i| [-1, 1, 0, 1][i % 4]).collect();
    let target: Vec<i64> = (0..N).map(|i| [1, 0, -1][i % 3]).collect();
    let source_big: Vec<_> = source.iter().copied().map(IBig::from).collect();
    let target_big: Vec<_> = target.iter().copied().map(IBig::from).collect();
    for p in [2, P] {
        let context = make_context(p, &Q, N);
        let source_client = client(&context, &source);
        let mut target_client = client(&context, &target);
        for level in 0..context.level_count() {
            let count = Q.len() - level;
            let modulus = total_modulus(count);
            if level == 0 {
                assert!(modulus > IBig::from(u128::MAX));
            }
            for truncated in [false, true] {
                let config = config(count, truncated);
                let mut rng = StdRng::seed_from_u64(0x10b6_5000 + level as u64);
                let key = target_client
                    .key_switching_key(&source_client, level, config, &mut rng)
                    .unwrap();
                assert_eq!(key.key.level, level);
                let row_errors = errors(
                    key.key.ciphertexts(),
                    &source_big,
                    &target_big,
                    count,
                    config,
                    p,
                );
                let step = if truncated {
                    IBig::ONE << 10
                } else {
                    IBig::ONE
                };
                let width = format!("{modulus:b}").len();
                let levels = width / 10 - usize::from(truncated);
                let digit_weights = ((IBig::ONE << (10 * levels)) - IBig::ONE) / IBig::from(1023);
                let split = IBig::from(511) * digit_weights * &step
                    + if truncated { &step / 2 } else { IBig::ONE };
                let boundaries = [
                    IBig::ZERO,
                    IBig::ONE,
                    &step / 2,
                    &step / 2 + IBig::ONE,
                    IBig::from(511),
                    IBig::from(512),
                    IBig::from(513),
                    IBig::from(1023) * &step + &step / 2,
                    &split - IBig::ONE,
                    split.clone(),
                    &split + IBig::ONE,
                    &modulus / 2 - IBig::ONE,
                    &modulus / 2,
                    &modulus / 2 + IBig::ONE,
                    &modulus - IBig::ONE,
                ];
                let c1: Vec<_> = (0..N)
                    .map(|i| {
                        modulo(
                            &(IBig::from(p) * &boundaries[i % boundaries.len()]),
                            &modulus,
                        )
                    })
                    .collect();
                let message: Vec<_> = (0..N).map(|i| IBig::from((i as u64 * 7) % p)).collect();
                let product = product(&c1, &source_big);
                let c0: Vec<_> = message
                    .iter()
                    .zip(&product)
                    .map(|(m, value)| m - value)
                    .collect();
                let input = BgvCiphertext::from_raw(encode(&[c0, c1.clone()], count));
                assert_eq!(phase(input.as_ref(), &source_big, count), message);
                let expected =
                    switched_phase(&message, &c1, &source_big, &row_errors, count, config, p);
                let mut output = context.new_ciphertext(level);
                let mut switch = BgvKeySwitcher::try_new(&context, &key).unwrap();
                switch.switch_to(&input, &mut output);
                assert_eq!(phase(output.as_ref(), &target_big, count), expected);
                for (actual, message) in expected.iter().zip(&message) {
                    assert_eq!(modulo(actual, &IBig::from(p)), *message);
                }
                assert_eq!(
                    target_client.decrypt_at_level(&output, level).as_ref(),
                    message
                        .iter()
                        .map(|value| u64::try_from(value).unwrap())
                        .collect::<Vec<_>>()
                );
                // A zero switched component has all-zero digits even for a
                // truncated gadget, so no key error or residual is injected.
                let constant =
                    BgvCiphertext::from_raw(encode(&[message.clone(), vec![IBig::ZERO; N]], count));
                switch.switch_to(&constant, &mut output);
                assert_eq!(output.as_ref(), constant.as_ref());
            }
        }
    }
}

#[test]
fn relinearization_and_automorphisms_keep_native_plus_phase_at_every_level() {
    let context = make_context(P, &Q, N);
    let secret: Vec<i64> = (0..N).map(|i| [-1, 0, 1, 1][i % 4]).collect();
    let secret_big: Vec<_> = secret.iter().copied().map(IBig::from).collect();
    let secret_squared = product(&secret_big, &secret_big);
    let client = client(&context, &secret);
    for level in 0..context.level_count() {
        let count = Q.len() - level;
        let config = config(count, true);
        let mut rng = StdRng::seed_from_u64(0x10b6_a070 + level as u64);
        let key = client.relinearization_key(level, config, &mut rng).unwrap();
        let row_errors = errors(
            key.key.ciphertexts(),
            &secret_squared,
            &secret_big,
            count,
            config,
            P,
        );
        let components: Vec<Vec<_>> = (0..3)
            .map(|component| {
                (0..N)
                    .map(|i| IBig::from(((i * 7 + component * 3) % 11) as i64 - 5))
                    .collect()
            })
            .collect();
        let before = add(
            &add(&components[0], &product(&components[1], &secret_big)),
            &product(&components[2], &secret_squared),
        );
        let expected = switched_phase(
            &before,
            &components[2],
            &secret_squared,
            &row_errors,
            count,
            config,
            P,
        );
        let quadratic = BgvQuadraticCiphertext::from_raw(encode(&components, count));
        assert_eq!(phase(quadratic.as_ref(), &secret_big, count), before);
        let mut linear = context.new_ciphertext(level);
        BgvRelinearizer::try_new(&context, &key)
            .unwrap()
            .relinearize_to(&quadratic, &mut linear);
        assert_eq!(phase(linear.as_ref(), &secret_big, count), expected);
        for exponent in [5, 2 * N - 1] {
            let key = client
                .automorphism_key(level, exponent, config, &mut rng)
                .unwrap();
            let transformed_secret = automorphism(&secret_big, exponent);
            let row_errors = errors(
                key.key.ciphertexts(),
                &transformed_secret,
                &secret_big,
                count,
                config,
                P,
            );
            let source = BgvCiphertext::from_raw(encode(&components[..2], count));
            let before = automorphism(
                &add(&components[0], &product(&components[1], &secret_big)),
                exponent,
            );
            let transformed_component = automorphism(&components[1], exponent);
            let expected = switched_phase(
                &before,
                &transformed_component,
                &transformed_secret,
                &row_errors,
                count,
                config,
                P,
            );
            BgvAutomorphism::try_new(&context, &key)
                .unwrap()
                .apply_to(&source, &mut linear);
            assert_eq!(phase(linear.as_ref(), &secret_big, count), expected);
        }
    }
}

#[test]
fn evaluation_keys_reject_numeric_mismatches_and_bad_storage_before_writes() {
    let context = make_context(P, &Q, N);
    let secret: Vec<i64> = (0..N).map(|i| [-1, 0, 1][i % 3]).collect();
    let client = client(&context, &secret);
    let mut rng = StdRng::seed_from_u64(0x10b6_bad0);
    let config = config(3, false);
    let switch_key = client
        .key_switching_key(&client, 0, config, &mut rng)
        .unwrap();
    let relin_key = client.relinearization_key(0, config, &mut rng).unwrap();
    let auto_key = client.automorphism_key(0, 5, config, &mut rng).unwrap();
    let wrong_contexts = [
        make_context(2, &Q, N),
        make_context(P, &[Q[2], Q[1], Q[0]], N),
        make_context(P, &Q, 64),
    ];
    for wrong in &wrong_contexts {
        assert!(BgvKeySwitcher::try_new(wrong, &switch_key).is_err());
        assert!(BgvRelinearizer::try_new(wrong, &relin_key).is_err());
        assert!(BgvAutomorphism::try_new(wrong, &auto_key).is_err());
    }
    let unprepared = BgvContext::try_new(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(N),
            BarrettModulus::new(P),
            &Q.map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
    )
    .unwrap();
    for level in [1, 2] {
        let switch_key = client
            .key_switching_key(&client, level, config, &mut rng)
            .unwrap();
        let relin_key = client.relinearization_key(level, config, &mut rng).unwrap();
        let auto_key = client.automorphism_key(level, 5, config, &mut rng).unwrap();
        assert!(matches!(BgvKeySwitcher::try_new(&unprepared, &switch_key),
            Err(crate::BgvEvaluationKeyError::Level { requested, available: 1 }) if requested == level));
        assert!(matches!(BgvRelinearizer::try_new(&unprepared, &relin_key),
            Err(crate::BgvEvaluationKeyError::Level { requested, available: 1 }) if requested == level));
        assert!(matches!(BgvAutomorphism::try_new(&unprepared, &auto_key),
            Err(crate::BgvEvaluationKeyError::Level { requested, available: 1 }) if requested == level));
    }
    for exponent in [0, 2, 2 * N, usize::MAX] {
        assert!(
            client
                .automorphism_key(0, exponent, config, &mut rng)
                .is_err()
        );
    }
    let mut switch = BgvKeySwitcher::try_new(&context, &switch_key).unwrap();
    let mut relin = BgvRelinearizer::try_new(&context, &relin_key).unwrap();
    let mut auto = BgvAutomorphism::try_new(&context, &auto_key).unwrap();
    let length = context.rns_poly_len(0);
    for bad_length in [0, 2 * length - 1, 2 * length + 1, 3 * length] {
        let input = BgvCiphertext::from_raw(vec![0; bad_length]);
        let mut output = BgvCiphertext::from_raw(vec![0xfeed; 2 * length]);
        assert!(catch_unwind(AssertUnwindSafe(|| switch.switch_to(&input, &mut output))).is_err());
        assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
        assert!(catch_unwind(AssertUnwindSafe(|| auto.apply_to(&input, &mut output))).is_err());
        assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
    }
    for bad_length in [0, 3 * length - 1, 3 * length + 1, 2 * length] {
        let input = BgvQuadraticCiphertext::from_raw(vec![0; bad_length]);
        let mut output = BgvCiphertext::from_raw(vec![0xfeed; 2 * length]);
        assert!(
            catch_unwind(AssertUnwindSafe(
                || relin.relinearize_to(&input, &mut output)
            ))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
    }
    let input = context.new_ciphertext(0);
    let quadratic = context.new_quadratic_ciphertext(0);
    for bad_length in [0, 2 * length - 1, 2 * length + 1] {
        let mut output = BgvCiphertext::from_raw(vec![0xfeed; bad_length]);
        assert!(catch_unwind(AssertUnwindSafe(|| switch.switch_to(&input, &mut output))).is_err());
        assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
        assert!(catch_unwind(AssertUnwindSafe(|| auto.apply_to(&input, &mut output))).is_err());
        assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
        assert!(
            catch_unwind(AssertUnwindSafe(
                || relin.relinearize_to(&quadratic, &mut output)
            ))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
    }
}

fn modulus_product(moduli: &[u64]) -> IBig {
    moduli.iter().fold(IBig::ONE, |a, &q| a * q)
}
fn crt_columns(residues: &[Vec<u64>], moduli: &[u64]) -> Vec<IBig> {
    let total = modulus_product(moduli);
    (0..N)
        .map(|i| {
            let mut result = IBig::ZERO;
            for (&q, limb) in moduli.iter().zip(residues) {
                let hat = &total / q;
                let inverse = power(&hat % q, q - 2, q);
                result += &hat * inverse * limb[i];
            }
            centered(&result, &total)
        })
        .collect()
}
fn hybrid_components(ciphertext: &[u64], moduli: &[u64]) -> Vec<Vec<IBig>> {
    ciphertext
        .chunks_exact(N * moduli.len())
        .map(|component| {
            let residues: Vec<_> = component
                .as_chunks::<N>()
                .0
                .iter()
                .zip(moduli)
                .map(|(values, &q)| inverse(values, q))
                .collect();
            crt_columns(&residues, moduli)
        })
        .collect()
}
fn polynomial_phase(components: &[Vec<IBig>], secret: &[IBig], modulus: &IBig) -> Vec<IBig> {
    add(&components[0], &product(&components[1], secret))
        .iter()
        .map(|x| centered(x, modulus))
        .collect()
}
fn projector(count: usize, range: std::ops::Range<usize>) -> IBig {
    let q = total_modulus(count);
    let mut result = IBig::ZERO;
    for &qi in &Q[range] {
        let hat = &q / qi;
        result += &hat * power(&hat % qi, qi - 2, qi);
    }
    modulo(&result, &q)
}
fn hybrid_column_errors(
    key: &super::NativeEvaluationKey,
    context: &BgvContext,
    source: &[IBig],
    target: &[IBig],
    error_bound: u64,
) -> Vec<Vec<IBig>> {
    let count = Q.len() - key.level;
    let super::KeyDecomposition::Hybrid(parameters) = &key.decomposition else {
        panic!("hybrid oracle requires Hybrid");
    };
    let moduli = key.base(context).moduli_values();
    let total = modulus_product(moduli);
    let p_aux = modulus_product(parameters.hybrid_rns().p_base().moduli_values());
    let alpha = parameters.hybrid_rns().partition_moduli_count();
    key.columns
        .chunks_exact(2 * N * moduli.len())
        .enumerate()
        .map(|(digit, column)| {
            let scalar = &p_aux * projector(count, digit * alpha..((digit + 1) * alpha).min(count));
            let phase = polynomial_phase(&hybrid_components(column, moduli), target, &total);
            phase
                .iter()
                .zip(source)
                .map(|(value, s)| {
                    let e = centered(&(value - &scalar * s), &total);
                    assert_eq!(&e % P, 0, "QP key phase error must be p-divisible");
                    let e = e / P;
                    assert!(e >= -IBig::from(error_bound) && e <= IBig::from(error_bound));
                    e
                })
                .collect()
        })
        .collect()
}

#[test]
fn hybrid_qp_role_columns_and_plaintext_preserving_component_quotients_match_integer_oracles() {
    const AUX: [u64; 2] = [1152921504606830593, 1152921504606748673];
    let context = BgvContext::try_with_levels(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(N),
            BarrettModulus::new(P),
            &Q.map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 21 },
        )
        .unwrap(),
        3,
    )
    .unwrap();
    let source: Vec<i64> = (0..N).map(|i| [-1, 0, 1, 1][i % 4]).collect();
    let target: Vec<i64> = (0..N).map(|i| [0, 1, -1][i % 3]).collect();
    let a = client(&context, &source);
    let b = client(&context, &target);
    let source: Vec<_> = source.into_iter().map(IBig::from).collect();
    let target: Vec<_> = target.into_iter().map(IBig::from).collect();
    let mut rng = StdRng::seed_from_u64(0x24b6_9001);
    for level in 0..3 {
        let count = Q.len() - level;
        let q = total_modulus(count);
        let alpha = 2;
        for auxiliary in [&AUX[..1], &AUX[..2]] {
            let parameters = context.hybrid_key_parameters(level, 2, auxiliary).unwrap();
            let switch = b
                .key_switching_key(&a, level, parameters.clone(), &mut rng)
                .unwrap();
            let errors = hybrid_column_errors(&switch.key, &context, &source, &target, 21);
            let relin = a
                .relinearization_key(level, parameters.clone(), &mut rng)
                .unwrap();
            hybrid_column_errors(
                &relin.key,
                &context,
                &product(&source, &source),
                &source,
                21,
            );
            let auto = a
                .automorphism_key(level, 5, parameters.clone(), &mut rng)
                .unwrap();
            hybrid_column_errors(&auto.key, &context, &automorphism(&source, 5), &source, 21);
            let p_aux = modulus_product(auxiliary);
            let qp = &q * &p_aux;
            let x: Vec<_> = (0..N).map(|i| &q / 2u64 - IBig::from(i * 13)).collect();
            let message: Vec<_> = (0..N).map(|i| IBig::from((i % 5) as i64 - 2)).collect();
            let mask_phase = product(&x, &source);
            let body: Vec<_> = message
                .iter()
                .zip(mask_phase)
                .map(|(m, a)| centered(&(m - a), &q))
                .collect();
            let input = BgvCiphertext::from_raw(encode(&[body.clone(), x.clone()], count));
            let moduli = switch.key.base(&context).moduli_values();
            let mut accumulator = vec![vec![IBig::ZERO; N]; 2];
            let mut epsilon = vec![IBig::ZERO; N];
            for (digit, column) in switch
                .key
                .columns
                .chunks_exact(2 * N * moduli.len())
                .enumerate()
            {
                let range = digit * alpha..((digit + 1) * alpha).min(count);
                let part = modulus_product(&Q[range.clone()]);
                let values: Vec<_> = x
                    .iter()
                    .map(|x| {
                        let mut d = IBig::ZERO;
                        for &qi in &Q[range.clone()] {
                            let hat = &part / qi;
                            let u = modulo(&(x * power(&hat % qi, qi - 2, qi)), &IBig::from(qi));
                            d += hat * u;
                        }
                        d
                    })
                    .collect();
                let components = hybrid_components(column, moduli);
                for component in 0..2 {
                    accumulator[component] = add(
                        &accumulator[component],
                        &product(&values, &components[component]),
                    );
                }
                epsilon = add(&epsilon, &product(&values, &errors[digit]));
            }
            // Independent p^-1 modulo P from a small-p inverse, rather than
            // the production per-limb inverse factors or ModDown converter.
            let inverse_p = (IBig::ONE + &p_aux * (P - power(&p_aux % P, P - 2, P))) / P;
            assert_eq!(modulo(&(&inverse_p * P), &p_aux), IBig::ONE);
            let remainders: Vec<Vec<_>> = accumulator
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|z| centered(&(z * &inverse_p), &p_aux))
                        .collect()
                })
                .collect();
            let mut expected: Vec<Vec<_>> = accumulator
                .iter()
                .zip(&remainders)
                .map(|(row, r)| {
                    row.iter()
                        .zip(r)
                        .map(|(z, r)| {
                            let numerator = z - r * P;
                            assert_eq!(&numerator % &p_aux, IBig::ZERO);
                            centered(&(numerator / &p_aux), &q)
                        })
                        .collect()
                })
                .collect();
            expected[0] = expected[0]
                .iter()
                .zip(&body)
                .map(|(a, b)| centered(&(a + b), &q))
                .collect();
            let mut output = context.new_ciphertext(level);
            BgvKeySwitcher::try_new(&context, &switch)
                .unwrap()
                .switch_to(&input, &mut output);
            assert_eq!(hybrid_components(output.as_ref(), &Q[..count]), expected);
            let r_phase = add(&remainders[0], &product(&remainders[1], &target));
            let residual: Vec<_> = epsilon
                .iter()
                .zip(r_phase)
                .map(|(e, r)| {
                    let numerator = e - r;
                    assert_eq!(&numerator % &p_aux, IBig::ZERO);
                    numerator / &p_aux
                })
                .collect();
            let expected_phase: Vec<_> = message
                .iter()
                .zip(&residual)
                .map(|(m, e)| centered(&(m + e * P), &q))
                .collect();
            assert_eq!(polynomial_phase(&expected, &target, &q), expected_phase);
            for (m, actual) in message.iter().zip(expected_phase) {
                let e = centered(&(actual - m), &q);
                assert_eq!(e % P, 0);
            }
            assert_eq!(modulus_product(moduli), qp);
        }
    }
}

#[test]
fn hybrid_collective_columns_include_all_s_squared_cross_terms_in_qp() {
    use crate::{
        BgvCollectiveAutomorphismKey, BgvCollectiveRelinearization, BgvCollectiveSwitchingKey,
    };
    let context = BgvContext::try_with_levels(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(N),
            BarrettModulus::new(P),
            &Q.map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 21 },
        )
        .unwrap(),
        3,
    )
    .unwrap();
    let shares: Vec<Vec<i64>> = (0..3)
        .map(|party| {
            (0..N)
                .map(|i| match (i + party * 3) % 5 {
                    0 => -1,
                    1 | 2 => 1,
                    _ => 0,
                })
                .collect()
        })
        .collect();
    let clients: Vec<_> = shares.iter().map(|s| client(&context, s)).collect();
    let source: Vec<_> = (0..N)
        .map(|i| IBig::from(shares.iter().map(|s| s[i]).sum::<i64>()))
        .collect();
    let mut rng = StdRng::seed_from_u64(0x24b6_9002);
    for level in 0..3 {
        let parameters = context
            .hybrid_key_parameters(level, 2, &[1152921504606830593])
            .unwrap();
        let plan =
            BgvCollectiveSwitchingKey::try_new(&context, level, parameters.clone(), &mut rng)
                .unwrap();
        let mut sum = plan.aggregate();
        for c in &clients {
            sum.add(
                &plan
                    .contribute(c.secret_key(), c.secret_key(), &mut rng)
                    .unwrap(),
            )
            .unwrap();
        }
        let key = plan.finalize(sum).unwrap();
        hybrid_column_errors(&key.key, &context, &source, &source, 63);
        let plan =
            BgvCollectiveAutomorphismKey::try_new(&context, level, 5, parameters.clone(), &mut rng)
                .unwrap();
        let mut sum = plan.aggregate();
        for c in &clients {
            sum.add(&plan.contribute(c.secret_key(), &mut rng).unwrap())
                .unwrap();
        }
        let key = plan.finalize(sum).unwrap();
        hybrid_column_errors(&key.key, &context, &automorphism(&source, 5), &source, 63);
        let plan =
            BgvCollectiveRelinearization::try_new(&context, level, parameters, &mut rng).unwrap();
        let mut first = plan.round_one_aggregate();
        let mut states = Vec::new();
        for c in &clients {
            let (m, s) = plan.start(c.secret_key(), &mut rng).unwrap();
            first.add(&m).unwrap();
            states.push(s);
        }
        let frozen = plan.freeze_round_one(first).unwrap();
        let mut second = plan.round_two_aggregate(&frozen).unwrap();
        for state in states {
            second
                .add(&state.round2(&frozen, &mut rng).unwrap())
                .unwrap();
        }
        let key = plan.finalize(&frozen, second).unwrap();
        hybrid_column_errors(
            &key.key,
            &context,
            &product(&source, &source),
            &source,
            21 * 3 * (2 * 3 * N as u64 + 1),
        );
    }
}
