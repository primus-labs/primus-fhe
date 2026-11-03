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
                let input = BgvCiphertext::new(encode(&[c0, c1.clone()], count));
                assert_eq!(phase(input.as_ref(), &source_big, count), message);
                let expected =
                    switched_phase(&message, &c1, &source_big, &row_errors, count, config, p);
                let mut output = context.new_ciphertext(level);
                let mut switch = BgvKeySwitcher::try_new(&context, level, &key).unwrap();
                switch.switch_to(&input, &mut output);
                assert_eq!(phase(output.as_ref(), &target_big, count), expected);
                for (actual, message) in expected.iter().zip(&message) {
                    assert_eq!(modulo(actual, &IBig::from(p)), *message);
                }
                assert_eq!(
                    target_client.decrypt(&output, level).as_ref(),
                    message
                        .iter()
                        .map(|value| u64::try_from(value).unwrap())
                        .collect::<Vec<_>>()
                );
                // A zero switched component has all-zero digits even for a
                // truncated gadget, so no key error or residual is injected.
                let constant =
                    BgvCiphertext::new(encode(&[message.clone(), vec![IBig::ZERO; N]], count));
                switch.switch_to(&constant, &mut output);
                assert_eq!(output, constant);
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
        let quadratic = BgvQuadraticCiphertext::new(encode(&components, count));
        assert_eq!(phase(quadratic.as_ref(), &secret_big, count), before);
        let mut linear = context.new_ciphertext(level);
        BgvRelinearizer::try_new(&context, level, &key)
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
            let source = BgvCiphertext::new(encode(&components[..2], count));
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
            BgvAutomorphism::try_new(&context, level, &key)
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
        assert!(BgvKeySwitcher::try_new(wrong, 0, &switch_key).is_err());
        assert!(BgvRelinearizer::try_new(wrong, 0, &relin_key).is_err());
        assert!(BgvAutomorphism::try_new(wrong, 0, &auto_key).is_err());
    }
    for wrong_level in [1, 2, 3, usize::MAX] {
        assert!(BgvKeySwitcher::try_new(&context, wrong_level, &switch_key).is_err());
        assert!(BgvRelinearizer::try_new(&context, wrong_level, &relin_key).is_err());
        assert!(BgvAutomorphism::try_new(&context, wrong_level, &auto_key).is_err());
    }
    for exponent in [0, 2, 2 * N, usize::MAX] {
        assert!(
            client
                .automorphism_key(0, exponent, config, &mut rng)
                .is_err()
        );
    }
    let mut switch = BgvKeySwitcher::try_new(&context, 0, &switch_key).unwrap();
    let mut relin = BgvRelinearizer::try_new(&context, 0, &relin_key).unwrap();
    let mut auto = BgvAutomorphism::try_new(&context, 0, &auto_key).unwrap();
    let length = context.rns_poly_len(0);
    for bad_length in [0, 2 * length - 1, 2 * length + 1, 3 * length] {
        let input = BgvCiphertext::new(vec![0; bad_length]);
        let mut output = BgvCiphertext::new(vec![0xfeed; 2 * length]);
        assert!(catch_unwind(AssertUnwindSafe(|| switch.switch_to(&input, &mut output))).is_err());
        assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
        assert!(catch_unwind(AssertUnwindSafe(|| auto.apply_to(&input, &mut output))).is_err());
        assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
    }
    for bad_length in [0, 3 * length - 1, 3 * length + 1, 2 * length] {
        let input = BgvQuadraticCiphertext::new(vec![0; bad_length]);
        let mut output = BgvCiphertext::new(vec![0xfeed; 2 * length]);
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
        let mut output = BgvCiphertext::new(vec![0xfeed; bad_length]);
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
