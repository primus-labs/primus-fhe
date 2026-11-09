//! Independent DFT/CRT phases and integer signed-digit residuals for BFV keys.

use super::NativeEvaluationKey;
use crate::{
    BfvAutomorphism, BfvCiphertext, BfvClient, BfvContext, BfvKeySwitcher, BfvParameters,
    BfvQuadraticCiphertext, BfvRelinearizer,
};
use dashu_int::IBig;
use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 32;
const P: u64 = 257;
const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];

fn make_context(p: u64, moduli: &[u64], n: usize) -> BfvContext {
    BfvContext::try_with_levels(
        BfvParameters::try_with_error_distribution(
            PolyLength::new(n),
            BarrettModulus::new(p),
            BarrettModulus::new((1 << 61) - 1),
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

fn client<'a>(context: &'a BfvContext, secret: &[i64]) -> BfvClient<'a> {
    let coefficient_key = GlweSecretKey::new(
        secret.to_vec(),
        context.parameters().size().glwe_size(),
        SecretKeyDistr::SparseTernary,
    );
    BfvClient::try_from_secret_key(
        context,
        DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, context.table()),
    )
    .unwrap()
}

fn multiply(a: u64, b: u64, q: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(q)) as u64
}

pub(super) fn power(mut value: u64, mut exponent: u64, q: u64) -> u64 {
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

pub(super) fn inverse(values: &[u64], q: u64) -> Vec<u64> {
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
    columns: impl IntoIterator<Item = BfvCiphertext<&'a [u64]>>,
    source_secret: &[IBig],
    target_secret: &[IBig],
    count: usize,
    config: DecompositionConfig,
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
                    let error = centered(&(actual - &weight * source), &modulus);
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
) -> Vec<IBig> {
    let modulus = total_modulus(count);
    let decomposed: Vec<_> = component
        .iter()
        .map(|value| decomposition(&modulo(value, &modulus), count, config))
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
        .map(|(phase, error)| centered(&(phase + error), &modulus))
        .collect()
}

#[test]
fn exact_and_truncated_switch_keys_match_integer_residuals() {
    let source: Vec<i64> = (0..N).map(|i| [-1, 1, 0, 1][i % 4]).collect();
    let target: Vec<i64> = (0..N).map(|i| [1, 0, -1][i % 3]).collect();
    let source_big: Vec<_> = source.iter().copied().map(IBig::from).collect();
    let target_big: Vec<_> = target.iter().copied().map(IBig::from).collect();
    for p in [2, P] {
        let context = make_context(p, &Q, N);
        let source_client = client(&context, &source);
        let target_client = client(&context, &target);
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
                let row_errors = errors(columns(&key.key), &source_big, &target_big, count, config);
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
                    .map(|i| modulo(&boundaries[i % boundaries.len()], &modulus))
                    .collect();
                let message: Vec<_> = (0..N).map(|i| IBig::from((i as u64 * 7) % p)).collect();
                let product = product(&c1, &source_big);
                let c0: Vec<_> = message
                    .iter()
                    .zip(&product)
                    .map(|(m, value)| m - value)
                    .collect();
                let input = BfvCiphertext::new(encode(&[c0, c1.clone()], count));
                assert_eq!(phase(input.as_ref(), &source_big, count), message);
                let expected =
                    switched_phase(&message, &c1, &source_big, &row_errors, count, config);
                let mut output = context.new_ciphertext(level);
                let mut switch = BfvKeySwitcher::try_new(&context, &key).unwrap();
                switch.switch_to(&input, &mut output);
                assert_eq!(phase(output.as_ref(), &target_big, count), expected);
                // A zero switched component has all-zero digits even for a
                // truncated gadget, so no key error or residual is injected.
                let constant =
                    BfvCiphertext::new(encode(&[message.clone(), vec![IBig::ZERO; N]], count));
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
            columns(&key.key),
            &secret_squared,
            &secret_big,
            count,
            config,
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
        );
        let quadratic = BfvQuadraticCiphertext::new(encode(&components, count));
        assert_eq!(phase(quadratic.as_ref(), &secret_big, count), before);
        let mut linear = context.new_ciphertext(level);
        BfvRelinearizer::try_new(&context, &key)
            .unwrap()
            .relinearize_to(&quadratic, &mut linear);
        assert_eq!(phase(linear.as_ref(), &secret_big, count), expected);
        for exponent in [5, 2 * N - 1] {
            let key = client
                .automorphism_key(level, exponent, config, &mut rng)
                .unwrap();
            let transformed_secret = automorphism(&secret_big, exponent);
            let row_errors = errors(
                columns(&key.key),
                &transformed_secret,
                &secret_big,
                count,
                config,
            );
            let source = BfvCiphertext::new(encode(&components[..2], count));
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
            );
            BfvAutomorphism::try_new(&context, &key)
                .unwrap()
                .apply_to(&source, &mut linear);
            assert_eq!(phase(linear.as_ref(), &secret_big, count), expected);
        }
    }
}

fn columns(key: &NativeEvaluationKey) -> impl ExactSizeIterator<Item = BfvCiphertext<&[u64]>> {
    key.columns
        .chunks_exact(2 * key.key_poly_len())
        .map(BfvCiphertext::new)
}

#[test]
fn hybrid_columns_and_all_native_role_phases_match_independent_dft_and_integer_bounds() {
    let source: Vec<i64> = (0..N).map(|i| [-1, 1, 0, 1][i % 4]).collect();
    let target: Vec<i64> = (0..N).map(|i| [1, 0, -1][i % 3]).collect();
    let source_big: Vec<_> = source.iter().copied().map(IBig::from).collect();
    let target_big: Vec<_> = target.iter().copied().map(IBig::from).collect();
    let context = make_context(P, &Q, N);
    let source_client = client(&context, &source);
    let target_client = client(&context, &target);
    for level in 0..context.level_count() {
        let count = Q.len() - level;
        let modulus = total_modulus(count);
        let components: Vec<Vec<_>> = (0..3)
            .map(|component| {
                (0..N)
                    .map(|i| {
                        centered(
                            &(&modulus / 2u64 - IBig::from(i * 19 + component * 37)),
                            &modulus,
                        )
                    })
                    .collect()
            })
            .collect();
        for auxiliary in [
            &[1_099_511_626_049u64][..],
            &[1_152_921_504_606_830_593, 1_152_921_504_606_748_673][..],
        ] {
            let parameters = context.hybrid_key_parameters(level, 2, auxiliary).unwrap();
            let mut rng = StdRng::seed_from_u64(0x24bf0a11 + level as u64);
            let switch = target_client
                .key_switching_key(&source_client, level, parameters.clone(), &mut rng)
                .unwrap();
            let relin = source_client
                .relinearization_key(level, parameters.clone(), &mut rng)
                .unwrap();
            let auto = source_client
                .automorphism_key(level, 5, parameters.clone(), &mut rng)
                .unwrap();
            let source_square = product(&source_big, &source_big);
            let transformed = automorphism(&source_big, 5);
            let p = auxiliary.iter().fold(IBig::ONE, |x, &p| x * p);
            // Independently derive each column's QP phase and its shared integer
            // error. The weight is P only in the contiguous alpha=2 partition.
            for (key, h, secret) in [
                (&switch.key, &source_big, &target_big),
                (&relin.key, &source_square, &source_big),
                (&auto.key, &transformed, &source_big),
            ] {
                let moduli = key.key_moduli_values(&context);
                for (column, values) in key.columns.chunks_exact(2 * key.key_poly_len()).enumerate()
                {
                    let mut first_errors = None;
                    for (index, &q) in moduli.iter().enumerate() {
                        let length = key.key_poly_len();
                        let secret = dft(secret, q);
                        let row: Vec<_> = (0..N)
                            .map(|i| {
                                (values[index * N + i]
                                    + multiply(values[length + index * N + i], secret[i], q))
                                    % q
                            })
                            .collect();
                        let phase = inverse(&row, q);
                        let weight = if index < count && index / 2 == column {
                            &p % q
                        } else {
                            0
                        };
                        let errors: Vec<_> = phase
                            .iter()
                            .zip(h)
                            .map(|(&x, h)| centered(&(IBig::from(x) - weight * h), &IBig::from(q)))
                            .collect();
                        assert!(errors.iter().all(|e| e >= &-IBig::ONE && e <= &IBig::ONE));
                        if let Some(first) = &first_errors {
                            assert_eq!(&errors, first, "QP columns use one coherent integer error");
                        } else {
                            first_errors = Some(errors);
                        }
                    }
                }
            }
            let digit_sum = Q[..count].chunks(2).fold(IBig::ZERO, |sum, part| {
                sum + part.len() * part.iter().fold(IBig::ONE, |x, &q| x * q)
            });
            let check = |actual: Vec<IBig>, before: Vec<IBig>, secret: &[IBig]| {
                let h = secret.iter().fold(IBig::ZERO, |sum, s| {
                    sum + if s < &IBig::ZERO { -s } else { s.clone() }
                });
                let bound = (IBig::from(N) * &digit_sum + &p - 1u64) / &p + (&h + 2u64) / 2u64;
                assert!(bound < &modulus / 2u64);
                for (actual, before) in actual.iter().zip(before) {
                    let error = centered(&(actual - before), &modulus);
                    assert!(
                        error >= -&bound && error <= bound,
                        "native Hybrid key/decomposition/ModDown residual bound"
                    );
                }
            };
            let input = BfvCiphertext::new(encode(&components[..2], count));
            let mut output = context.new_ciphertext(level);
            BfvKeySwitcher::try_new(&context, &switch)
                .unwrap()
                .switch_to(&input, &mut output);
            check(
                phase(output.as_ref(), &target_big, count),
                phase(input.as_ref(), &source_big, count),
                &target_big,
            );
            let quadratic = BfvQuadraticCiphertext::new(encode(&components, count));
            BfvRelinearizer::try_new(&context, &relin)
                .unwrap()
                .relinearize_to(&quadratic, &mut output);
            check(
                phase(output.as_ref(), &source_big, count),
                phase(quadratic.as_ref(), &source_big, count),
                &source_big,
            );
            BfvAutomorphism::try_new(&context, &auto)
                .unwrap()
                .apply_to(&input, &mut output);
            check(
                phase(output.as_ref(), &source_big, count),
                automorphism(&phase(input.as_ref(), &source_big, count), 5),
                &source_big,
            );
        }
    }
}

#[test]
fn hybrid_secret_extension_uses_full_owner_q_when_the_first_prime_is_ambiguous() {
    use super::{BfvEvaluationKeyError, NativeHybridError};
    use rand::Rng;
    let law = SecretKeyDistr::gaussian(60_000_000_000_000.0);
    let make = |moduli: &[u64]| {
        BfvContext::try_with_levels(
            BfvParameters::try_with_error_distribution(
                PolyLength::new(N),
                BarrettModulus::new(2),
                BarrettModulus::new((1 << 61) - 1),
                &moduli
                    .iter()
                    .copied()
                    .map(BarrettModulus::new)
                    .collect::<Vec<_>>(),
                law,
                ErrorDistribution::CenteredBinomial { eta: 1 },
            )
            .unwrap(),
            moduli.len(),
        )
        .unwrap()
    };
    let source_context = make(&Q);
    let target_context = make(&[Q[0], Q[1], 1_125_899_906_826_241]);
    let magnitude = (Q[0] / 2 + 7) as i64;
    let mut coefficients = vec![0i64; N];
    coefficients[0] = magnitude;
    coefficients[3] = -magnitude;
    let expected: Vec<_> = coefficients.iter().copied().map(IBig::from).collect();
    let secret = GlweSecretKey::new(
        coefficients,
        source_context.parameters().size().glwe_size(),
        law,
    );
    let source = BfvClient::try_from_secret_key(
        &source_context,
        DcrtGlweSecretKey::from_coeff_secret_key(&secret, source_context.table()),
    )
    .unwrap();
    assert!(
        source_context
            .parameters()
            .encryption_parameters()
            .secret_key_sampler()
            .maximum_magnitude()
            > Q[0] / 2
    );
    for level in 0..3 {
        let target_context = if level == 0 {
            &source_context
        } else {
            &target_context
        };
        let params = target_context
            .hybrid_key_parameters(level, 2, &[1_099_511_626_049])
            .unwrap();
        let key = NativeEvaluationKey::prepare_metadata(target_context, level, params).unwrap();
        let extended = key.secret(&source_context, source.secret_key()).unwrap();
        for (limb, &q) in extended
            .as_chunks::<N>()
            .0
            .iter()
            .zip(key.key_moduli_values(target_context))
        {
            assert_eq!(limb.as_slice(), dft(&expected, q));
        }
    }
    // This residue has both positive and negative candidates inside the
    // supported interval, so the original coefficient is ambiguous.
    let ambiguous = make(&Q[..1]);
    let small = GlweSecretKey::new(
        vec![magnitude; N],
        ambiguous.parameters().size().glwe_size(),
        law,
    );
    let client = BfvClient::try_from_secret_key(
        &ambiguous,
        DcrtGlweSecretKey::from_coeff_secret_key(&small, ambiguous.table()),
    )
    .unwrap();
    let params = ambiguous
        .hybrid_key_parameters(0, 1, &[1_099_511_626_049])
        .unwrap();
    let mut rng = StdRng::seed_from_u64(0x24bf5ec);
    let mut before = StdRng::seed_from_u64(0x24bf5ec);
    assert!(matches!(
        client.relinearization_key(0, params, &mut rng),
        Err(BfvEvaluationKeyError::Hybrid(
            NativeHybridError::AmbiguousSecret { .. }
        ))
    ));
    assert_eq!(rng.next_u64(), before.next_u64());
}
