//! Independent integer tensors, centered-wrap residuals and complete native phases.
use super::HpsMultiplier;
use crate::{BfvCiphertext, BfvClient, BfvContext, BfvParameters, BfvRelinearizer};
use dashu_int::IBig;
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 32;
const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];
const P: [u64; 3] = [
    1_152_921_504_606_830_593,
    1_152_921_504_606_748_673,
    1_152_921_504_606_683_137,
];

fn coefficients(input: [i32; 8]) -> Vec<IBig> {
    let mut result: Vec<_> = input.map(IBig::from).into();
    result.resize(N, IBig::ZERO);
    result
}
fn modulo(x: &IBig, q: &IBig) -> IBig {
    let r = x % q;
    if r < IBig::ZERO { r + q } else { r }
}
fn centered(x: &IBig, q: &IBig) -> IBig {
    let r = modulo(x, q);
    if r > q / 2u64 { r - q } else { r }
}
fn product_moduli(moduli: &[u64]) -> IBig {
    moduli.iter().fold(IBig::ONE, |a, &b| a * b)
}
fn nearest(x: &IBig, denominator: &IBig) -> IBig {
    if x < &IBig::ZERO {
        -((-x + denominator / 2u64) / denominator)
    } else {
        (x + denominator / 2u64) / denominator
    }
}
fn power(mut x: u64, mut exponent: u64, q: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = (u128::from(result) * u128::from(x) % u128::from(q)) as u64;
        }
        x = (u128::from(x) * u128::from(x) % u128::from(q)) as u64;
        exponent >>= 1;
    }
    result
}
fn product(lhs: &[IBig], rhs: &[IBig]) -> Vec<IBig> {
    let mut result = vec![IBig::ZERO; N];
    for (i, a) in lhs.iter().enumerate() {
        for (j, b) in rhs.iter().enumerate() {
            if i + j < N {
                result[i + j] += a * b;
            } else {
                result[i + j - N] -= a * b;
            }
        }
    }
    result
}
fn add(lhs: &[IBig], rhs: &[IBig]) -> Vec<IBig> {
    lhs.iter().zip(rhs).map(|(a, b)| a + b).collect()
}
fn tensor(lhs: &[Vec<IBig>], rhs: &[Vec<IBig>]) -> Vec<Vec<IBig>> {
    vec![
        product(&lhs[0], &rhs[0]),
        add(&product(&lhs[0], &rhs[1]), &product(&lhs[1], &rhs[0])),
        product(&lhs[1], &rhs[1]),
    ]
}
fn phase(components: &[Vec<IBig>], secret: &[IBig]) -> Vec<IBig> {
    let mut phase = components[0].clone();
    let mut s_power = secret.to_vec();
    for component in &components[1..] {
        phase = add(&phase, &product(component, &s_power));
        s_power = product(&s_power, secret);
    }
    phase
}
fn context(t: u64) -> BfvContext {
    BfvContext::try_with_levels(
        BfvParameters::try_with_error_distribution(
            PolyLength::new(N),
            BarrettModulus::new(t),
            BarrettModulus::new((1 << 61) - 1),
            &Q.map(BarrettModulus::new),
            SecretKeyDistr::UniformTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
        Q.len(),
    )
    .unwrap()
}
fn encode(
    context: &BfvContext,
    level: usize,
    coefficients: &[Vec<IBig>],
) -> BfvCiphertext<Vec<u64>> {
    let count = Q.len() - level;
    let mut ciphertext = context.new_ciphertext(level);
    for (component, values) in coefficients
        .iter()
        .zip(ciphertext.as_mut().chunks_exact_mut(count * N))
    {
        for ((&q, table), values) in Q[..count]
            .iter()
            .zip(context.table().iter())
            .zip(values.as_chunks_mut::<N>().0.iter_mut())
        {
            for (value, x) in values.iter_mut().zip(component) {
                *value = u64::try_from(modulo(x, &IBig::from(q))).unwrap();
            }
            table.transform_slice(values);
        }
    }
    ciphertext
}
fn decode_components(context: &BfvContext, level: usize, values: &[u64]) -> Vec<Vec<IBig>> {
    let count = Q.len() - level;
    let q = product_moduli(&Q[..count]);
    let mut data = values.to_vec();
    for component in data.chunks_exact_mut(count * N) {
        for (table, values) in context
            .table()
            .iter()
            .zip(component.as_chunks_mut::<N>().0.iter_mut())
        {
            table.inverse_transform_slice(values);
        }
    }
    data.chunks_exact(count * N)
        .map(|component| {
            (0..N)
                .map(|j| {
                    let mut sum = IBig::ZERO;
                    for (i, &qi) in Q[..count].iter().enumerate() {
                        let hat = &q / qi;
                        let hat_mod = &hat % qi;
                        sum += &hat * power(hat_mod, qi - 2, qi) * component[i * N + j];
                    }
                    centered(&sum, &q)
                })
                .collect()
        })
        .collect()
}

// Reconstructs the sum-of-fractions P/Q map with integers only. In particular
// epsilon is NOT rounded to a centered interval after the P wrap.
fn scaled_rhs(input: &[IBig], q_moduli: &[u64], p: &IBig) -> (Vec<IBig>, usize) {
    let q = product_moduli(q_moduli);
    let mut wraps = 0;
    let result = input
        .iter()
        .map(|x| {
            let mut numerator_epsilon = IBig::ZERO;
            for &qi in q_moduli {
                let hat = &q / qi;
                let inverse = power(&hat % qi, qi - 2, qi);
                let di = modulo(&(-p * x * inverse), &IBig::from(qi));
                numerator_epsilon += di * hat;
            }
            assert!(numerator_epsilon >= IBig::ZERO);
            assert!(numerator_epsilon < &q * q_moduli.len());
            let numerator = p * x + &numerator_epsilon;
            assert_eq!(&numerator % &q, IBig::ZERO);
            let raw = numerator / &q;
            let y = centered(&raw, p);
            let kappa = (&raw - &y) / p;
            assert!(kappa == IBig::ZERO || kappa == IBig::ONE);
            wraps += usize::from(kappa == IBig::ONE);
            y
        })
        .collect();
    (result, wraps)
}

#[test]
fn integer_tensor_wrap_and_complete_phase_residual_hold_across_prefixes() {
    let mut total_wraps = 0;
    for t in [193u64, 65_537] {
        let context = context(t);
        let secret = coefficients([1, -1, 0, 1, 0, 0, 0, 0]);
        let h = 3u64;
        let mut secret_i64 = vec![0; N];
        secret_i64[..4].copy_from_slice(&[1, -1, 0, 1]);
        let coefficient_key = GlweSecretKey::new(
            secret_i64,
            context.parameters().size().glwe_size(),
            SecretKeyDistr::UniformTernary,
        );
        let mut client = BfvClient::try_from_secret_key(
            &context,
            DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, context.table()),
        )
        .unwrap();
        let mut rng = StdRng::seed_from_u64(0x23bf_0001 + t);
        for level in 0..context.level_count() {
            let count = Q.len() - level;
            let q = product_moduli(&Q[..count]);
            let delta = &q / t;
            let message = coefficients([2, -1, 1, 0, -2, 0, 0, 0]);
            let right_message = coefficients([1, 1, 0, -1, 0, 0, 0, 0]);
            let error = coefficients([1, 0, -1, 0, 1, 0, 0, 0]);
            let mask: Vec<_> = (0..N)
                .map(|i| centered(&(&q / 2u64 - IBig::from(i * 13)), &q))
                .collect();
            let make = |m: &[IBig], sign: i32| {
                let mask: Vec<_> = mask.iter().map(|x| x * sign).collect();
                let masked = product(&mask, &secret);
                let body: Vec<_> = m
                    .iter()
                    .zip(&error)
                    .zip(masked)
                    .map(|((m, e), a)| centered(&(&delta * m + e - a), &q))
                    .collect();
                vec![body, mask]
            };
            let lhs = make(&message, 1);
            let rhs = make(&right_message, 1);
            let left = encode(&context, level, &lhs);
            let right = encode(&context, level, &rhs);
            // One P exercises P<Q and positive centered wraps; three P crosses
            // 128 bits and exercises P>Q. Neither path assumes P>NQ.
            for p_moduli in [&P[..1], &P[..3]] {
                let p = product_moduli(p_moduli);
                let mut multiplier = HpsMultiplier::try_new(&context, level, p_moduli).unwrap();
                let mut output = context.new_quadratic_ciphertext(level);
                for square in [false, true] {
                    let right_coeff = if square { &lhs } else { &rhs };
                    let mut scaled = Vec::new();
                    for input in right_coeff {
                        let (y, wraps) = scaled_rhs(input, &Q[..count], &p);
                        total_wraps += wraps;
                        scaled.push(y);
                    }
                    let expected: Vec<Vec<_>> = tensor(&lhs, &scaled)
                        .iter()
                        .map(|component| component.iter().map(|z| nearest(&(z * t), &p)).collect())
                        .collect();
                    // Each asymmetric lift must fully overwrite its own
                    // output even when square reuses one coefficient/INTT pass.
                    multiplier.coefficients.fill(u64::MAX);
                    multiplier.lhs_p.fill(u64::MAX);
                    multiplier.rhs_qp.fill(u64::MAX);
                    multiplier.tensor.fill(u64::MAX);
                    if square {
                        multiplier.square_to(&left, &mut output);
                    } else {
                        multiplier.multiply_to(&left, &right, &mut output);
                    }
                    assert_eq!(
                        decode_components(&context, level, output.as_ref()),
                        expected
                            .iter()
                            .map(|component| component
                                .iter()
                                .map(|x| centered(x, &q))
                                .collect::<Vec<_>>())
                            .collect::<Vec<_>>()
                    );
                    let exact: Vec<Vec<_>> = tensor(&lhs, right_coeff)
                        .iter()
                        .map(|component| component.iter().map(|z| nearest(&(z * t), &q)).collect())
                        .collect();
                    let hps_phase = phase(&expected, &secret);
                    let exact_phase = phase(&exact, &secret);
                    let b_epsilon_numerator = IBig::from(t) * N * count * &q * (1 + h).pow(2);
                    let b_epsilon = (&b_epsilon_numerator + 2u64 * &p - 1u64) / (2u64 * &p);
                    let b_wrap = IBig::from(N) * (2u64 * (&q % t) + t) * (1 + h);
                    let bound = b_epsilon + b_wrap + 1 + h + h * h;
                    for (a, b) in hps_phase.iter().zip(exact_phase) {
                        let e = centered(&(a - b), &q);
                        assert!(e >= -&bound && e <= bound);
                    }
                    let key = client
                        .relinearization_key(
                            level,
                            DecompositionConfig {
                                log_basis: DecompositionBaseLog::new(8),
                                level_count: None,
                            },
                            &mut rng,
                        )
                        .unwrap();
                    let mut relin = BfvRelinearizer::try_new(&context, &key).unwrap();
                    let mut linear = context.new_ciphertext(level);
                    relin.relinearize_to(&output, &mut linear);
                    let expected_message =
                        product(&message, if square { &message } else { &right_message });
                    let canonical: Vec<_> = expected_message
                        .iter()
                        .map(|m| u64::try_from(modulo(m, &IBig::from(t))).unwrap())
                        .collect();
                    assert_eq!(client.decrypt_at_level(&linear, level).as_ref(), canonical);
                    let final_phase = phase(
                        &decode_components(&context, level, linear.as_ref()),
                        &secret,
                    );
                    for (actual, m) in final_phase.iter().zip(&expected_message) {
                        let error = centered(&(actual - &delta * m), &q);
                        assert!(error > -(&delta / 2u64) && error < &delta / 2u64);
                    }
                }
            }
        }
    }
    assert!(
        total_wraps > 0,
        "fixtures must exercise the explicit centered-wrap term"
    );
}

#[test]
fn automatic_auxiliary_budget_includes_the_configured_secret_support() {
    for secret in [
        SecretKeyDistr::UniformTernary,
        SecretKeyDistr::Gaussian {
            standard_deviation: 3.19,
        },
    ] {
        let context = BfvContext::try_with_levels(
            BfvParameters::try_with_error_distribution(
                PolyLength::new(N),
                BarrettModulus::new(65_537),
                BarrettModulus::new((1 << 61) - 1),
                &Q.map(BarrettModulus::new),
                secret,
                ErrorDistribution::CenteredBinomial { eta: 1 },
            )
            .unwrap(),
            Q.len(),
        )
        .unwrap();
        let b = context
            .parameters()
            .encryption_parameters()
            .secret_key_sampler()
            .maximum_magnitude();
        let h_plus_one = IBig::from(N) * b + 1u64;
        for level in 0..context.level_count() {
            let multiplier = HpsMultiplier::try_with_default_basis(&context, level).unwrap();
            let p = product_moduli(multiplier.auxiliary_moduli());
            let l = Q.len() - level;
            let k = IBig::from(4u64) * 65_537u64 * 65_537u64 * N * l * &h_plus_one * &h_plus_one;
            assert!(p >= k);
            assert!(p > IBig::from(2 * l));
            assert!(
                multiplier
                    .auxiliary_moduli()
                    .iter()
                    .all(|x| !Q[..l].contains(x))
            );
        }
    }
}
