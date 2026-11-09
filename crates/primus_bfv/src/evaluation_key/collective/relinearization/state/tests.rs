use std::sync::Arc;

use super::super::BfvCollectiveLookup;
use super::*;
use crate::{
    BfvClient, BfvContext, BfvParameters, ErrorDistribution, SecretKeyDistr,
    collective::BfvRawQuadraticAggregate,
    evaluation_key::{
        BfvEvaluationKeyConfig,
        tests::{inverse, power},
    },
};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn add(a: &[u64], b: &[u64], q: u64) -> Vec<u64> {
    a.iter()
        .zip(b)
        .map(|(&a, &b)| ((a as u128 + b as u128) % q as u128) as u64)
        .collect()
}
fn sub(a: &[u64], b: &[u64], q: u64) -> Vec<u64> {
    a.iter()
        .zip(b)
        .map(|(&a, &b)| ((a as u128 + q as u128 - b as u128) % q as u128) as u64)
        .collect()
}
// Independent coefficient-ring oracle: no DCRT multiplication/kernel.
fn convolution(a: &[u64], b: &[u64], q: u64) -> Vec<u64> {
    let n = a.len();
    let mut out = vec![0; n];
    for (i, &a) in a.iter().enumerate() {
        for (j, &b) in b.iter().enumerate() {
            let term = (a as u128 * b as u128 % q as u128) as u64;
            let index = (i + j) % n;
            out[index] = if i + j < n {
                ((out[index] as u128 + term as u128) % q as u128) as u64
            } else {
                ((out[index] as u128 + q as u128 - term as u128) % q as u128) as u64
            };
        }
    }
    out
}
fn coefficients(context: &BfvContext, values: &[u64]) -> Vec<u64> {
    let n = context.parameters().poly_length().get();
    values
        .chunks_exact(n)
        .zip(context.codec(0).moduli_values())
        .flat_map(|(values, &q)| inverse(values, q))
        .collect()
}
fn key_coefficients(setup: &EvaluationSetup<'_>, values: &[u64]) -> Vec<u64> {
    values
        .chunks_exact(setup.native.n)
        .zip(setup.native.key_moduli_values())
        .flat_map(|(values, &q)| inverse(values, q))
        .collect()
}
fn signed(values: &[u64], q: u64) -> Vec<i64> {
    values
        .iter()
        .map(|&x| {
            if x > q / 2 {
                x as i64 - q as i64
            } else {
                x as i64
            }
        })
        .collect()
}

#[test]
fn two_round_cross_terms_and_error_law_match_independent_coefficient_oracle() {
    let n = 32;
    let q = [
        1_125_899_906_248_961,
        1_125_899_906_051_329,
        1_125_899_904_322_049,
    ];
    let context = BfvContext::try_with_levels(
        BfvParameters::try_with_decoder_modulus(
            PolyLength::new(n),
            BarrettModulus::new(257),
            BarrettModulus::new((1 << 61) - 1),
            &q.map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 21 },
        )
        .unwrap(),
        3,
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0x0015_bf02);
    let clients: Vec<_> = (0..3)
        .map(|_| BfvClient::generate(&context, &mut rng))
        .collect();
    for level in [0, 1] {
        for hybrid in [false, true] {
            let config: BfvEvaluationKeyConfig = if hybrid {
                context
                    .hybrid_key_parameters(level, 2, &[1_099_511_626_049])
                    .unwrap()
                    .into()
            } else {
                DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(10),
                    level_count: None,
                }
                .into()
            };
            let plan = BfvCollectiveLookup::try_new(&context, level, config, &mut rng).unwrap();
            let len = plan.setup.native.key_poly_len();

            let columns = plan.setup.native.key_len() / (2 * len);
            let secrets: Vec<_> = clients
                .iter()
                .map(|c| {
                    key_coefficients(
                        &plan.setup,
                        &plan.setup.native.secret(&context, c.secret_key()).unwrap(),
                    )
                })
                .collect();
            let masks: Vec<_> = plan
                .setup
                .masks
                .chunks_exact(len)
                .map(|v| key_coefficients(&plan.setup, v))
                .collect();
            let mut r1sum = plan.aggregate(3).unwrap();
            let mut states = Vec::new();
            let mut u = Vec::new();
            let mut r1 = Vec::new();
            for client in &clients {
                let (message, state) = plan.start(client.secret_key(), &mut rng).unwrap();
                u.push(key_coefficients(&plan.setup, &state.ephemeral));
                r1.push(
                    message
                        .residues
                        .chunks_exact(len)
                        .map(|v| key_coefficients(&plan.setup, v))
                        .collect::<Vec<_>>(),
                );
                r1sum.add(&message).unwrap();
                states.push(state);
            }
            let round1 = plan.freeze_round1(r1sum).unwrap();
            let h: Vec<_> = round1
                .residues
                .chunks_exact(len)
                .map(|v| key_coefficients(&plan.setup, v))
                .collect();
            let mut r2 = Vec::new();
            let mut keys = round1
                .finalize_lookup_for_roster(|round1| {
                    let mut r2sum = round1.aggregate(3)?;
                    for state in states {
                        let message = state.round2(round1, &mut rng)?;
                        r2.push(
                            message
                                .residues
                                .chunks_exact(len)
                                .map(|v| key_coefficients(&plan.setup, v))
                                .collect::<Vec<_>>(),
                        );
                        r2sum.add(&message)?;
                    }
                    Ok::<_, BfvCollectiveError>(r2sum)
                })
                .unwrap();
            assert_eq!(keys.len(), 3);
            let key = keys.pop().unwrap();
            assert!(keys.iter().all(|owner| Arc::ptr_eq(&key.key, &owner.key)));
            for column in 0..columns {
                let actual_moduli = plan.setup.native.key_moduli_values();
                let q_count = context.codec(level).moduli_count();
                let weights: Vec<_> = actual_moduli
                    .iter()
                    .enumerate()
                    .map(|(limb, &q)| {
                        if hybrid {
                            if limb < q_count && limb / 2 == column {
                                1_099_511_626_049 % q
                            } else {
                                0
                            }
                        } else {
                            (0..column).fold(1u64, |x, _| (x as u128 * 1024 % q as u128) as u64)
                        }
                    })
                    .collect();
                let key_column = &key.key.columns[column * 2 * len..(column + 1) * 2 * len];
                let c0 = key_coefficients(&plan.setup, &key_column[..len]);
                let c1 = key_coefficients(&plan.setup, &key_column[len..]);
                let mut first_errors: Option<Vec<Vec<i64>>> = None;
                for (limb, &weight) in weights.iter().enumerate() {
                    let q = plan.setup.native.key_moduli_values()[limb];
                    let range = limb * n..(limb + 1) * n;
                    let mut sum_s = vec![0; n];
                    let mut sum_u = vec![0; n];
                    let mut e0 = vec![0; n];
                    let mut e1 = vec![0; n];
                    let mut e2 = vec![0; n];
                    let mut errors = Vec::new();
                    for party in 0..3 {
                        let s = &secrets[party][range.clone()];
                        let u = &u[party][range.clone()];
                        let a = &masks[column][range.clone()];
                        let h0 = &r1[party][2 * column][range.clone()];
                        let h1 = &r1[party][2 * column + 1][range.clone()];
                        let gs: Vec<_> = s
                            .iter()
                            .map(|&x| (x as u128 * weight as u128 % q as u128) as u64)
                            .collect();
                        let error0 = add(&sub(h0, &gs, q), &convolution(a, u, q), q);
                        let error1 = sub(h1, &convolution(a, s, q), q);
                        let expected_z = add(
                            &convolution(s, &h[2 * column][range.clone()], q),
                            &convolution(&sub(u, s, q), &h[2 * column + 1][range.clone()], q),
                            q,
                        );
                        let error2 = sub(&r2[party][column][range.clone()], &expected_z, q);
                        for error in [&error0, &error1, &error2] {
                            let error = signed(error, q);
                            assert!(error.iter().all(|x| (-21..=21).contains(x)));
                            errors.push(error);
                        }
                        e0 = add(&e0, &error0, q);
                        e1 = add(&e1, &error1, q);
                        e2 = add(&e2, &error2, q);
                        sum_s = add(&sum_s, s, q);
                        sum_u = add(&sum_u, u, q);
                    }
                    if let Some(first) = &first_errors {
                        assert_eq!(first, &errors, "same integer errors across all CRT limbs");
                    } else {
                        first_errors = Some(errors);
                    }
                    let square = convolution(&sum_s, &sum_s, q);
                    let gsquare: Vec<_> = square
                        .iter()
                        .map(|&x| (x as u128 * weight as u128 % q as u128) as u64)
                        .collect();
                    let expected = add(
                        &add(
                            &add(&gsquare, &convolution(&sum_s, &e0, q), q),
                            &convolution(&sum_u, &e1, q),
                            q,
                        ),
                        &e2,
                        q,
                    );
                    let actual = add(
                        &c0[range.clone()],
                        &convolution(&c1[range.clone()], &sum_s, q),
                        q,
                    );
                    assert_eq!(
                        actual, expected,
                        "all i,k cross terms, level {level}, column {column}, limb {limb}"
                    );
                }
            }
            assert_eq!(columns, plan.setup.masks.len() / len);
            if hybrid {
                use dashu_int::IBig;
                let q_values = context.codec(level).moduli_values();
                let modulus = q_values.iter().fold(IBig::ONE, |x, &q| x * q);
                let delta = &modulus / 257u64;
                let q_len = context.rns_poly_len(level);
                let mut tensor = vec![0; 3 * q_len];
                for (limb, &q) in tensor[2 * q_len..].chunks_exact_mut(n).zip(q_values) {
                    limb.fill(&delta % q);
                }
                let mut output = context.new_ciphertext(level);
                key.prepare()
                    .apply_to(
                        BfvRawQuadraticAggregate::try_new(&context, level, tensor).unwrap(),
                        &mut output,
                    )
                    .unwrap();
                let c0 = coefficients(&context, &output.as_ref()[..q_len]);
                let c1 = coefficients(&context, &output.as_ref()[q_len..]);
                let mut s = vec![0i64; n];
                for secret in &secrets {
                    for (out, value) in s.iter_mut().zip(signed(&secret[..n], q_values[0])) {
                        *out += value;
                    }
                }
                let mut square = vec![0i64; n];
                for (i, &a) in s.iter().enumerate() {
                    for (j, &b) in s.iter().enumerate() {
                        square[(i + j) % n] += if i + j < n { a * b } else { -a * b };
                    }
                }
                let mut actual_limbs = Vec::new();
                for (index, &q) in q_values.iter().enumerate() {
                    let secret: Vec<_> = s.iter().map(|&x| x.rem_euclid(q as i64) as u64).collect();
                    let range = index * n..(index + 1) * n;
                    actual_limbs.push(add(
                        &c0[range.clone()],
                        &convolution(&c1[range], &secret, q),
                        q,
                    ));
                }
                // Deterministic key-error support and actual partition digit range.
                // Ecol<=2*G²*N*21+G*21; each digit magnitude <width*Qpart.
                let e_column = 2 * 9 * n * 21 + 3 * 21;
                let digit_sum = q_values.chunks(2).fold(IBig::ZERO, |sum, chunk| {
                    sum + chunk.len() * chunk.iter().fold(IBig::ONE, |x, &q| x * q)
                });
                let p = IBig::from(1_099_511_626_049u64);
                let bound = (n * e_column * digit_sum + &p - 1u64) / &p + (1 + 3 * n).div_ceil(2);
                for i in 0..n {
                    let mut phase = IBig::ZERO;
                    for ((&q, values), hat) in q_values
                        .iter()
                        .zip(&actual_limbs)
                        .zip(q_values.iter().map(|&q| &modulus / q))
                    {
                        let inverse = power(&hat % q, q - 2, q);
                        phase += IBig::from(values[i]) * inverse * &hat;
                    }
                    let mut error = (phase - &delta * square[i]) % &modulus;
                    if error < IBig::ZERO {
                        error += &modulus;
                    }
                    if error > &modulus / 2u64 {
                        error -= &modulus;
                    }
                    assert!(
                        error >= -&bound && error <= bound,
                        "raw Hybrid lookup is unscaled and its complete key/rounding error is bounded"
                    );
                }
            } else {
                // For a monomial t2=1, the unscaled lookup is exactly the first
                // evaluation column when the full radix has no dropped bits.
                let mut tensor = vec![0; 3 * len];
                for limb in tensor[2 * len..].chunks_exact_mut(n) {
                    limb.fill(1);
                }
                let mut output = context.new_ciphertext(level);
                let first_column = key.key.columns[..2 * len].to_vec();
                key.prepare()
                    .apply_to(
                        BfvRawQuadraticAggregate::try_new(&context, level, tensor).unwrap(),
                        &mut output,
                    )
                    .unwrap();
                assert_eq!(output.as_ref(), first_column);
            }
        }
    }
}
