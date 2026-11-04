use super::*;
use crate::BfvParameters;
use primus_decompose::DecompositionBaseLog;
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
    let mut out = values.to_vec();
    transform(context, &mut out, true);
    out
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
        BfvParameters::try_with_error_distribution(
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
        let plan = BfvCollectiveRelinearization::try_new(
            &context,
            level,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(10),
                level_count: None,
            },
            &mut rng,
        )
        .unwrap();
        let len = context.rns_poly_len(level);
        let limbs = context.codec(level).moduli_count();
        let columns = plan.setup.native.basis.level_count().get();
        let secrets: Vec<_> = clients
            .iter()
            .map(|c| coefficients(&context, secret(c, len)))
            .collect();
        let masks: Vec<_> = plan
            .setup
            .masks
            .chunks_exact(len)
            .map(|v| coefficients(&context, v))
            .collect();
        let mut r1sum = plan.aggregate(3).unwrap();
        let mut states = Vec::new();
        let mut u = Vec::new();
        let mut r1 = Vec::new();
        for client in &clients {
            let (message, state) = plan.start(client, &mut rng).unwrap();
            u.push(coefficients(&context, &state.ephemeral));
            r1.push(
                message
                    .residues
                    .chunks_exact(len)
                    .map(|v| coefficients(&context, v))
                    .collect::<Vec<_>>(),
            );
            r1sum.add(&message).unwrap();
            states.push(state);
        }
        let round1 = plan.freeze_round1(r1sum).unwrap();
        let h: Vec<_> = round1
            .residues
            .chunks_exact(len)
            .map(|v| coefficients(&context, v))
            .collect();
        let mut r2sum = round1.aggregate(3).unwrap();
        let mut r2 = Vec::new();
        for state in states {
            let message = state.round2(&round1, &mut rng).unwrap();
            r2.push(
                message
                    .residues
                    .chunks_exact(len)
                    .map(|v| coefficients(&context, v))
                    .collect::<Vec<_>>(),
            );
            r2sum.add(&message).unwrap();
        }
        let key = round1.finalize_lookup(r2sum).unwrap();
        let mut weights = vec![0; limbs];
        for (column, scalar) in plan.setup.native.basis.scalar_iter().enumerate() {
            context
                .codec(level)
                .base_q()
                .decompose_to(primus_integer::BigUint(scalar), Residues(&mut weights));
            let key_column = &key.key.columns[column * 2 * len..(column + 1) * 2 * len];
            let c0 = coefficients(&context, &key_column[..len]);
            let c1 = coefficients(&context, &key_column[len..]);
            let mut first_errors: Option<Vec<Vec<i64>>> = None;
            for limb in 0..limbs {
                let q = q[limb];
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
                        .map(|&x| (x as u128 * weights[limb] as u128 % q as u128) as u64)
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
                    .map(|&x| (x as u128 * weights[limb] as u128 % q as u128) as u64)
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
