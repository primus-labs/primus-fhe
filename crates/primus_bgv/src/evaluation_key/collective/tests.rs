use super::*;
use crate::BgvParameters;
use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 32;
const P: u64 = 193;
const Q: [u64; 3] = [1125899906248961, 1125899906051329, 1125899904322049];
fn context() -> BgvContext {
    BgvContext::try_with_levels(
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
    .unwrap()
}
fn config() -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(5),
        level_count: None,
    }
}
fn owner<'a>(context: &'a BgvContext, coeff: &[i64]) -> BgvClient<'a> {
    let coefficient = GlweSecretKey::new(
        coeff.to_vec(),
        context.parameters().size().glwe_size(),
        SecretKeyDistr::SparseTernary,
    );
    BgvClient::try_from_secret_key(
        context,
        DcrtGlweSecretKey::from_coeff_secret_key(&coefficient, context.table()),
    )
    .unwrap()
}
fn fixture() -> [Vec<i64>; 3] {
    std::array::from_fn(|party| {
        (0..N)
            .map(|i| match (i + party * 3) % 5 {
                0 => -1,
                1 | 2 => 1,
                _ => 0,
            })
            .collect()
    })
}
fn sum(shares: &[Vec<i64>]) -> Vec<i64> {
    (0..N).map(|i| shares.iter().map(|s| s[i]).sum()).collect()
}
fn inverse(context: &BgvContext, input: &[u64]) -> Vec<u64> {
    let mut values = input.to_vec();
    for (table, limb) in context.table().iter().zip(values.chunks_exact_mut(N)) {
        table.inverse_transform_slice(limb)
    }
    values
}
fn convolution(a: &[i128], b: &[i128]) -> Vec<i128> {
    let mut output = vec![0; N];
    for (i, &a) in a.iter().enumerate() {
        for (j, &b) in b.iter().enumerate() {
            let index = i + j;
            if index < N {
                output[index] += a * b
            } else {
                output[index - N] -= a * b
            }
        }
    }
    output
}
fn phase_coefficients(
    context: &BgvContext,
    cipher: &[u64],
    s: &[i64],
    level: usize,
) -> Vec<Vec<i128>> {
    let len = context.rns_poly_len(level);
    let c0 = inverse(context, &cipher[..len]);
    let c1 = inverse(context, &cipher[len..]);
    c0.chunks_exact(N)
        .zip(c1.chunks_exact(N))
        .zip(context.base_q(level).moduli_values())
        .map(|((c0, c1), &q)| {
            let product = convolution(
                &c1.iter().map(|&v| i128::from(v)).collect::<Vec<_>>(),
                &s.iter().map(|&v| i128::from(v)).collect::<Vec<_>>(),
            );
            c0.iter()
                .zip(product)
                .map(|(&value, product)| (i128::from(value) + product).rem_euclid(i128::from(q)))
                .collect()
        })
        .collect()
}
fn centered(x: i128, q: u64) -> i128 {
    let x = x.rem_euclid(i128::from(q));
    if x > i128::from(q) / 2 {
        x - i128::from(q)
    } else {
        x
    }
}

fn check_linear_columns(
    context: &BgvContext,
    key: &NativeEvaluationKey,
    source: &[i64],
    target: &[i64],
) {
    let level = key.level;
    let len = context.rns_poly_len(level);
    let base = context.base_q(level);
    let mut weights = vec![0; base.moduli_count()];
    for (column, scalar) in key
        .columns
        .chunks_exact(2 * len)
        .zip(key.radix_basis().scalar_iter())
    {
        base.decompose_to(primus_integer::BigUint(scalar), Residues(&mut weights));
        let phase = phase_coefficients(context, column, target, level);
        for (i, &source) in source.iter().enumerate() {
            let errors = phase
                .iter()
                .zip(base.moduli_values())
                .zip(&weights)
                .map(|((limb, &q), &g)| {
                    let error = centered(
                        limb[i] - i128::from(P) * i128::from(g) * i128::from(source),
                        q,
                    );
                    assert_eq!(error % i128::from(P), 0);
                    error / i128::from(P)
                })
                .collect::<Vec<_>>();
            assert!(errors.iter().all(|&x| x == errors[0]));
            assert!(errors[0].abs() <= 63);
        }
    }
}

#[test]
fn collective_two_round_columns_match_full_secret_square() {
    let context = context();
    let shares = fixture();
    let clients = shares
        .iter()
        .map(|s| owner(&context, s))
        .collect::<Vec<_>>();
    let combined = sum(&shares);
    let mut rng = StdRng::seed_from_u64(0x15_2002);
    let setup = BgvCollectiveRelinearization::try_new(&context, 0, config(), &mut rng).unwrap();
    let mut first = setup.round_one_aggregate();
    let mut states = Vec::new();
    for client in &clients {
        let (message, state) = setup.start(client, &mut rng).unwrap();
        first.add(&message).unwrap();
        states.push(state)
    }
    let frozen = setup.freeze_round_one(first).unwrap();
    let mut second = setup.round_two_aggregate(&frozen).unwrap();
    for state in states {
        let message = state.round2(&frozen, &mut rng).unwrap();
        second.add(&message).unwrap();
    }
    let key = setup.finalize(&frozen, second).unwrap();
    let square = convolution(
        &combined.iter().map(|&x| i128::from(x)).collect::<Vec<_>>(),
        &combined.iter().map(|&x| i128::from(x)).collect::<Vec<_>>(),
    );
    let len = context.rns_poly_len(0);
    let mut weights = vec![0; Q.len()];
    for (column, scalar) in key
        .key
        .columns
        .chunks_exact(2 * len)
        .zip(key.key.radix_basis().scalar_iter())
    {
        context
            .base_q(0)
            .decompose_to(primus_integer::BigUint(scalar), Residues(&mut weights));
        let phase = phase_coefficients(&context, column, &combined, 0);
        for (i, &square) in square.iter().enumerate() {
            let errors = phase
                .iter()
                .zip(Q)
                .zip(&weights)
                .map(|((limb, q), &g)| {
                    let error = centered(limb[i] - i128::from(P) * i128::from(g) * square, q);
                    assert_eq!(error % i128::from(P), 0);
                    error / i128::from(P)
                })
                .collect::<Vec<_>>();
            assert!(errors.iter().all(|&x| x == errors[0]));
            assert!(errors[0].abs() <= 21 * 3 * (2 * N as i128 * 3 + 1));
        }
    }
}

#[test]
fn collective_linear_columns_have_shared_p_scaled_noise() {
    let context = context();
    let shares = fixture();
    let clients = shares
        .iter()
        .map(|s| owner(&context, s))
        .collect::<Vec<_>>();
    let combined = sum(&shares);
    let target_shares = shares
        .iter()
        .map(|s| s.iter().map(|&x| -x).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let targets = target_shares
        .iter()
        .map(|s| owner(&context, s))
        .collect::<Vec<_>>();
    let mut rng = StdRng::seed_from_u64(0x15_3003);
    let setup = BgvCollectiveSwitchingKey::try_new(&context, 1, config(), &mut rng).unwrap();
    let mut aggregate = setup.aggregate();
    for (client, target) in clients.iter().zip(&targets) {
        let message = setup.contribute(client, target, &mut rng).unwrap();
        aggregate.add(&message).unwrap();
    }
    let key = setup.finalize(aggregate).unwrap();
    check_linear_columns(&context, &key.key, &combined, &sum(&target_shares));
    let auto = BgvCollectiveAutomorphismKey::try_new(&context, 1, 5, config(), &mut rng).unwrap();
    let mut aggregate = auto.aggregate();
    for client in &clients {
        aggregate
            .add(&auto.contribute(client, &mut rng).unwrap())
            .unwrap()
    }
    let key = auto.finalize(aggregate).unwrap();
    let mut transformed_secret = vec![0; N];
    for (i, &secret) in combined.iter().enumerate() {
        let index = i * 5 % (2 * N);
        transformed_secret[index % N] = if index < N { secret } else { -secret };
    }
    check_linear_columns(&context, &key.key, &transformed_secret, &combined);
}
