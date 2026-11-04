use primus_bgv::{
    BgvAutomorphism, BgvCiphertext, BgvClient, BgvCollectiveAutomorphismKey, BgvCollectiveError,
    BgvCollectivePublicKey, BgvCollectiveRelinearization, BgvCollectiveSwitchingKey, BgvContext,
    BgvEvaluator, BgvKeySwitcher, BgvModulusSwitch, BgvParameters, BgvRelinearizer, BgvSeededInput,
};
use primus_decompose::DecompositionBaseLog;
use primus_decompose::DecompositionConfig;
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey};
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;
use primus_poly::{DcrtPolynomial, Polynomial};
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
    for (table, limb) in context
        .table()
        .iter()
        .zip(values.as_chunks_mut::<N>().0.iter_mut())
    {
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
    c0.as_chunks::<N>()
        .0
        .iter()
        .zip(c1.as_chunks::<N>().0.iter())
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

#[test]
fn collective_public_input_and_partial_phase_have_one_mask_and_shared_integer_noise() {
    let context = context();
    let shares = fixture();
    let clients = shares
        .iter()
        .map(|s| owner(&context, s))
        .collect::<Vec<_>>();
    let secret = sum(&shares);
    let mut rng = StdRng::seed_from_u64(0x15_1001);
    let setup = BgvCollectivePublicKey::try_new(&context, &mut rng).unwrap();
    let mut aggregate = setup.aggregate();
    for client in &clients {
        let message = setup.contribute(client, &mut rng).unwrap();
        aggregate.add(&message).unwrap();
    }
    let key = setup.finalize(aggregate).unwrap();
    let phase = phase_coefficients(&context, key.as_ciphertext().as_ref(), &secret, 0);
    for i in 0..N {
        let errors = phase
            .iter()
            .zip(Q)
            .map(|(limb, q)| {
                let x = centered(limb[i], q);
                assert_eq!(x % i128::from(P), 0);
                x / i128::from(P)
            })
            .collect::<Vec<_>>();
        assert!(errors.iter().all(|&x| x == errors[0]));
        assert!(errors[0].abs() <= 63)
    }
    let input = BgvSeededInput::try_new(&context, setup.common_mask().to_vec()).unwrap();
    let mut aggregate = input.aggregate();
    let mut expected = vec![0; N];
    for (party, client) in clients.iter().enumerate() {
        let message = Polynomial::new(
            (0..N)
                .map(|i| ((i + party * 31) % P as usize) as u64)
                .collect::<Vec<_>>(),
        );
        for (out, &x) in expected.iter_mut().zip(message.as_ref()) {
            *out = (*out + x) % P
        }
        let contribution = input.contribute(client, &message, &mut rng).unwrap();
        aggregate.add(&contribution).unwrap();
    }
    let cipher = input.finalize(aggregate).unwrap();
    assert_eq!(
        &cipher.as_ref()[context.rns_poly_len(0)..],
        input.common_mask()
    );
    let mut oracle = owner(&context, &secret);
    assert_eq!(oracle.decrypt(&cipher, 0).as_ref(), expected);
    let len = context.rns_poly_len(0);
    let mut total = DcrtPolynomial(cipher.as_ref()[..len].to_vec());
    let mut partial = DcrtPolynomial(vec![0; len]);
    for client in &clients {
        client.partial_phase_to(&cipher, 0, &mut partial).unwrap();
        total.add_assign(&partial, N, context.base_q(0).moduli())
    }
    let phase = phase_coefficients(&context, cipher.as_ref(), &secret, 0);
    let coefficient = inverse(&context, total.as_ref());
    for (limb, (expected, &q)) in coefficient
        .as_chunks::<N>()
        .0
        .iter()
        .zip(phase.iter().zip(Q.iter()))
    {
        assert_eq!(
            limb.iter()
                .map(|&x| i128::from(x) % i128::from(q))
                .collect::<Vec<_>>(),
            *expected
        )
    }
    let mut encryptor = context.public_key_encryptor(&key).unwrap();
    let message = Polynomial::new((0..N).map(|i| i as u64).collect::<Vec<_>>());
    let cipher = encryptor.encrypt(&message, &mut rng);
    assert_eq!(oracle.decrypt(&cipher, 0).as_ref(), message.as_ref());
}

#[test]
fn collective_two_round_relinearization_matches_full_secret_square_and_native_consumers() {
    let context = context();
    let shares = fixture();
    let clients = shares
        .iter()
        .map(|s| owner(&context, s))
        .collect::<Vec<_>>();
    let combined = sum(&shares);
    let mut oracle = owner(&context, &combined);
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
    let message = Polynomial::new(
        (0..N)
            .map(|i| if i < 3 { (i + 2) as u64 } else { 0 })
            .collect::<Vec<_>>(),
    );
    let cipher = oracle.encrypt(&message, &mut rng);
    let mut quadratic = context.new_quadratic_ciphertext(0);
    BgvEvaluator::new(&context, 0).square_to(&cipher, &mut quadratic);
    let mut output = context.new_ciphertext(0);
    BgvRelinearizer::try_new(&context, &key)
        .unwrap()
        .relinearize_to(&quadratic, &mut output);
    let expected = convolution(
        &message
            .as_ref()
            .iter()
            .map(|&x| i128::from(x))
            .collect::<Vec<_>>(),
        &message
            .as_ref()
            .iter()
            .map(|&x| i128::from(x))
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        oracle.decrypt(&output, 0).as_ref(),
        expected
            .iter()
            .map(|x| x.rem_euclid(i128::from(P)) as u64)
            .collect::<Vec<_>>()
    );
}

#[test]
fn collective_linear_keys_and_rejection_boundaries() {
    let context = context();
    let shares = fixture();
    let clients = shares
        .iter()
        .map(|s| owner(&context, s))
        .collect::<Vec<_>>();
    let combined = sum(&shares);
    let mut source = owner(&context, &combined);
    let target_shares = shares
        .iter()
        .map(|s| s.iter().map(|&x| -x).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let targets = target_shares
        .iter()
        .map(|s| owner(&context, s))
        .collect::<Vec<_>>();
    let mut target = owner(&context, &sum(&target_shares));
    let mut rng = StdRng::seed_from_u64(0x15_3003);
    let setup = BgvCollectiveSwitchingKey::try_new(&context, 1, config(), &mut rng).unwrap();
    let other = BgvCollectiveSwitchingKey::try_from_common_masks(
        &context,
        1,
        config(),
        setup.common_masks().to_vec(),
    )
    .unwrap();
    let mut aggregate = setup.aggregate();
    for (client, target) in clients.iter().zip(&targets) {
        let message = setup.contribute(client, target, &mut rng).unwrap();
        assert!(other.aggregate().add(&message).is_err());
        aggregate.add(&message).unwrap();
    }
    let key = setup.finalize(aggregate).unwrap();
    let mut input = context.new_ciphertext(1);
    let message = Polynomial::new(
        (0..N)
            .map(|i| (i * 7 % P as usize) as u64)
            .collect::<Vec<_>>(),
    );
    let top = source.encrypt_centered(&message, &mut rng);
    BgvModulusSwitch::new(&context, 0).switch_to(&top, &mut input);
    let mut output = context.new_ciphertext(1);
    BgvKeySwitcher::try_new(&context, &key)
        .unwrap()
        .switch_to(&input, &mut output);
    assert_eq!(target.decrypt(&output, 1).as_ref(), message.as_ref());
    let auto = BgvCollectiveAutomorphismKey::try_new(&context, 1, 5, config(), &mut rng).unwrap();
    let mut aggregate = auto.aggregate();
    for client in &clients {
        aggregate
            .add(&auto.contribute(client, &mut rng).unwrap())
            .unwrap()
    }
    let key = auto.finalize(aggregate).unwrap();
    let mut transformed_message = vec![0; N];
    for (i, &coefficient) in message.as_ref().iter().enumerate() {
        let index = i * 5 % (2 * N);
        transformed_message[index % N] = if index < N {
            coefficient
        } else {
            (P - coefficient) % P
        };
    }
    BgvAutomorphism::try_new(&context, &key)
        .unwrap()
        .apply_to(&input, &mut output);
    assert_eq!(source.decrypt(&output, 1).as_ref(), transformed_message);
    let pk = BgvCollectivePublicKey::try_new(&context, &mut rng).unwrap();
    assert!(pk.finalize(pk.aggregate()).is_err());
    assert!(pk.try_import(vec![]).is_err());
    let mut bad = vec![0; context.rns_poly_len(0)];
    bad[0] = Q[0];
    assert!(pk.try_import(bad).is_err());
    let second_context = self::context();
    let different = owner(&second_context, &shares[0]);
    assert!(pk.contribute(&different, &mut rng).is_err());
    let relin = BgvCollectiveRelinearization::try_new(&context, 1, config(), &mut rng).unwrap();
    let (message, state) = relin.start(&clients[0], &mut rng).unwrap();
    let mut aggregate = relin.round_one_aggregate();
    aggregate.add(&message).unwrap();
    let frozen = relin.freeze_round_one(aggregate).unwrap();
    let alternate = relin
        .try_import_frozen_round_one(frozen.as_residues().to_vec(), 1)
        .unwrap();
    let response = state.round2(&frozen, &mut rng).unwrap();
    assert!(
        relin
            .round_two_aggregate(&alternate)
            .unwrap()
            .add(&response)
            .is_err()
    );
    assert!(relin.try_import_round_two(&frozen, vec![]).is_err());
    let mut partial = DcrtPolynomial(vec![17; context.rns_poly_len(1)]);
    let before = partial.as_ref().to_vec();
    let mut bad_input = BgvCiphertext::new(input.as_ref().to_vec());
    bad_input.as_mut()[0] = Q[0];
    assert!(
        source
            .partial_phase_to(&bad_input, 1, &mut partial)
            .is_err()
    );
    assert_eq!(partial.as_ref(), before);
    assert!(
        source
            .partial_phase_to(&input, usize::MAX, &mut partial)
            .is_err()
    );
    assert_eq!(partial.as_ref(), before);
    let gaussian = BgvContext::try_new(
        BgvParameters::try_coefficients(
            PolyLength::new(N),
            BarrettModulus::new(P),
            &Q.map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            1.0,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        BgvCollectivePublicKey::try_new(&gaussian, &mut rng),
        Err(BgvCollectiveError::Distribution)
    ));
}
