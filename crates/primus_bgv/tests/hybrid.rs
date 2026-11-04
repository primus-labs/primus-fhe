//! Native Hybrid roles use the ordinary requests and actual QP collective messages.
use primus_bgv::{
    BgvAutomorphism, BgvCiphertext, BgvClient, BgvCollectiveAutomorphismKey,
    BgvCollectiveRelinearization, BgvCollectiveSwitchingKey, BgvContext, BgvKeySwitcher,
    BgvModulusSwitch, BgvMultiplication, BgvParameters,
};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};
const N: usize = 32;
const T: u64 = 193;
const Q: [u64; 3] = [1125899906248961, 1125899906051329, 1125899904322049];
const P: [u64; 2] = [1152921504606830593, 1152921504606748673];
fn context() -> BgvContext {
    BgvContext::try_with_levels(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(N),
            BarrettModulus::new(T),
            &Q.map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 21 },
        )
        .unwrap(),
        3,
    )
    .unwrap()
}
fn message() -> Polynomial<Vec<u64>> {
    Polynomial::new(
        (0..N)
            .map(|i| ((i as i64 % 5) - 2).rem_euclid(T as i64) as u64)
            .collect(),
    )
}
fn product(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut out = vec![0i64; N];
    let center = |x: u64| {
        if x > T / 2 {
            x as i64 - T as i64
        } else {
            x as i64
        }
    };
    for (i, &a) in a.iter().enumerate() {
        for (j, &b) in b.iter().enumerate() {
            out[(i + j) % N] += if i + j < N {
                center(a) * center(b)
            } else {
                -center(a) * center(b)
            };
        }
    }
    out.into_iter()
        .map(|x| x.rem_euclid(T as i64) as u64)
        .collect()
}
fn automorphism(a: &[u64], exponent: usize) -> Vec<u64> {
    let mut out = vec![0; N];
    for (i, &a) in a.iter().enumerate() {
        let k = i * exponent % (2 * N);
        out[k % N] = if k < N { a } else { (T - a) % T };
    }
    out
}
#[test]
fn hybrid_native_roles_and_prepared_multiplication_recover_at_every_prefix() {
    let context = context();
    let mut rng = StdRng::seed_from_u64(0x24b6_0001);
    let mut alice = BgvClient::generate(&context, &mut rng);
    let mut bob = BgvClient::generate(&context, &mut rng);
    let plaintext = message();
    let square = product(plaintext.as_ref(), plaintext.as_ref());
    let mut input = alice.encrypt_centered(&plaintext, &mut rng);
    assert_ne!(P[0] % T, 1, "this case must not rely on P=1 mod t");
    for level in 0..3 {
        let parameters = context.hybrid_key_parameters(level, 2, &P[..1]).unwrap();
        let key = alice
            .relinearization_key(level, parameters.clone(), &mut rng)
            .unwrap();
        let mut request = BgvMultiplication::try_new(&context, &key).unwrap();
        let mut output = context.new_ciphertext(level);
        request.square_to(&input, &mut output);
        assert_eq!(alice.decrypt(&output, level).as_ref(), square);
        let switch = bob
            .key_switching_key(&alice, level, parameters.clone(), &mut rng)
            .unwrap();
        BgvKeySwitcher::try_new(&context, &switch)
            .unwrap()
            .switch_to(&input, &mut output);
        assert_eq!(bob.decrypt(&output, level).as_ref(), plaintext.as_ref());
        let auto = alice
            .automorphism_key(level, 2 * N - 1, parameters, &mut rng)
            .unwrap();
        BgvAutomorphism::try_new(&context, &auto)
            .unwrap()
            .apply_to(&input, &mut output);
        assert_eq!(
            alice.decrypt(&output, level).as_ref(),
            automorphism(plaintext.as_ref(), 2 * N - 1)
        );
        if level < 2 {
            let mut next = context.new_ciphertext(level + 1);
            BgvModulusSwitch::new(&context, level).switch_to(&input, &mut next);
            input = next;
        }
    }
}
#[test]
fn hybrid_collective_qp_messages_and_square_cross_terms_use_native_roles() {
    let context = context();
    let mut rng = StdRng::seed_from_u64(0x24b6_0002);
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
    let owners: Vec<_> = shares
        .iter()
        .map(|s| {
            let coeff = GlweSecretKey::new(
                s.clone(),
                context.parameters().size().glwe_size(),
                SecretKeyDistr::SparseTernary,
            );
            BgvClient::try_from_secret_key(
                &context,
                DcrtGlweSecretKey::from_coeff_secret_key(&coeff, context.table()),
            )
            .unwrap()
        })
        .collect();
    let combined: Vec<i64> = (0..N).map(|i| shares.iter().map(|s| s[i]).sum()).collect();
    let coeff = GlweSecretKey::new(
        combined,
        context.parameters().size().glwe_size(),
        SecretKeyDistr::SparseTernary,
    );
    let mut aggregate_client = BgvClient::try_from_secret_key(
        &context,
        DcrtGlweSecretKey::from_coeff_secret_key(&coeff, context.table()),
    )
    .unwrap();
    let plaintext = message();
    let input = aggregate_client.encrypt_centered(&plaintext, &mut rng);
    let parameters = context.hybrid_key_parameters(0, 3, &P).unwrap();
    let setup =
        BgvCollectiveRelinearization::try_new(&context, 0, parameters.clone(), &mut rng).unwrap();
    assert_eq!(
        setup.common_masks().len(),
        parameters.partition_count() * parameters.qp_poly_len()
    );
    let mut first = setup.round_one_aggregate();
    let mut states = Vec::new();
    for owner in &owners {
        let (message, state) = setup.start(owner, &mut rng).unwrap();
        first.add(&message).unwrap();
        states.push(state);
    }
    let frozen = setup.freeze_round_one(first).unwrap();
    let mut second = setup.round_two_aggregate(&frozen).unwrap();
    for state in states {
        second
            .add(&state.round2(&frozen, &mut rng).unwrap())
            .unwrap();
    }
    let key = setup.finalize(&frozen, second).unwrap();
    let mut output = context.new_ciphertext(0);
    BgvMultiplication::try_new(&context, &key)
        .unwrap()
        .square_to(&input, &mut output);
    assert_eq!(
        aggregate_client.decrypt(&output, 0).as_ref(),
        product(plaintext.as_ref(), plaintext.as_ref())
    );
    let setup =
        BgvCollectiveSwitchingKey::try_new(&context, 0, parameters.clone(), &mut rng).unwrap();
    let mut sum = setup.aggregate();
    for owner in &owners {
        sum.add(&setup.contribute(owner, owner, &mut rng).unwrap())
            .unwrap();
    }
    let key = setup.finalize(sum).unwrap();
    BgvKeySwitcher::try_new(&context, &key)
        .unwrap()
        .switch_to(&input, &mut output);
    assert_eq!(
        aggregate_client.decrypt(&output, 0).as_ref(),
        plaintext.as_ref()
    );
    let setup =
        BgvCollectiveAutomorphismKey::try_new(&context, 0, 5, parameters, &mut rng).unwrap();
    let mut sum = setup.aggregate();
    for owner in &owners {
        sum.add(&setup.contribute(owner, &mut rng).unwrap())
            .unwrap();
    }
    let key = setup.finalize(sum).unwrap();
    BgvAutomorphism::try_new(&context, &key)
        .unwrap()
        .apply_to(&input, &mut output);
    assert_eq!(
        aggregate_client.decrypt(&output, 0).as_ref(),
        automorphism(plaintext.as_ref(), 5)
    );
    let mut malformed = setup.common_masks().to_vec();
    malformed[Q.len() * N] = P[0];
    assert!(
        BgvCollectiveAutomorphismKey::try_from_common_masks(
            &context,
            0,
            5,
            context.hybrid_key_parameters(0, 3, &P).unwrap(),
            malformed
        )
        .is_err()
    );
}
#[test]
fn hybrid_binding_and_prewrite_rejections_do_not_consume_randomness_or_output() {
    let context = context();
    let mut rng = StdRng::seed_from_u64(0x24b6_0003);
    let alice = BgvClient::generate(&context, &mut rng);
    let low = context.hybrid_key_parameters(1, 2, &P).unwrap();
    let mut rng = StdRng::seed_from_u64(0x24b6_bad0);
    let mut expected = StdRng::seed_from_u64(0x24b6_bad0);
    assert!(alice.relinearization_key(0, low, &mut rng).is_err());
    assert_eq!(rng.next_u64(), expected.next_u64());
    let p = context.hybrid_key_parameters(0, 2, &P).unwrap();
    let key = alice.relinearization_key(0, p, &mut rng).unwrap();
    let mut request = BgvMultiplication::try_new(&context, &key).unwrap();
    let len = context.new_ciphertext(0).as_ref().len();
    let bad = BgvCiphertext::new(vec![0; len - 1]);
    let mut output = BgvCiphertext::new(vec![17; len]);
    assert!(catch_unwind(AssertUnwindSafe(|| request.square_to(&bad, &mut output))).is_err());
    assert!(output.as_ref().iter().all(|&x| x == 17));
    assert!(context.hybrid_key_parameters(0, 2, &[Q[0]]).is_err());
    let nonunit = context.hybrid_key_parameters(0, 2, &[T]).unwrap();
    let mut rng = StdRng::seed_from_u64(0x24b6_bad1);
    let mut expected = StdRng::seed_from_u64(0x24b6_bad1);
    assert!(alice.relinearization_key(0, nonunit, &mut rng).is_err());
    assert_eq!(rng.next_u64(), expected.next_u64());
    let coefficient = GlweSecretKey::new(
        vec![2; N],
        context.parameters().size().glwe_size(),
        SecretKeyDistr::SparseTernary,
    );
    let unsupported = BgvClient::try_from_secret_key(
        &context,
        DcrtGlweSecretKey::from_coeff_secret_key(&coefficient, context.table()),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0x24b6_bad2);
    let mut expected = StdRng::seed_from_u64(0x24b6_bad2);
    assert!(
        unsupported
            .relinearization_key(
                0,
                context.hybrid_key_parameters(0, 2, &P).unwrap(),
                &mut rng
            )
            .is_err()
    );
    assert_eq!(rng.next_u64(), expected.next_u64());
}

#[test]
fn hybrid_secret_extension_handles_the_configured_gaussian_hard_support() {
    let context = BgvContext::try_new(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(N),
            BarrettModulus::new(T),
            &Q.map(BarrettModulus::new),
            SecretKeyDistr::Gaussian {
                standard_deviation: 1.25,
            },
            ErrorDistribution::CenteredBinomial { eta: 21 },
        )
        .unwrap(),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0x24b6_0004);
    let mut alice = BgvClient::generate(&context, &mut rng);
    let parameters = context.hybrid_key_parameters(0, 3, &P).unwrap();
    let key = alice.relinearization_key(0, parameters, &mut rng).unwrap();
    let input = message();
    let encrypted = alice.encrypt_centered(&input, &mut rng);
    let mut output = context.new_ciphertext(0);
    BgvMultiplication::try_new(&context, &key)
        .unwrap()
        .square_to(&encrypted, &mut output);
    assert_eq!(
        alice.decrypt(&output, 0).as_ref(),
        product(input.as_ref(), input.as_ref())
    );
}

#[test]
fn hybrid_secret_lift_uses_complete_stored_q_when_the_first_prime_is_ambiguous() {
    let law = SecretKeyDistr::Gaussian {
        standard_deviation: 25.0,
    };
    let context = BgvContext::try_with_levels(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(N),
            BarrettModulus::new(2),
            &[449, 577].map(BarrettModulus::new),
            law,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
        2,
    )
    .unwrap();
    assert_eq!(
        context
            .parameters()
            .encryption_parameters()
            .secret_key_sampler()
            .maximum_magnitude(),
        300
    );
    let mut coefficients = vec![0; N];
    coefficients[..2].copy_from_slice(&[249, -250]);
    let coeff = GlweSecretKey::new(
        coefficients.clone(),
        context.parameters().size().glwe_size(),
        law,
    );
    let mut client = BgvClient::try_from_secret_key(
        &context,
        DcrtGlweSecretKey::from_coeff_secret_key(&coeff, context.table()),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0x24b6_0005);
    // Actual |s_i|=250 exceeds the auxiliary prime 193; exact residue encoding
    // is valid and must not inherit the old bounded GLWE conversion restriction.
    let parameters = context.hybrid_key_parameters(0, 2, &[193]).unwrap();
    let key = client
        .key_switching_key(&client, 0, parameters, &mut rng)
        .unwrap();
    let mut input = context.new_ciphertext(0);
    let len = context.rns_poly_len(0);
    input.as_mut()[len..].fill(1); // c1=1 in NTT.
    let mut output = context.new_ciphertext(0);
    BgvKeySwitcher::try_new(&context, &key)
        .unwrap()
        .switch_to(&input, &mut output);
    let mut expected = vec![0; N];
    expected[0] = 1;
    assert_eq!(client.decrypt(&output, 0).as_ref(), expected);
    // A lower-level role still derives its actual secret from the complete
    // stored highest Q, even though active Q cannot disambiguate +/-250.
    client
        .relinearization_key(
            1,
            context.hybrid_key_parameters(1, 2, &[193]).unwrap(),
            &mut rng,
        )
        .unwrap();
    let ambiguous = BgvContext::try_new(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(N),
            BarrettModulus::new(2),
            &[449].map(BarrettModulus::new),
            law,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
    )
    .unwrap();
    let coeff = GlweSecretKey::new(coefficients, ambiguous.parameters().size().glwe_size(), law);
    let client = BgvClient::try_from_secret_key(
        &ambiguous,
        DcrtGlweSecretKey::from_coeff_secret_key(&coeff, ambiguous.table()),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0x24b6_bad3);
    let mut expected = StdRng::seed_from_u64(0x24b6_bad3);
    assert!(matches!(
        client.relinearization_key(
            0,
            ambiguous.hybrid_key_parameters(0, 1, &[193]).unwrap(),
            &mut rng
        ),
        Err(primus_bgv::BgvEvaluationKeyError::Hybrid(
            primus_lattice::hybrid::NativeHybridError::AmbiguousSecret { bound: 300 }
        ))
    ));
    assert_eq!(rng.next_u64(), expected.next_u64());
}
