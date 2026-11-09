//! Collective public boundaries and normal native-key consumers.
use primus_bfv::collective::{
    BfvCollectiveAutomorphismKey, BfvCollectiveError, BfvCollectiveLookup, BfvCollectivePublicKey,
    BfvCollectiveRelinearization, BfvCollectiveSwitchingKey, BfvRawQuadraticAggregate,
    raw_unflooded_partial_phase_to,
};
use primus_bfv::evaluation::{BfvAutomorphism, BfvKeySwitcher, BfvMultiplication, BfvRelinearizer};
use primus_bfv::keys::BfvEvaluationKeyConfig;
use primus_bfv::{BfvCiphertext, BfvClient, BfvContext, BfvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;
use primus_poly::{DcrtPolynomial, Polynomial};
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};

const N: usize = 32;
const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];
fn context(n: usize) -> BfvContext {
    BfvContext::try_with_levels(
        BfvParameters::try_coefficients(
            PolyLength::new(n),
            BarrettModulus::new(257),
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
        log_basis: DecompositionBaseLog::new(10),
        level_count: None,
    }
}
fn share(context: &BfvContext, rng: &mut StdRng) -> DcrtGlweSecretKey<u64> {
    let coefficient = GlweSecretKey::generate(
        context.parameters().size().glwe_size(),
        context
            .parameters()
            .encryption_parameters()
            .secret_key_sampler(),
        rng,
    );
    DcrtGlweSecretKey::from_coeff_secret_key(&coefficient, context.table())
}

fn phase(
    context: &BfvContext,
    clients: &[DcrtGlweSecretKey<u64>],
    ct: &BfvCiphertext<Vec<u64>>,
    level: usize,
) -> Vec<u64> {
    let n = context.parameters().poly_length().get();
    let len = context.rns_poly_len(level);
    let mut output = ct.as_ref()[..len].to_vec();
    let mut partial = DcrtPolynomial(vec![0; len]);
    for client in clients {
        partial.as_mut().copy_from_slice(&ct.as_ref()[len..]);
        let key = client.iter_dcrt_poly().next().unwrap();
        partial.mul_assign(
            &DcrtPolynomial(&key.as_ref()[..len]),
            n,
            context.codec(level).base_q().moduli(),
        );
        for ((out, input), &q) in output
            .chunks_exact_mut(n)
            .zip(partial.as_ref().chunks_exact(n))
            .zip(context.codec(level).moduli_values())
        {
            for (x, &y) in out.iter_mut().zip(input) {
                *x = ((*x as u128 + y as u128) % q as u128) as u64;
            }
        }
    }
    for (table, limb) in context.table().iter().zip(output.chunks_exact_mut(n)) {
        table.inverse_transform_slice(limb);
    }
    output
}
fn decode(context: &BfvContext, mut phase: Vec<u64>, level: usize) -> Vec<u64> {
    let n = context.parameters().poly_length().get();
    let codec = context.codec(level);
    let mut output = Polynomial(vec![0; n]);
    let mut scratch = vec![0; codec.decode_scratch_len(n)];
    codec.decode_coeffs_to(
        &mut primus_poly::CrtPolynomial(&mut phase),
        &mut output,
        &mut scratch,
    );
    output.0
}

#[test]
fn collective_keys_feed_existing_native_consumers_without_aggregate_secret() {
    let context = context(N);
    for hybrid in [false, true] {
        let config: BfvEvaluationKeyConfig = if hybrid {
            context
                .hybrid_key_parameters(
                    0,
                    2,
                    &[1_152_921_504_606_830_593, 1_152_921_504_606_748_673],
                )
                .unwrap()
                .into()
        } else {
            context.radix_key_parameters(0, config()).unwrap().into()
        };
        let mut rng = StdRng::seed_from_u64(0x15bf00);
        let clients: Vec<_> = (0..3).map(|_| share(&context, &mut rng)).collect();
        let target: Vec<_> = (0..3).map(|_| share(&context, &mut rng)).collect();
        let public = BfvCollectivePublicKey::try_new(&context, &mut rng).unwrap();
        let mut sum = public.aggregate(3).unwrap();
        for client in &clients {
            sum.add(&public.contribute(client, &mut rng).unwrap())
                .unwrap();
        }
        let pk = public.finalize(sum).unwrap();
        let mut encryptor = context.public_key_encryptor(&pk).unwrap();
        let message: Vec<_> = (0..N).map(|i| (i % 7) as u64).collect();
        let input = encryptor.encrypt(&Polynomial(&message), &mut rng);
        assert_eq!(
            decode(&context, phase(&context, &clients, &input, 0), 0),
            message
        );
        let switching =
            BfvCollectiveSwitchingKey::try_new(&context, 0, config.clone(), &mut rng).unwrap();
        let mut sum = switching.aggregate(3).unwrap();
        for (source, target) in clients.iter().zip(&target) {
            sum.add(&switching.contribute(source, target, &mut rng).unwrap())
                .unwrap();
        }
        let key = switching.finalize(sum).unwrap();
        let mut evaluator = BfvKeySwitcher::try_new(&context, &key).unwrap();
        let mut output = context.new_ciphertext(0);
        evaluator.switch_to(&input, &mut output);
        assert_eq!(
            decode(&context, phase(&context, &target, &output, 0), 0),
            message
        );
        let auto = BfvCollectiveAutomorphismKey::try_new(&context, 0, 5, config.clone(), &mut rng)
            .unwrap();
        let mut sum = auto.aggregate(3).unwrap();
        for client in &clients {
            sum.add(&auto.contribute(client, &mut rng).unwrap())
                .unwrap();
        }
        let key = auto.finalize(sum).unwrap();
        BfvAutomorphism::try_new(&context, &key)
            .unwrap()
            .apply_to(&input, &mut output);
        let mut expected = vec![0; N];
        for (i, &value) in message.iter().enumerate() {
            let exponent = i * 5;
            expected[exponent % N] = if (exponent / N).is_multiple_of(2) {
                value
            } else {
                (257 - value) % 257
            };
        }
        assert_eq!(
            decode(&context, phase(&context, &clients, &output, 0), 0),
            expected
        );
        let plan =
            BfvCollectiveRelinearization::try_new(&context, 0, config.clone(), &mut rng).unwrap();
        let mut sum = plan.aggregate(3).unwrap();
        let mut states = Vec::new();
        for client in &clients {
            let (message, state) = plan.start(client, &mut rng).unwrap();
            sum.add(&message).unwrap();
            states.push(state);
        }
        let round1 = plan.freeze_round1(sum).unwrap();
        assert!(round1.aggregate(2).is_err());
        let mut sum = round1.aggregate(3).unwrap();
        for state in states {
            sum.add(&state.round2(&round1, &mut rng).unwrap()).unwrap();
        }
        let key = round1.finalize(sum).unwrap();
        let mut quadratic = context.new_quadratic_ciphertext(0);
        quadratic.as_mut()[..input.as_ref().len()].copy_from_slice(input.as_ref());
        BfvRelinearizer::try_new(&context, &key)
            .unwrap()
            .relinearize_to(&quadratic, &mut output);
        assert_eq!(
            decode(&context, phase(&context, &clients, &output, 0), 0),
            message
        );
        let mut multiplication = BfvMultiplication::try_new(&context, &key).unwrap();
        multiplication.square_to(&input, &mut output);
        let mut expected = vec![0i64; N];
        for (i, &a) in message.iter().enumerate() {
            for (j, &b) in message.iter().enumerate() {
                let term = (a * b) as i64;
                expected[(i + j) % N] += if i + j < N { term } else { -term };
            }
        }
        let expected: Vec<_> = expected
            .into_iter()
            .map(|x| x.rem_euclid(257) as u64)
            .collect();
        assert_eq!(
            decode(&context, phase(&context, &clients, &output, 0), 0),
            expected
        );
    }
}

#[test]
fn checked_payloads_instances_levels_and_own_share_embedding() {
    let context = context(N);
    let mut rng = StdRng::seed_from_u64(0x15bf01);
    let client = share(&context, &mut rng);
    let prepared_at_level_one = context.radix_key_parameters(1, config()).unwrap();
    let mut request_rng = StdRng::seed_from_u64(0x17_bf_02);
    let mut expected_rng = StdRng::seed_from_u64(0x17_bf_02);
    assert!(
        BfvCollectiveSwitchingKey::try_new(&context, 0, prepared_at_level_one, &mut request_rng)
            .is_err()
    );
    assert_eq!(request_rng.next_u64(), expected_rng.next_u64());
    let a = BfvCollectivePublicKey::try_new(&context, &mut rng).unwrap();
    let b =
        BfvCollectivePublicKey::try_from_common_mask(&context, a.common_mask().to_vec()).unwrap();
    let msg = a.contribute(&client, &mut rng).unwrap();
    let mut sum = b.aggregate(1).unwrap();
    assert!(sum.add(&msg).is_err());
    sum.add(
        &b.try_import_contribution(msg.as_residues().to_vec())
            .unwrap(),
    )
    .unwrap();
    b.finalize(sum).unwrap();
    assert!(a.aggregate(0).is_err());
    assert!(a.finalize(a.aggregate(1).unwrap()).is_err());
    assert!(a.try_import_contribution(vec![0; 1]).is_err());
    let mut bad = vec![0; context.rns_poly_len(0)];
    bad[0] = Q[0];
    assert!(a.try_import_contribution(bad).is_err());
    let client_owner = BfvClient::try_from_secret_key(&context, client).unwrap();
    let mut partial = DcrtPolynomial(vec![42; context.rns_poly_len(0)]);
    assert!(
        raw_unflooded_partial_phase_to(&client_owner, &BfvCiphertext::zero_raw(1), 0, &mut partial)
            .is_err()
    );
    assert!(partial.as_ref().iter().all(|&x| x == 42));
    assert!(
        raw_unflooded_partial_phase_to(&client_owner, &context.new_ciphertext(0), 3, &mut partial)
            .is_err()
    );
    let client = client_owner.into_secret_key();
    let large = crate::context(2 * N);
    let embedded = large.try_embed_secret_from(&context, &client).unwrap();
    embedded
        .validate_parameters(
            large.parameters().size(),
            large.parameters().base_q().moduli(),
        )
        .unwrap();
    let source = client.iter_dcrt_poly().next().unwrap();
    let destination = embedded.iter_dcrt_poly().next().unwrap();
    for ((source, destination), (source_table, destination_table)) in source
        .as_ref()
        .as_chunks::<N>()
        .0
        .iter()
        .zip(destination.as_ref().as_chunks::<{ 2 * N }>().0)
        .zip(context.table().iter().zip(large.table().iter()))
    {
        let mut source = source.to_vec();
        let mut destination = destination.to_vec();
        source_table.inverse_transform_slice(&mut source);
        destination_table.inverse_transform_slice(&mut destination);
        for i in 0..N {
            assert_eq!(destination[2 * i], source[i]);
            assert_eq!(destination[2 * i + 1], 0);
        }
    }
    let unsupported = DcrtGlweSecretKey::from_coeff_secret_key(
        &GlweSecretKey::new(
            vec![2i64; N],
            context.parameters().size().glwe_size(),
            SecretKeyDistr::SparseTernary,
        ),
        context.table(),
    );
    assert!(large.try_embed_secret_from(&context, &unsupported).is_err());
    assert!(context.try_embed_secret_from(&context, &client).is_err());
    // Raw keys preserve numerical geometry checks before RNG. Their actual
    // NTT provenance remains a generation/import contract, not pointer identity.
    let foreign_context = crate::context(2 * N);
    let foreign = share(&foreign_context, &mut rng);
    let switching = BfvCollectiveSwitchingKey::try_new(&context, 0, config(), &mut rng).unwrap();
    for (source, target) in [(&foreign, &client), (&client, &foreign)] {
        let mut request_rng = StdRng::seed_from_u64(0x17_bf_01);
        let mut expected_rng = StdRng::seed_from_u64(0x17_bf_01);
        assert!(matches!(
            switching.contribute(source, target, &mut request_rng),
            Err(BfvCollectiveError::Binding)
        ));
        assert_eq!(request_rng.next_u64(), expected_rng.next_u64());
    }
    // A fresh lookup is prepared from its independent setup and consumes both
    // its key and raw aggregate. The all-zero tensor has exact zero output.
    let key = {
        let plan = BfvCollectiveLookup::try_new(&context, 1, config(), &mut rng).unwrap();
        let (msg, state) = plan.start(&client, &mut rng).unwrap();
        let mut sum = plan.aggregate(1).unwrap();
        sum.add(&msg).unwrap();
        let mut replay = plan.aggregate(1).unwrap();
        replay.add(&msg).unwrap();
        let r1 = plan.freeze_round1(sum).unwrap();
        assert!(matches!(
            plan.freeze_round1(replay),
            Err(BfvCollectiveError::ConsumedLookupSetup)
        ));
        r1.finalize_lookup(|r1| {
            let msg = state.round2(r1, &mut rng)?;
            let mut sum = r1.aggregate(1)?;
            sum.add(&msg)?;
            Ok::<_, BfvCollectiveError>(sum)
        })
        .unwrap()
    };
    // The final owner retains no setup/R1 workspace.
    assert!(core::ptr::eq(key.context(), &context));
    assert_eq!(key.level(), 1);
    let lookup = key.prepare();
    let mut output = context.new_ciphertext(1);
    lookup
        .apply_to(
            BfvRawQuadraticAggregate::try_new(&context, 1, vec![0; 3 * context.rns_poly_len(1)])
                .unwrap(),
            &mut output,
        )
        .unwrap();
    assert!(output.as_ref().iter().all(|&x| x == 0));
}

#[test]
fn relinearization_state_and_bodies_stay_bound_to_their_round_and_role() {
    let context = context(N);
    let mut rng = StdRng::seed_from_u64(0x05_bf21);
    let owners = [share(&context, &mut rng), share(&context, &mut rng)];
    let level = 1;
    for config in [
        BfvEvaluationKeyConfig::from(config()),
        context
            .hybrid_key_parameters(level, 1, &[1_099_511_626_049])
            .unwrap()
            .into(),
    ] {
        let plan = BfvCollectiveRelinearization::try_new(&context, level, config.clone(), &mut rng)
            .unwrap();
        let other = BfvCollectiveRelinearization::try_from_common_mask(
            &context,
            level,
            config.clone(),
            plan.common_mask().to_vec(),
        )
        .unwrap();
        let (message, state) = plan.start(&owners[0], &mut rng).unwrap();
        let mut other_sum = other.aggregate(2).unwrap();
        assert!(matches!(
            other_sum.add(&message),
            Err(BfvCollectiveError::Binding)
        ));
        let mut pending = Vec::new();
        for owner in &owners {
            let (message, state) = other.start(owner, &mut rng).unwrap();
            let received = other
                .try_import_contribution(message.into_residues())
                .unwrap();
            other_sum.add(&received).unwrap();
            pending.push(state);
        }
        let round1 = other.freeze_round1(other_sum).unwrap();
        let mut rejected_rng = StdRng::seed_from_u64(0x05_bf22);
        let mut untouched_rng = StdRng::seed_from_u64(0x05_bf22);
        assert!(matches!(
            state.round2(&round1, &mut rejected_rng),
            Err(BfvCollectiveError::Binding)
        ));
        assert_eq!(rejected_rng.next_u64(), untouched_rng.next_u64());
        assert!(matches!(
            round1.aggregate(1),
            Err(BfvCollectiveError::Count)
        ));

        let switching =
            BfvCollectiveSwitchingKey::try_new(&context, level, config, &mut rng).unwrap();
        let mut switch_sum = switching.aggregate(2).unwrap();
        let mut round2_sum = round1.aggregate(2).unwrap();
        for state in pending {
            let message = state.round2(&round1, &mut rng).unwrap();
            assert_eq!(message.as_residues().len(), switching.contribution_len());
            assert!(matches!(
                switch_sum.add(&message),
                Err(BfvCollectiveError::Binding)
            ));
            round2_sum.add(&message).unwrap();
        }
        let key = round1.finalize(round2_sum).unwrap();
        assert!(BfvRelinearizer::try_new(&context, &key).is_ok());
    }
}
