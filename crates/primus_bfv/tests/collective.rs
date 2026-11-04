//! Collective public boundaries and normal native-key consumers.
use primus_bfv::*;
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;
use primus_poly::{DcrtPolynomial, Polynomial};
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 32;
const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];
fn context(n: usize) -> BfvContext {
    BfvContext::try_with_levels(
        BfvParameters::try_with_error_distribution(
            PolyLength::new(n),
            BarrettModulus::new(257),
            BarrettModulus::new((1 << 61) - 1),
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
fn phase(
    context: &BfvContext,
    clients: &[BfvClient<'_>],
    ct: &BfvCiphertext<Vec<u64>>,
    level: usize,
) -> Vec<u64> {
    let n = context.parameters().poly_length().get();
    let len = context.rns_poly_len(level);
    let mut output = ct.as_ref()[..len].to_vec();
    let mut partial = DcrtPolynomial(vec![0; len]);
    for client in clients {
        client.partial_phase_to(ct, level, &mut partial).unwrap();
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
    let mut rng = StdRng::seed_from_u64(0x15bf00);
    let clients: Vec<_> = (0..3)
        .map(|_| BfvClient::generate(&context, &mut rng))
        .collect();
    let target: Vec<_> = (0..3)
        .map(|_| BfvClient::generate(&context, &mut rng))
        .collect();
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
        BfvCollectiveSwitchingKey::try_new(&context, &context, 0, config(), &mut rng).unwrap();
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
    let auto = BfvCollectiveAutomorphismKey::try_new(&context, 0, 5, config(), &mut rng).unwrap();
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
    let plan = BfvCollectiveRelinearization::try_new(&context, 0, config(), &mut rng).unwrap();
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

#[test]
fn checked_payloads_instances_levels_and_own_share_embedding() {
    let context = context(N);
    let mut rng = StdRng::seed_from_u64(0x15bf01);
    let client = BfvClient::generate(&context, &mut rng);
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
    let mut partial = DcrtPolynomial(vec![42; context.rns_poly_len(0)]);
    assert!(
        client
            .partial_phase_to(&BfvCiphertext::zero(1), 0, &mut partial)
            .is_err()
    );
    assert!(partial.as_ref().iter().all(|&x| x == 42));
    assert!(
        client
            .partial_phase_to(&context.new_ciphertext(0), 3, &mut partial)
            .is_err()
    );
    let large = crate::context(2 * N);
    let embedded = client.try_embed_secret(&large).unwrap();
    assert!(std::ptr::eq(embedded.context(), &large));
    assert!(client.try_embed_secret(&context).is_err());
    // A fresh lookup is prepared from its independent setup and consumes both
    // its key and raw aggregate. The all-zero tensor has exact zero output.
    let key = {
        let plan = BfvCollectiveRelinearization::try_new(&context, 1, config(), &mut rng).unwrap();
        let (msg, state) = plan.start(&client, &mut rng).unwrap();
        let mut sum = plan.aggregate(1).unwrap();
        sum.add(&msg).unwrap();
        let r1 = plan.freeze_round1(sum).unwrap();
        let msg = state.round2(&r1, &mut rng).unwrap();
        let mut sum = r1.aggregate(1).unwrap();
        sum.add(&msg).unwrap();
        r1.finalize_lookup(sum).unwrap()
    };
    // The final owner retains no setup/R1 workspace.
    let lookup = key.prepare(&context).unwrap();
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
