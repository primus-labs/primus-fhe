//! Use CBS to choose an encrypted fee vector, add encrypted extra fees, and return one fee as LWE.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_fourier --example fourier_circuit_bootstrap`
//! Add `-- --split-trace` to select Split(35) trace keys for extra Fourier precision
//! (requires the default-enabled `split-trace` feature).
//! To use TfheFftTable alone, switch the Table import and this target's
//! required-features to tfhe-fft, then add `--no-default-features --features tfhe-fft,split-trace`.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_fft::RustFftTable as Table;
use primus_tfhe_glwe_fourier::FourierTracePrecision;
use primus_tfhe_glwe_fourier::{Evaluator, TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

type Word = u64;

fn main() {
    let mut config = experimental::CLASSIC_CBS_U64;
    // Select only trace precision; clients, CBS and CMux stay the same.
    if std::env::args().any(|arg| arg == "--split-trace") {
        config.fourier_trace_precision = FourierTracePrecision::Split35;
    }
    let context = TfheContext::<Word, Table>::try_from_cbs_config(config).unwrap();
    let poly_length = config.pbs.bsk_poly_length.get();

    // Client: keep client_key secret; give only server_key to the server.
    // Keygen includes BR, CBS and the return KS material.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    let encryptor = context
        .cbs_encryptor(client_key.external_lwe_secret_key())
        .unwrap();
    let mut ring_client = context
        .accumulator_client(client_key.glwe_secret_key(), 8)
        .unwrap();

    // Client: repeat short fee patterns across all N polynomial coefficients.
    // These are coefficient messages, not independent SIMD slots. Candidate
    // Scaled t_ring=8 is separate from the CBS control's gadget scale.
    let fees_a: Vec<Word> = [1, 0, 2, 1].into_iter().cycle().take(poly_length).collect();
    let fees_b: Vec<Word> = [3, 1, 0, 2].into_iter().cycle().take(poly_length).collect();
    let extra_fees: Vec<Word> = [0, 1, 1, 0].into_iter().cycle().take(poly_length).collect();
    let a = ring_client.encrypt(&fees_a, &mut rng);
    let b = ring_client.encrypt(&fees_b, &mut rng);
    let extra = ring_client.encrypt(&extra_fees, &mut rng);
    let mut input = context.allocate_lwe_ciphertext();
    let decryptor = context
        .ring_return_decryptor(client_key.external_lwe_secret_key(), 8)
        .unwrap();
    let mut returned = context.allocate_lwe_ciphertext();

    // Server, offline: receive encrypted fees; compile the predicate and prepare buffers.
    // F(m)=[m>=2] is a bit throughout the padded input domain 0..4.
    let program = context.compile_cbs_fn(|m| Word::from(m >= 2)).unwrap();
    let cbs = context
        .circuit_bootstrap_evaluator_with_lookup_table(&server_key, program)
        .unwrap();
    let mut control = cbs.allocate_output();
    // Move the existing BR/transform workspace into the LWE-return evaluator.
    // CBS borrows it for each operation; no second BR workspace is allocated.
    let (mut cbs, resources) = cbs.into_parts();
    let mut evaluator = Evaluator::try_from_resources(resources, server_key.server_key()).unwrap();
    let mut selected = context.allocate_accumulator_ciphertext();
    // Use the candidate ring modulus for the subsequent ciphertext addition.
    let ring_modulus = context.parameters().ring_modulus();

    println!("fees = (m >= 2 ? B : A) + extra");
    for message in [0, 1, 2, 3] {
        // Client -> server: send a padded encrypted integer in 0..4.
        encryptor
            .encrypt_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server, online: CBS computes the predicate; CMux chooses B when true.
        cbs.circuit_bootstrap_to(
            input.as_view(),
            &mut control,
            evaluator.bootstrap_resources_mut(),
        );
        cbs.cmux_to(
            &control,
            &a,
            &b,
            &mut selected,
            evaluator.bootstrap_resources_mut(),
        );
        selected.add_assign(&extra, ring_modulus);

        // Server -> client: return a chosen coefficient, not the whole ring ciphertext.
        let index = 2;
        evaluator.return_ring_at_to(selected.as_view(), index, returned.as_mut_view());
        // Client: decode the returned fee with the original t_ring=8.
        let fee = decryptor.decrypt(returned.as_view()).unwrap();
        let chosen_fees = if message >= 2 { &fees_b } else { &fees_a };
        assert_eq!(fee, chosen_fees[index] + extra_fees[index]);
        println!("m={message}: fee[{index}]={fee}");
    }
}
