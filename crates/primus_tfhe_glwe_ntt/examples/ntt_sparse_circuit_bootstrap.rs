//! Use sparse CBS to choose an encrypted fee vector, then add encrypted extra fees.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_ntt --example ntt_sparse_circuit_bootstrap`
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_ntt::U64NttTable as Table;
use primus_tfhe_glwe_ntt::{TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

type Word = u64;

fn main() {
    let config = experimental::SPARSE_CBS_U64;
    // Fixed-weight binary secret; three copies and 64 buckets for sparse BR.
    let context = TfheContext::<Word, Table>::try_from_cbs_config(config).unwrap();
    let poly_length = config.pbs.bsk_poly_length.get();

    // Client: keep client_key secret; give only server_key to the server.
    // Keygen includes BR, CBS and KS; this workflow consumes the ring result.
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
    let mut decoded = vec![0; poly_length];

    // Server, offline: receive encrypted fees; compile the predicate and prepare buffers.
    // F(m)=[m>=2] is a bit throughout the padded input domain 0..4.
    let program = context.compile_cbs_fn(|m| Word::from(m >= 2)).unwrap();
    let mut cbs = context
        .circuit_bootstrap_evaluator_with_lookup_table(&server_key, program)
        .unwrap();
    let mut control = cbs.allocate_output();
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
        cbs.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
        cbs.cmux_to(
            control.as_view(),
            a.as_view(),
            b.as_view(),
            selected.as_mut_view(),
        );
        selected.add_assign(&extra, ring_modulus);

        // Client: decrypt only the final fees and check all N coefficients.
        ring_client.decrypt_to(&selected, &mut decoded);
        let chosen_fees = if message >= 2 { &fees_b } else { &fees_a };
        for ((&result, &fee), &addition) in decoded.iter().zip(chosen_fees).zip(&extra_fees) {
            assert_eq!(result, fee + addition);
        }
        println!("m={message}: fees={:?}", &decoded[..4]);
    }
}
