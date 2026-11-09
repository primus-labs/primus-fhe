//! An MSB Boolean revocation bit selects an encrypted vector of service limits.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_fourier --example fourier_msb_cbs`
//! The experimental arithmetic config is not a certified security/DFR preset.

use primus_fft::RustFftTable as Table;
use primus_tfhe_glwe_fourier::{CbsInputEncoding, TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

type Word = u64;

fn main() {
    let mut config = experimental::CLASSIC_CBS_U64;
    config.input_encoding = CbsInputEncoding::MsbBoolean;
    let n = config.pbs.bsk_poly_length.get();
    let context = TfheContext::<Word, Table>::try_from_cbs_config(config).unwrap();

    // Client: only server_key and encrypted inputs leave this side. CBS uses
    // 0 / round(q_external/2); ordinary context.encryptor retains PBS's t=8.
    let mut rng = StdRng::seed_from_u64(42);
    let (client, server) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    let encryptor = context
        .cbs_encryptor(client.external_lwe_secret_key())
        .unwrap();
    let mut ring_client = context
        .accumulator_client(client.glwe_secret_key(), 8)
        .unwrap();
    let limited: Vec<Word> = [1, 0, 1, 0].into_iter().cycle().take(n).collect();
    let full: Vec<Word> = [3, 2, 1, 3].into_iter().cycle().take(n).collect();
    let a = ring_client.encrypt(&limited, &mut rng);
    let b = ring_client.encrypt(&full, &mut rng);
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![0; n];

    // Server, offline: NOT turns the revoked bit into an allowed GGSW control.
    // Program compilation owns the MSB sign LUT and trace correction.
    let program = context
        .compile_cbs_fn(|revoked| 1 - revoked as Word)
        .unwrap();
    let mut evaluator = context
        .circuit_bootstrap_evaluator_with_lookup_table(&server, program)
        .unwrap();
    let mut control = evaluator.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();
    for revoked in [0, 1] {
        // Client -> server. The same method also serves padded CBS configurations.
        encryptor
            .encrypt_to(revoked, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server, online: both the predicate and selected vector remain encrypted.
        evaluator.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
        evaluator.cmux_to(
            control.as_view(),
            a.as_view(),
            b.as_view(),
            selected.as_mut_view(),
        );

        // Client: recover only the final service limits. These are polynomial
        // coefficient messages, not independent SIMD slots.
        ring_client.decrypt_to(&selected, &mut decoded);
        assert_eq!(
            decoded,
            if revoked == 0 { &full } else { &limited }.as_slice()
        );
        println!("revoked={revoked}: limits={:?}", &decoded[..4]);
    }
}
