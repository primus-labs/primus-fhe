//! Select one of four encrypted records using a two-bit input and one-hot CBS.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_ntt --example ntru_ntt_one_hot`
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_ntt::U64NttTable as Table;
use primus_tfhe_ntru_ntt::{TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

// The paired experimental entry fixes u64 coefficients and the operation domains.
type Word = u64;
const RECORDS: [[Word; 4]; 4] = [[0, 1, 2, 3], [1, 3, 0, 2], [3, 0, 1, 2], [2, 1, 3, 0]];

fn main() {
    let config = experimental::CLASSIC_ONE_HOT_U64;
    let context = TfheContext::<Word, Table, _>::try_from_cbs_config(config).unwrap();
    let poly_length = config.pbs.bsk_poly_length.get();

    // Client: keep the independent LWE/NTRU secrets; send server_key and encrypted records.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    // The selector is encrypted with the external LWE secret.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret).unwrap();

    // Candidate ring messages use their own t=8 space at accumulator Q.
    let mut ring_client = context
        .accumulator_client(client_key.accumulator_ntru_secret_key(), 8)
        .unwrap();
    // Repeat each record across coefficients; these are not independent SIMD slots.
    let candidates = RECORDS.map(|record| {
        let plaintext: Vec<_> = record.into_iter().cycle().take(poly_length).collect();
        ring_client.encrypt(&plaintext, &mut rng)
    });
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![0; poly_length];

    // Server: keep delta_1..delta_3 and one result; C0 is the default branch.
    let mut one_hot = context.one_hot_evaluator(&server_key).unwrap();
    let mut selectors = one_hot.allocate_nonzero_ngsw_output();
    let mut selected = context.allocate_accumulator_ciphertext();

    for message in [0, 1, 2, 3] {
        // Client -> server: one padded two-bit input; the server never sees message.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server: zero nonzero-branch controls choose C0; otherwise delta_r selects Cr.
        one_hot.one_hot_nonzero_ngsw_to(input.as_view(), &mut selectors);
        one_hot.cmux_k_to(
            one_hot.nonzero_ngsw_selectors(&selectors),
            candidates[0].as_view(),
            &candidates[1..],
            selected.as_mut_view(),
        );

        // Client: check every coefficient against the original record; print its prefix.
        ring_client.decrypt_to(&selected, &mut decoded);
        let expected = RECORDS[message as usize];
        assert!(
            decoded
                .iter()
                .zip(expected.iter().cycle())
                .all(|(actual, expected)| actual == expected)
        );
        println!("input {message}: selected record {:?}", &decoded[..4]);
    }
}
