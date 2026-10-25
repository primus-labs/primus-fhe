//! Evaluate the encrypted access rule: admin OR (member AND NOT revoked).
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_ntt --example ntt_boolean`
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_ntt::U64NttTable as Table;
use primus_tfhe_glwe_ntt::{BooleanGate, PbsMessageConfig, TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

type Word = u64;

fn main() {
    // Boolean clients and gates require Rounded t=4 for both input and output.
    let mut config = experimental::CLASSIC_PBS_U64;
    config.messages = PbsMessageConfig::new(4);
    let context = TfheContext::<Word, Table>::try_from_pbs_config(config).unwrap();

    // Client: keep client_key secret; give only server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.try_generate_keys(&mut rng).unwrap();
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.boolean_encryptor(external_secret).unwrap();
    let decryptor = context.boolean_decryptor(external_secret).unwrap();
    let mut admin = context.allocate_lwe_ciphertext();
    let mut member = context.allocate_lwe_ciphertext();
    let mut revoked = context.allocate_lwe_ciphertext();

    // Server, offline: prepare gate LUTs, scratch and intermediate ciphertexts.
    let mut evaluator = context.boolean_evaluator(&server_key).unwrap();
    let mut not_revoked = context.allocate_lwe_ciphertext();
    let mut eligible = context.allocate_lwe_ciphertext();
    let mut allowed = context.allocate_lwe_ciphertext();

    println!("allowed = admin OR (member AND NOT revoked)");
    for (is_admin, is_member, is_revoked) in [
        (false, false, false),
        (false, true, false),
        (false, true, true),
        (true, false, true),
    ] {
        // Client -> server: encrypt the three independent Boolean inputs.
        encryptor
            .encrypt_to(is_admin, admin.as_mut_view(), &mut rng)
            .unwrap();
        encryptor
            .encrypt_to(is_member, member.as_mut_view(), &mut rng)
            .unwrap();
        encryptor
            .encrypt_to(is_revoked, revoked.as_mut_view(), &mut rng)
            .unwrap();

        // Server, online: NOT is affine; AND and OR each use one PBS.
        evaluator.not_to(revoked.as_view(), not_revoked.as_mut_view());
        evaluator.evaluate_binary_to(
            BooleanGate::And,
            member.as_view(),
            not_revoked.as_view(),
            eligible.as_mut_view(),
        );
        evaluator.evaluate_binary_to(
            BooleanGate::Or,
            admin.as_view(),
            eligible.as_view(),
            allowed.as_mut_view(),
        );

        // Client: decode only the final decision returned by the server.
        let result = decryptor.decrypt(allowed.as_view()).unwrap();
        assert_eq!(result, is_admin || (is_member && !is_revoked));
        println!("admin={is_admin}, member={is_member}, revoked={is_revoked}: allowed={result}");
    }
}
