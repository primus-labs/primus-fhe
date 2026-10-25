//! Two PBS calls with independent small-LWE q and ring Q, in either PBS order.
//! Run: `cargo run --release -p primus_tfhe_glwe_ntt --example ntt_two_moduli`
//! Demonstration parameters only; no security or failure-probability claim.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe::{GlweDimension, SecretKeyDistr};
use primus_lwe::LweDimension;
use primus_modulus::PowOf2Modulus;
use primus_ntt::U64NttTable;
use primus_shape::PolyLength;
use primus_tfhe_glwe_ntt::{
    BlindRotationMethod, DecompositionConfig, GadgetEncryptionConfig, LweConfig, ModulusConfig,
    PbsConfig, PbsMessageConfig, PbsOrder, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

fn main() {
    // Small controls live at q=1024; all ring keys and LUT coefficients use Q.
    // This G1-inspired geometry uses padded t=4, not the author's MSB encoding.
    let config = PbsConfig::<u64, PowOf2Modulus<u64>> {
        small_lwe: LweConfig {
            dimension: LweDimension::new(571),
            cipher_modulus: ModulusConfig::Explicit(1024),
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 3.2,
        },
        ring_modulus: ModulusConfig::Explicit(18_014_398_509_404_161),
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(2048),
        bsk_secret_distr: SecretKeyDistr::UniformBinary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(17),
                level_count: Some(DecompositionLevelCount::new(2)),
            },
            noise_standard_deviation: 3.2,
        },
        // Auxiliary ring-KS choice for this example, not an author parameter.
        key_switching: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(6)),
            },
            noise_standard_deviation: 3.2,
        },
        method: BlindRotationMethod::Classic,
        messages: PbsMessageConfig::new(4),
        order: PbsOrder::BootstrapKeyswitch,
    };
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context =
            TfheContext::<u64, U64NttTable, _>::try_from_pbs_config(PbsConfig { order, ..config })
                .unwrap();

        // Client: the context chooses (s,q) for BR→KS or (S,Q) for KS→BR.
        // Only server_key and encrypted inputs are sent to the server.
        let mut rng = StdRng::seed_from_u64(42);
        let (client_key, server_key) = context.try_generate_keys(&mut rng).unwrap();
        let secret = client_key.external_lwe_secret_key();
        let encryptor = context.encryptor(secret).unwrap();
        let decryptor = context.pbs_decryptor(secret).unwrap();

        // Server: compile once and reuse evaluator/output storage. No manual codec.
        let lut = context
            .pbs_lookup_table_compiler()
            .unwrap()
            .compile_fn(|m| 1 - m as u64)
            .unwrap();
        let mut evaluator = context.evaluator(&server_key).unwrap();
        let mut inverted = context.allocate_lwe_ciphertext();
        let mut restored = context.allocate_lwe_ciphertext();
        for message in [0, 1] {
            let input = encryptor.encrypt_padded(message, &mut rng).unwrap();
            evaluator.apply_lookup_table_to(input.as_view(), &lut, inverted.as_mut_view());
            evaluator.apply_lookup_table_to(inverted.as_view(), &lut, restored.as_mut_view());

            // Client: both returned ciphertexts stay in the order's external domain.
            assert_eq!(decryptor.decrypt(inverted.as_view()).unwrap(), 1 - message);
            assert_eq!(decryptor.decrypt(restored.as_view()).unwrap(), message);
            println!("{order:?}: {message} -> {} -> {message}", 1 - message);
        }
    }
}
