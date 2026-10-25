//! Turn an encrypted score in 0..64 into 17 numeric threshold flags with one MVB.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_ntt --example ntru_ntt_mvb_thresholds`
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_ntt::U64NttTable as Table;
use primus_tfhe_ntru_ntt::{TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

// The paired experimental entry fixes u64 coefficients and the operation domains.
type Word = u64;

const DOMAIN: usize = 64;
const OUTPUTS: usize = 17;

fn main() {
    let config = experimental::CLASSIC_THRESHOLD_MVB_U64;
    let context = TfheContext::<Word, Table, _>::try_from_pbs_config(config).unwrap();

    // Numeric threshold flags use Scaled t=2; the input keeps Rounded t=128.
    let thresholds: Vec<_> = (1..=OUTPUTS).map(|i| i * DOMAIN / (OUTPUTS + 1)).collect();

    // Client: keep client_key and the decryptor; give server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.try_generate_keys(&mut rng).unwrap();
    // Clients borrow only the external secret; no LUT or codec is needed.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret).unwrap();
    let decryptor = context.mvb_decryptor(external_secret).unwrap();
    let mut input = context.allocate_lwe_ciphertext();
    let mut flags = [0; OUTPUTS];

    // Server: MVB keeps all 64 inputs; interleaving 17 outputs fits only 32 here.
    let program = context
        .compile_mvb_fn(DOMAIN, OUTPUTS, |score, i| {
            Word::from(score >= thresholds[i])
        })
        .unwrap();
    let mut evaluator = context.mvb_evaluator(&server_key).unwrap();
    let mut outputs = vec![context.allocate_lwe_ciphertext(); OUTPUTS];

    for score in [12, 45] {
        // Client -> server: send the encrypted score.
        encryptor
            .encrypt_padded_to(score, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server -> client: return one ciphertext per threshold, reusing all buffers.
        evaluator.apply_lookup_table_to(input.as_view(), &program, &mut outputs);

        // Client: decrypt with the agreed Scaled output codec.
        for (i, output) in outputs.iter().enumerate() {
            flags[i] = decryptor.decrypt(output.as_view()).unwrap();
            assert_eq!(flags[i], Word::from(score as usize >= thresholds[i]));
        }
        println!("score={score}, thresholds={thresholds:?}, flags={flags:?}");
    }
}
