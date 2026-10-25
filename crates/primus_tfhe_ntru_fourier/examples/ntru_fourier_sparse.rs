//! Combine two encrypted inputs and apply two successive LUTs with sparse PBS.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_fourier --example ntru_fourier_sparse`
//! To use TfheFftTable alone, switch the Table import and this target's
//! required-features to tfhe-fft, then add `--no-default-features --features tfhe-fft`.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_fft::RustFftTable as Table;
use primus_tfhe_ntru_fourier::{TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

type Word = u64;

fn main() {
    // Rounded t=32 for both input and output lets the first PBS feed the next.
    let config = experimental::SPARSE_PBS_U64;
    // Sparse BR uses a fixed-weight secret, three copies and 64 buckets.
    let context = TfheContext::<Word, Table, _>::try_from_pbs_config(config).unwrap();

    // Client: keep client_key secret; give only server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.try_generate_keys(&mut rng).unwrap();
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret).unwrap();
    let decryptor = context.pbs_decryptor(external_secret).unwrap();
    let mut x_input = context.allocate_lwe_ciphertext();
    let mut y_input = context.allocate_lwe_ciphertext();

    // Server, offline: compile the public functions and prepare reusable buffers.
    let compiler = context.pbs_lookup_table_compiler().unwrap();
    let score_lut = compiler.compile_fn(|z| z.min(6) as Word).unwrap();
    let price_lut = compiler
        .compile_fn(|score| (2 * score + usize::from(score >= 4)) as Word)
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut combined = context.allocate_lwe_ciphertext();
    let mut score = context.allocate_lwe_ciphertext();
    let mut price = context.allocate_lwe_ciphertext();
    // LWE arithmetic uses external q, not the accumulator ring modulus Q.
    let modulus = context.parameters().external_lwe().cipher_modulus();

    println!("score = min(2*x + y, 6); price = 2*score + [score >= 4]");
    for (x, y) in [(0, 0), (1, 1), (2, 1), (3, 3)] {
        // Client -> server: padded inputs x,y in 0..4.
        encryptor
            .encrypt_padded_to(x, x_input.as_mut_view(), &mut rng)
            .unwrap();
        encryptor
            .encrypt_padded_to(y, y_input.as_mut_view(), &mut rng)
            .unwrap();

        // Server, online: 2*x+y <= 9 and score <= 6 stay in padded 0..16.
        // Feedback also carries the first PBS's noise; equal domains alone are
        // insufficient for arbitrary chains. These parameters serve this workload.
        x_input.mul_scalar_to(2, &mut combined, modulus);
        combined.add_assign(&y_input, modulus);
        evaluator.apply_lookup_table_to(combined.as_view(), &score_lut, score.as_mut_view());
        evaluator.apply_lookup_table_to(score.as_view(), &price_lut, price.as_mut_view());

        // Client: decode only the final ciphertext returned by the server.
        let result = decryptor.decrypt(price.as_view()).unwrap();
        let expected_score = (2 * x + y).min(6);
        let expected = 2 * expected_score + Word::from(expected_score >= 4);
        assert_eq!(result, expected);
        println!("x={x}, y={y}: price={result}");
    }
}
