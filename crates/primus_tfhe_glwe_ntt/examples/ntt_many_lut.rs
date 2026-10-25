//! Compute grade and flag with one ManyLUT, then combine their encrypted outputs.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_ntt --example ntt_many_lut`
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_ntt::U64NttTable as Table;
use primus_tfhe_glwe_ntt::{PbsMessageConfig, TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

type Word = u64;

fn main() {
    // Rounded input t=16 (padded 0..8), output t=8: the domains are independent.
    let config = experimental::CLASSIC_MANY_LUT_U64;
    let context = TfheContext::<Word, Table>::try_from_pbs_config(config).unwrap();

    // Client: keep client_key secret; give only server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.try_generate_keys(&mut rng).unwrap();
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret).unwrap();
    let decryptor = context.pbs_decryptor(external_secret).unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server, offline: interleave grade=x/2 and flag=[x>=5] in one LUT.
    // Both outputs share one blind rotation and use the configured t_out=8.
    let compiler = context.pbs_lookup_table_compiler().unwrap();
    let lut = compiler
        .compile_interleaved_fn(2, |x, lane| {
            if lane == 0 {
                (x / 2) as Word
            } else {
                Word::from(x >= 5)
            }
        })
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut outputs = vec![context.allocate_lwe_ciphertext(); 2];
    let mut code = context.allocate_lwe_ciphertext();
    // Use the external LWE modulus for ciphertext arithmetic.
    let modulus = context.parameters().external_modulus();

    println!("grade = x/2; flag = [x >= 5]; code = 2*grade + flag (messages 16 -> 8)");
    for message in [0, 4, 5, 6] {
        // Client -> server: send one encrypted padded input.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server, online: outputs[0] is grade; outputs[1] is flag.
        evaluator.apply_interleaved_lookup_table_to(input.as_view(), &lut, &mut outputs);
        outputs[0].mul_scalar_to(2, &mut code, modulus);
        code.add_assign(&outputs[1], modulus);

        // Client: decode the final code <= 7 at t=8. It is not fed back to
        // input PBS, whose t=16 encoding differs from these outputs.
        let result = decryptor.decrypt(code.as_view()).unwrap();
        let expected = 2 * (message / 2) + Word::from(message >= 5);
        assert_eq!(result, expected);
        println!("x={message}: code={result}");
    }

    // Another service uses the same keys/context with Rounded messages 8→16.
    // Client: select matching input and output domains without building codecs.
    let messages = PbsMessageConfig::new(8).with_output_modulus(16);
    let encryptor = context
        .encryptor_with_message_modulus(external_secret, messages.input_modulus)
        .unwrap();
    let decryptor = context
        .pbs_decryptor_with_message_modulus(external_secret, messages.output_modulus)
        .unwrap();
    encryptor
        .encrypt_padded_to(3, input.as_mut_view(), &mut rng)
        .unwrap();

    // Server: compile the new price function; reuse the evaluator and output.
    let price_lut = context
        .pbs_lookup_table_compiler_with_messages(messages)
        .unwrap()
        .compile_fn(|x| (2 * x + 1) as Word)
        .unwrap();
    evaluator.apply_lookup_table_to(input.as_view(), &price_lut, code.as_mut_view());

    // Client: only the final ciphertext comes back.
    let price = decryptor.decrypt(code.as_view()).unwrap();
    assert_eq!(price, 7);
    println!("price = 2*x + 1 (messages 8 -> 16); x=3: price={price}");
}
