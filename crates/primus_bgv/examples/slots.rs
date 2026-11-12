//! Basic full-ring slots: public encryption, plaintext +1 and slotwise scaling.
//! Run: cargo run -p primus_bgv --example slots --features batching

use primus_bgv::evaluation::BgvEvaluator;
use primus_bgv::{
    BgvClient, BgvContext, BgvParameters, ErrorDistribution, PlaintextEmbedding, SecretKeyDistr,
};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).is_some() {
        return Err(
            "this basic example takes no arguments; see ciphertext_multiplication for --hybrid"
                .into(),
        );
    }
    const N: usize = 32;
    const P: u64 = 193;
    // Functional demonstration parameters, not a security preset.
    let moduli = [
        1_125_899_906_248_961,
        1_125_899_906_051_329,
        1_125_899_904_322_049,
    ]
    .map(BarrettModulus::new);
    let parameters = BgvParameters::try_coefficients(
        PolyLength::new(N),
        BarrettModulus::new(P),
        &moduli,
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::Gaussian {
            standard_deviation: 0.849,
        },
    )?;
    let context = BgvContext::try_new(parameters)?;
    let batching = context.batching_encoder()?;
    let mut rng = StdRng::seed_from_u64(0x09b6_5107);
    let mut client = BgvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let mut evaluator = BgvEvaluator::new(&context, 0);
    let mut input = context.new_plaintext();
    let mut one = context.new_plaintext();
    let mut factor = context.new_plaintext();
    let mut output = context.new_ciphertext(0);
    let capacity = batching.slot_capacity();
    batching.encode_to(&[1; N], one.as_mut());

    // n=N: encode directly into context-owned plaintext shapes.
    // Both requests reuse the encoder, keys, evaluator and ciphertext output.
    for (offset, scalar) in [(0, 3), (1, 5)] {
        let values = (0..capacity).map(|i| i as u64 + offset).collect::<Vec<_>>();
        batching.encode_to(&values, input.as_mut());
        batching.encode_to(&[scalar; N], factor.as_mut());
        let mut encrypted = encryptor.encrypt_centered(&input, &mut rng);
        evaluator.add_plain_assign(&mut encrypted, &one, PlaintextEmbedding::Centered);
        evaluator.mul_plain_to(
            &encrypted,
            &factor,
            &mut output,
            PlaintextEmbedding::Centered,
        );
        let recovered = client.decrypt(&output);
        let slots = batching.decode(recovered.as_ref());
        let expected = values
            .iter()
            .map(|&value| (value + 1) * scalar % P)
            .collect::<Vec<_>>();
        assert_eq!(slots, expected);
    }
    println!("BGV: two packed requests recovered using one prepared setup");
    Ok(())
}
