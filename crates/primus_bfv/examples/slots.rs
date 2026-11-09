//! Basic BFV slots: public encryption, plaintext addition/multiplication and recovery.
//! Run: cargo run -p primus_bfv --example slots --features batching

use primus_bfv::evaluation::BfvEvaluator;
use primus_bfv::{
    BfvClient, BfvContext, BfvParameters, ErrorDistribution, PlaintextEmbedding, SecretKeyDistr,
};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().nth(1).is_some() {
        return Err(
            "slots takes no options; see leveled_slots for encrypted multiplication/rotation"
                .into(),
        );
    }
    const N: usize = 32;
    const P: u64 = 193;
    // n=N: coefficients go directly into the plaintext polynomial.
    // These small functional parameters are not a security preset.
    let context = BfvContext::try_new(BfvParameters::try_coefficients(
        PolyLength::new(N),
        BarrettModulus::new(P),
        &[1_125_899_906_826_241, 1_125_899_906_629_633].map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::Gaussian {
            standard_deviation: 0.849,
        },
    )?)?;
    let batching = context.batching_encoder()?;
    let mut rng = StdRng::seed_from_u64(0x12bf_5107);
    let mut client = BfvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let mut evaluator = BfvEvaluator::new(&context, 0);

    // Encode directly into n=N plaintexts. Reuse the encoder and evaluator;
    // encryption, recovery and slot decoding conveniences allocate their results.
    let capacity = batching.slot_capacity();
    let values: Vec<_> = (1..=capacity as u64).collect();
    let mut message = context.new_plaintext();
    batching.encode_to(&values, message.as_mut());
    let mut offset = context.new_plaintext();
    batching.encode_to(&vec![1; capacity], offset.as_mut());
    let mut factors = vec![0; capacity];
    let mut factor = context.new_plaintext();
    let mut shifted = context.new_ciphertext(0);
    let mut product = context.new_ciphertext(0);
    for scalar in [3, 5] {
        factors.fill(scalar);
        batching.encode_to(&factors, factor.as_mut());
        let encrypted_message = encryptor.encrypt_centered(&message, &mut rng);
        evaluator.add_plain_to(
            &encrypted_message,
            &offset,
            &mut shifted,
            PlaintextEmbedding::Centered,
        );
        evaluator.mul_plain_to(
            &shifted,
            &factor,
            &mut product,
            PlaintextEmbedding::Centered,
        );
        let slots = batching.decode(client.decrypt(&product).as_ref());
        for (&actual, &value) in slots.iter().zip(&values) {
            assert_eq!(actual, scalar * (value + 1) % P);
        }
    }
    println!("BFV: reused one setup to evaluate scalar * (slots + 1) for 3 and 5");
    Ok(())
}
