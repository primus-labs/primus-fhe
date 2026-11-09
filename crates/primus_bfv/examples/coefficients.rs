//! Basic BFV coefficients: public encryption, plaintext addition/multiplication and recovery.
//! Run: cargo run -p primus_bfv --example coefficients

use primus_bfv::evaluation::BfvEvaluator;
use primus_bfv::{
    BfvClient, BfvContext, BfvParameters, ErrorDistribution, PlaintextEmbedding, SecretKeyDistr,
};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 32;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Small functional parameters, not a security preset.
    let parameters = BfvParameters::try_coefficients(
        PolyLength::new(N),
        BarrettModulus::new(193),
        &[1_125_899_906_826_241, 1_125_899_906_629_633].map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::Gaussian {
            standard_deviation: 0.849,
        },
    )?;
    let context = BfvContext::try_new(parameters)?;
    let mut rng = StdRng::seed_from_u64(0x12bf_c0ef);
    let mut client = BfvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let mut evaluator = BfvEvaluator::new(&context, 0);

    // Reuse setup, evaluator and output buffers; encryption/recovery conveniences
    // allocate their returned values. No evaluation keys are needed here.
    let mut input = context.new_plaintext();
    let mut scalar_plaintext = context.new_plaintext();
    let mut encrypted = context.new_ciphertext(0);

    // Reuse the prepared operations and buffers with fresh encryption coins.
    let embedding = PlaintextEmbedding::Centered;
    for scalar in [7, 11] {
        input.as_mut()[..3].copy_from_slice(&[1, 2, 3]);
        encryptor.encrypt_centered_to(&input, &mut encrypted, &mut rng);
        scalar_plaintext.as_mut()[0] = 1;
        evaluator.add_plain_assign(&mut encrypted, &scalar_plaintext, embedding);
        scalar_plaintext.as_mut()[0] = scalar;
        evaluator.mul_plain_assign(&mut encrypted, &scalar_plaintext, embedding);
        client.decrypt_to(&encrypted, &mut input);
        assert_eq!(input.as_ref()[..3], [2 * scalar, 2 * scalar, 3 * scalar]);
        assert!(input.as_ref()[3..].iter().all(|&value| value == 0));
    }
    println!("BFV: reused one setup to evaluate scalar * ((1 + 2X + 3X²) + 1) for 7 and 11");
    Ok(())
}
