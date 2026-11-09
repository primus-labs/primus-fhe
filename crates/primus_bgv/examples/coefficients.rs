//! Basic coefficient workflow: public encryption, plaintext +1 and scalar product.
//! Run: cargo run -p primus_bgv --example coefficients

use primus_bgv::evaluation::BgvEvaluator;
use primus_bgv::{
    BgvClient, BgvContext, BgvParameters, ErrorDistribution, PlaintextEmbedding, SecretKeyDistr,
};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const N: usize = 32;
    // Functional demonstration parameters, not a security preset.
    let moduli = [
        1_125_899_906_248_961,
        1_125_899_906_051_329,
        1_125_899_904_322_049,
    ]
    .map(BarrettModulus::new);
    let parameters = BgvParameters::try_coefficients(
        PolyLength::new(N),
        BarrettModulus::new(193),
        &moduli,
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::Gaussian {
            standard_deviation: 0.849,
        },
    )?;
    let context = BgvContext::try_new(parameters)?;
    let mut rng = StdRng::seed_from_u64(0x09b6_0001);
    let mut client = BgvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let mut evaluator = BgvEvaluator::new(&context, 0);
    let mut input = context.new_plaintext();
    let mut scalar_plaintext = context.new_plaintext();
    let mut encrypted = context.new_ciphertext(0);

    // Reuse the prepared operations and buffers with fresh encryption coins.
    let embedding = PlaintextEmbedding::Centered;
    for (message, scalar, answer) in [([3, 2], 7, [28, 14]), ([4, 1], 11, [55, 11])] {
        input.as_mut()[..2].copy_from_slice(&message);
        encryptor.encrypt_centered_to(&input, &mut encrypted, &mut rng);
        scalar_plaintext.as_mut()[0] = 1;
        evaluator.add_plain_assign(&mut encrypted, &scalar_plaintext, embedding);
        scalar_plaintext.as_mut()[0] = scalar;
        evaluator.mul_plain_assign(&mut encrypted, &scalar_plaintext, embedding);
        client.decrypt_to(&encrypted, &mut input);
        assert_eq!(input.as_ref()[..2], answer);
        assert!(input.as_ref()[2..].iter().all(|&value| value == 0));
    }
    println!("BGV: two coefficient requests recovered using one prepared setup");
    Ok(())
}
