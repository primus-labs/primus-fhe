//! Basic coefficient workflow: public encryption, plaintext +1 and scalar product.
//! Run: cargo run -p primus_bgv --example coefficients

use primus_bgv::{BgvClient, BgvContext, BgvEvaluator, BgvParameters, PlaintextEmbedding};
use primus_glwe_rns::SecretKeyDistr;
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
        0.849,
    )?;
    let context = BgvContext::try_new(parameters)?;
    let mut rng = StdRng::seed_from_u64(0x09b6_0001);
    let mut client = BgvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let mut evaluator = BgvEvaluator::new(&context, 0);
    let mut input = context.new_plaintext();
    let mut one = context.new_plaintext();
    one.as_mut()[0] = 1;
    let mut factor = context.new_plaintext();
    let mut output = context.new_ciphertext(0);
    let mut expected = context.new_plaintext();

    // Reuse context, keys, evaluator and output; encrypt with fresh coins each time.
    for (message, scalar, answer) in [([3, 2], 7, [28, 14]), ([4, 1], 11, [55, 11])] {
        input.as_mut()[..2].copy_from_slice(&message);
        factor.as_mut()[0] = scalar;
        let mut encrypted = encryptor.encrypt_centered(&input, &mut rng);
        evaluator.add_plain_assign(&mut encrypted, &one, PlaintextEmbedding::Centered);
        evaluator.mul_plain_to(
            &encrypted,
            &factor,
            &mut output,
            PlaintextEmbedding::Centered,
        );
        let recovered = client.decrypt(&output, 0);
        expected.as_mut()[..2].copy_from_slice(&answer);
        assert_eq!(recovered, expected);
    }
    println!("BGV: two coefficient requests recovered using one prepared setup");
    Ok(())
}
