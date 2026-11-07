//! Advanced: multiply two ciphertexts with one prepared relinearization key.
//! Run: cargo run -p primus_bgv --example ciphertext_multiplication
//! Select native Hybrid keys: append -- --hybrid.
use primus_bgv::evaluation::BgvMultiplication;
use primus_bgv::keys::BgvEvaluationKeyConfig;
use primus_bgv::{BgvClient, BgvContext, BgvParameters, ErrorDistribution, SecretKeyDistr};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
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
    let context = BgvContext::try_new(BgvParameters::try_coefficients(
        PolyLength::new(N),
        BarrettModulus::new(193),
        &moduli,
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::Gaussian {
            standard_deviation: 0.849,
        },
    )?)?;
    let mut rng = StdRng::seed_from_u64(0x09b6_0001);
    let mut client = BgvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let config: BgvEvaluationKeyConfig = match std::env::args().nth(1).as_deref() {
        Some("--hybrid") => context
            .hybrid_key_parameters(0, moduli.len(), &[1_152_921_504_606_830_593])?
            .into(),
        None => DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        }
        .into(),
        _ => return Err("expected no arguments or --hybrid".into()),
    };
    let relin_key = client.relinearization_key(0, config, &mut rng)?;
    let mut multiplication = BgvMultiplication::try_new(&context, &relin_key)?;
    // Reuse setup and multiplication scratch across two ordinary requests.
    let mut a = context.new_plaintext();
    let mut b = context.new_plaintext();
    b.as_mut()[..2].copy_from_slice(&[5, 1]);
    let mut product = context.new_ciphertext(0);
    let mut expected = context.new_plaintext();
    for (left, answer) in [([3, 2], [15, 13, 2]), ([4, 1], [20, 9, 1])] {
        a.as_mut()[..2].copy_from_slice(&left);
        let encrypted_a = encryptor.encrypt(&a, &mut rng);
        let encrypted_b = encryptor.encrypt(&b, &mut rng);
        multiplication.multiply_to(&encrypted_a, &encrypted_b, &mut product);
        let recovered = client.decrypt(&product);
        expected.as_mut()[..3].copy_from_slice(&answer);
        assert_eq!(recovered, expected);
    }
    println!("BGV: two coefficient products recovered using one prepared setup");
    Ok(())
}
