//! Public encryption and one BFV coefficient multiplication.
//! Run: cargo run -p primus_bfv --example coefficients

use primus_bfv::{BfvClient, BfvContext, BfvMultiplication, BfvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
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
        0.849,
    )?;
    let context = BfvContext::try_new(parameters)?;
    let mut rng = StdRng::seed_from_u64(0x12bf_c0ef);
    let mut client = BfvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let relin_key = client.relinearization_key(
        0,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        },
        &mut rng,
    )?;
    let mut multiplication = BfvMultiplication::try_new(&context, &relin_key)?;

    let mut message = Polynomial::<Vec<u64>>::zero(N);
    message.as_mut()[..3].copy_from_slice(&[1, 2, 3]);
    let mut factor = Polynomial::<Vec<u64>>::zero(N);
    factor.as_mut()[0] = 7;
    let encrypted_message = encryptor.encrypt_centered(&message, &mut rng);
    let encrypted_factor = encryptor.encrypt_centered(&factor, &mut rng);
    let mut product = context.new_ciphertext(0);
    multiplication.multiply_to(&encrypted_message, &encrypted_factor, &mut product);
    let recovered = client.decrypt(&product, 0);
    let mut expected = vec![0; N];
    expected[..3].copy_from_slice(&[7, 14, 21]);
    assert_eq!(recovered.as_ref(), expected);
    println!("BFV: (1 + 2X + 3X²) × 7 = 7 + 14X + 21X²");
    Ok(())
}
