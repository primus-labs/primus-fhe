//! Public BFV slot multiplication followed by one encrypted row rotation.
//! Run: cargo run -p primus_bfv --example slots --features batching

use primus_bfv::{BfvAutomorphism, BfvClient, BfvContext, BfvMultiplication, BfvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const N: usize = 32;
    const P: u64 = 193;
    // n=N: coefficients go directly into the plaintext polynomial.
    // These small functional parameters are not a security preset.
    let context = BfvContext::try_new(BfvParameters::try_coefficients(
        PolyLength::new(N),
        BarrettModulus::new(P),
        &[1_125_899_906_826_241, 1_125_899_906_629_633].map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        0.849,
    )?)?;
    let batching = context.batching_encoder()?;
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let mut rng = StdRng::seed_from_u64(0x12bf_5107);
    let mut client = BfvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let relin_key = client.relinearization_key(0, config, &mut rng)?;
    let rotation_key = client.row_rotation_key(0, &batching, 1, config, &mut rng)?;
    let mut multiplication = BfvMultiplication::try_new(&context, &relin_key)?;
    let mut rotation = BfvAutomorphism::try_new(&context, &rotation_key)?;

    // Reuse setup and prepared operations; the convenience calls allocate results.
    let capacity = batching.slot_capacity();
    let values: Vec<_> = (1..=capacity as u64).collect();
    let mut product = context.new_ciphertext(0);
    let mut rotated = context.new_ciphertext(0);
    let half = capacity / 2;
    for scalar in [3, 5] {
        let message = Polynomial(batching.encode(&values));
        let factor = Polynomial(batching.encode(&vec![scalar; capacity]));
        let encrypted_message = encryptor.encrypt_centered(&message, &mut rng);
        let encrypted_factor = encryptor.encrypt_centered(&factor, &mut rng);
        multiplication.multiply_to(&encrypted_message, &encrypted_factor, &mut product);
        rotation.apply_to(&product, &mut rotated);
        let slots = batching.decode(client.decrypt(&rotated, 0).as_ref());
        for (i, &actual) in slots.iter().enumerate() {
            let source = (i / half) * half + (i % half + 1) % half;
            assert_eq!(actual, scalar * values[source] % batching.plain_modulus());
        }
    }
    println!("BFV: reused one setup for two slot multiplications and left row rotations");
    Ok(())
}
