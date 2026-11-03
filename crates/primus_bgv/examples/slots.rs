//! One full-ring packed request: multiply two encrypted vectors, rotate, recover.
use primus_bgv::{BgvAutomorphism, BgvClient, BgvContext, BgvMultiplication, BgvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const N: usize = 32;
    const P: u64 = 193;
    // n=N: encode directly into the plaintext, without subring embed/extract.
    let moduli = [
        1_125_899_906_248_961,
        1_125_899_906_051_329,
        1_125_899_904_322_049,
    ]
    .map(BarrettModulus::new);
    let context = BgvContext::try_new(BgvParameters::try_coefficients(
        PolyLength::new(N),
        BarrettModulus::new(P),
        &moduli,
        SecretKeyDistr::SparseTernary,
        0.849,
    )?)?;
    let batching = context.batching_encoder()?;
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let mut rng = StdRng::seed_from_u64(0x09b6_5107);
    let mut client = BgvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let relin_key = client.relinearization_key(0, config, &mut rng)?;
    let rotate_key = client.row_rotation_key(0, &batching, 1, config, &mut rng)?;
    let mut multiplication = BgvMultiplication::try_new(&context, &relin_key)?;
    let mut rotation = BgvAutomorphism::try_new(&context, &rotate_key)?;
    // Reuse setup and operation scratch; convenience encoding/encryption/recovery
    // allocate their returned values. Advanced examples show prepared `_to` calls.
    let capacity = batching.slot_capacity();
    let factor = Polynomial(batching.encode(&vec![2; capacity]));
    let mut product = context.new_ciphertext(0);
    let mut rotated = context.new_ciphertext(0);
    for offset in [0, 1] {
        let values = (0..capacity).map(|i| i as u64 + offset).collect::<Vec<_>>();
        let input = Polynomial(batching.encode(&values));
        let encrypted = encryptor.encrypt_centered(&input, &mut rng);
        let encrypted_factor = encryptor.encrypt_centered(&factor, &mut rng);
        multiplication.multiply_to(&encrypted, &encrypted_factor, &mut product);
        rotation.apply_to(&product, &mut rotated);
        let recovered = client.decrypt(&rotated, 0);
        let slots = batching.decode(recovered.as_ref());
        let half = capacity / 2;
        let expected = (0..capacity)
            .map(|i| 2 * values[i / half * half + (i % half + 1) % half] % batching.plain_modulus())
            .collect::<Vec<_>>();
        assert_eq!(slots, expected);
    }
    println!("BGV: two packed multiplication/rotation requests using one prepared setup");
    Ok(())
}
