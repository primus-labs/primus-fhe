//! One full-ring packed request: multiply two encrypted vectors, rotate, recover.
use primus_bgv::{BgvAutomorphism, BgvClient, BgvContext, BgvMultiplication, BgvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_encoding::BatchingEncoder;
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
    let batching = BatchingEncoder::try_new(PolyLength::new(N), BarrettModulus::new(P))?;
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let mut rng = StdRng::seed_from_u64(0x09b6_5107);
    let mut client = BgvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let relin_key = client.relinearization_key(0, config, &mut rng)?;
    let rotate_key = client.automorphism_key(0, batching.rotation_exponent(1), config, &mut rng)?;
    let mut multiplication = BgvMultiplication::try_new(&context, &relin_key)?;
    let mut rotation = BgvAutomorphism::try_new(&context, 0, &rotate_key)?;
    let values = (0..N as u64).collect::<Vec<_>>();
    let mut a = Polynomial::<Vec<u64>>::zero(N);
    let mut b = Polynomial::<Vec<u64>>::zero(N);
    batching.encode_to(&values, a.as_mut());
    batching.encode_to(&[2; N], b.as_mut());
    let encrypted_a = encryptor.encrypt_centered(&a, &mut rng);
    let encrypted_b = encryptor.encrypt_centered(&b, &mut rng);
    let mut product = context.new_ciphertext(0);
    let mut rotated = context.new_ciphertext(0);
    multiplication.multiply_to(&encrypted_a, &encrypted_b, &mut product);
    rotation.apply_to(&product, &mut rotated);
    let recovered = client.decrypt(&rotated, 0);
    let mut slots = vec![0; N];
    let mut scratch = vec![0; N];
    batching.decode_to(recovered.as_ref(), &mut slots, &mut scratch);
    let half = N / 2;
    let expected = (0..N)
        .map(|i| 2 * values[i / half * half + (i % half + 1) % half] % P)
        .collect::<Vec<_>>();
    assert_eq!(slots, expected);
    println!("BGV: encrypted element-wise multiplication and row-left rotation, {N} slots");
    Ok(())
}
