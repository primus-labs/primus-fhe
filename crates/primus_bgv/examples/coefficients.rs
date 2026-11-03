//! One public-key multiplication: (3+2X)(5+X) = 15+13X+2X².
use primus_bgv::{BgvClient, BgvContext, BgvMultiplication, BgvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
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
        0.849,
    )?)?;
    let mut rng = StdRng::seed_from_u64(0x09b6_0001);
    let mut client = BgvClient::generate(&context, &mut rng);
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
    let mut multiplication = BgvMultiplication::try_new(&context, &relin_key)?;
    let mut a = Polynomial::<Vec<u64>>::zero(N);
    let mut b = Polynomial::<Vec<u64>>::zero(N);
    a.as_mut()[..2].copy_from_slice(&[3, 2]);
    b.as_mut()[..2].copy_from_slice(&[5, 1]);
    let encrypted_a = encryptor.encrypt(&a, &mut rng);
    let encrypted_b = encryptor.encrypt(&b, &mut rng);
    let mut product = context.new_ciphertext(0);
    multiplication.multiply_to(&encrypted_a, &encrypted_b, &mut product);
    let recovered = client.decrypt(&product, 0);
    let mut expected = vec![0; N];
    expected[..3].copy_from_slice(&[15, 13, 2]);
    assert_eq!(recovered.as_ref(), expected);
    println!("BGV: (3+2X)(5+X) = 15+13X+2X² modulo 193");
    Ok(())
}
