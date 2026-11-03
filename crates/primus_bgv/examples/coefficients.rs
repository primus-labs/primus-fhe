//! Complete coefficient BGV with native plus phase and exact centered recovery.
use primus_bgv::{BgvClient, BgvContext, BgvEvaluator, BgvParameters, PlaintextEmbedding};
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let n = 32;
    let p = 193;
    let moduli = [
        1_125_899_906_248_961,
        1_125_899_906_051_329,
        1_125_899_904_322_049,
    ]
    .map(BarrettModulus::new);
    let context = BgvContext::try_new(BgvParameters::try_coefficients(
        PolyLength::new(n),
        BarrettModulus::new(p),
        &moduli,
        SecretKeyDistr::SparseTernary,
        0.849,
    )?)?;
    let mut rng = StdRng::seed_from_u64(0x09b6_0001);
    let mut client = BgvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let input = Polynomial((0..n).map(|i| (3 * i as u64 + 1) % p).collect::<Vec<_>>());
    let mut addend = Polynomial::<Vec<u64>>::zero(n);
    addend.as_mut()[0] = p - 2;
    let mut multiplier = Polynomial::<Vec<u64>>::zero(n);
    multiplier.as_mut()[1] = 3;
    let mut ciphertext = context.new_ciphertext(0);
    let mut output = context.new_ciphertext(0);
    encryptor.encrypt_centered_to(&input, &mut ciphertext, &mut rng);
    let mut evaluator = BgvEvaluator::new(&context, 0);
    evaluator.add_plain_assign(&mut ciphertext, &addend, PlaintextEmbedding::Centered);
    evaluator.mul_plain_to(
        &ciphertext,
        &multiplier,
        &mut output,
        PlaintextEmbedding::Centered,
    );
    let result = client.decrypt(&output, 0);
    let mut expected = vec![0; n];
    for (i, &value) in input.as_ref().iter().enumerate() {
        let value = (value + if i == 0 { p - 2 } else { 0 }) % p;
        expected[(i + 1) % n] = if i + 1 < n {
            3 * value % p
        } else {
            (p - 3 * value % p) % p
        };
    }
    assert_eq!(result.as_ref(), expected);
    println!(
        "Validated BGV coefficient public-encrypt -> add_plain -> mul_plain -> exact recovery, N={n}, p={p}, 150-bit Q."
    );
    Ok(())
}
