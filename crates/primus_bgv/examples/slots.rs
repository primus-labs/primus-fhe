//! Shared batching in a plaintext subring; the secret and ciphertext stay full N.
use primus_bgv::{BgvClient, BgvContext, BgvEvaluator, BgvParameters, PlaintextEmbedding};
use primus_encoding::BatchingEncoder;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const N: usize = 128;
    const SLOTS: usize = 32;
    const ACTIVE: usize = 13;
    const P: u64 = 193;
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
    let batching = BatchingEncoder::try_new(PolyLength::new(SLOTS), BarrettModulus::new(P))?;
    let values = (0..ACTIVE)
        .map(|i| (7 * i as u64 + 1) % P)
        .collect::<Vec<_>>();
    let offsets = vec![7; ACTIVE];
    let factors = (0..SLOTS).map(|i| 1 + i as u64 % 5).collect::<Vec<_>>();
    let mut small = vec![0; SLOTS];
    let mut input = Polynomial::<Vec<u64>>::zero(N);
    let mut addend = Polynomial::<Vec<u64>>::zero(N);
    let mut multiplier = Polynomial::<Vec<u64>>::zero(N);
    batching.encode_to(&values, &mut small);
    batching.embed_to(&small, input.as_mut());
    batching.encode_to(&offsets, &mut small);
    batching.embed_to(&small, addend.as_mut());
    batching.encode_to(&factors, &mut small);
    batching.embed_to(&small, multiplier.as_mut());
    let mut rng = StdRng::seed_from_u64(0x09b6_5107);
    let mut client = BgvClient::generate(&context, &mut rng);
    assert_eq!(client.secret_key().rns_glwe_size().poly_length().get(), N);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let mut ciphertext = context.new_ciphertext();
    let mut output = context.new_ciphertext();
    encryptor.encrypt_centered_to(&input, &mut ciphertext, &mut rng);
    let mut evaluator = BgvEvaluator::new(&context);
    evaluator.add_plain_assign(&mut ciphertext, &addend, PlaintextEmbedding::Centered);
    evaluator.mul_plain_to(
        &ciphertext,
        &multiplier,
        &mut output,
        PlaintextEmbedding::Centered,
    );
    let decoded = client.decrypt(&output);
    batching.extract_to(decoded.as_ref(), &mut small);
    let mut slots = vec![0; SLOTS];
    let mut scratch = vec![0; SLOTS];
    batching.decode_to(&small, &mut slots, &mut scratch);
    for i in 0..SLOTS {
        assert_eq!(
            slots[i],
            if i < ACTIVE {
                (values[i] + offsets[i]) * factors[i] % P
            } else {
                0
            }
        );
    }
    assert!(
        decoded
            .as_ref()
            .iter()
            .enumerate()
            .all(|(i, &v)| i % (N / SLOTS) == 0 || v == 0)
    );
    println!(
        "Validated shared BGV slots: {ACTIVE}/{SLOTS} active slots, full secret/ciphertext N={N}, zero padding, exact 150-bit CRT recovery."
    );
    println!(
        "Plaintext row-left-rotation exponent={}, row-swap exponent={}; ciphertext rotations require later evaluation keys.",
        batching.rotation_exponent(1),
        batching.row_swap_exponent()
    );
    Ok(())
}
