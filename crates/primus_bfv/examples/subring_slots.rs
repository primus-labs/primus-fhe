//! BFV consumes the same subring batching encoder as BGV.
use primus_bfv::{
    BfvClient, BfvContext, BfvEvaluator, BfvModulusSwitch, BfvParameters, PlaintextEmbedding,
};
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
    let moduli = [1_125_899_906_826_241, 1_125_899_906_629_633].map(BarrettModulus::new);
    let context = BfvContext::try_with_levels(
        BfvParameters::try_coefficients(
            PolyLength::new(N),
            BarrettModulus::new(P),
            &moduli,
            SecretKeyDistr::SparseTernary,
            0.849,
        )?,
        2,
    )?;
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
    let mut rng = StdRng::seed_from_u64(0x09bf_5107);
    let mut client = BfvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let mut ciphertext = context.new_ciphertext(0);
    let mut output = context.new_ciphertext(0);
    encryptor.encrypt_centered_to(&input, &mut ciphertext, &mut rng);
    let mut evaluator = BfvEvaluator::new(&context, 0);
    evaluator.add_plain_assign(&mut ciphertext, &addend, PlaintextEmbedding::Centered);
    evaluator.mul_plain_to(
        &ciphertext,
        &multiplier,
        &mut output,
        PlaintextEmbedding::Centered,
    );
    let mut reduced = context.new_ciphertext(1);
    BfvModulusSwitch::new(&context, 0).switch_to(&output, &mut reduced);
    let decoded = client.decrypt(&reduced, 1);
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
    println!(
        "Validated shared BFV slots: {ACTIVE}/{SLOTS} active slots, full secret/ciphertext N={N}, exact prime drop and zero padding."
    );
    Ok(())
}
