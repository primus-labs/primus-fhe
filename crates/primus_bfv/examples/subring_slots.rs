//! Pack a smaller plaintext ring into a full-ring BFV ciphertext and drop one prime.
//! Run: cargo run -p primus_bfv --example subring_slots --features batching

use primus_bfv::evaluation::{BfvEvaluator, BfvModulusSwitch};
use primus_bfv::{
    BfvClient, BfvContext, BfvParameters, ErrorDistribution, PlaintextEmbedding, SecretKeyDistr,
};
use primus_encoding::BatchingEncoder;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const N: usize = 128;
    const SLOTS: usize = 32;
    const P: u64 = 193;
    // Small demonstration parameters.
    let moduli = [1_125_899_906_826_241, 1_125_899_906_629_633].map(BarrettModulus::new);
    let context = BfvContext::try_with_levels(
        BfvParameters::try_coefficients(
            PolyLength::new(N),
            BarrettModulus::new(P),
            &moduli,
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::Gaussian {
                standard_deviation: 0.849,
            },
        )?,
        2,
    )?;
    let batching = BatchingEncoder::try_new(PolyLength::new(SLOTS), BarrettModulus::new(P))?;

    // Only the plaintext transform uses SLOTS. The client and ciphertexts use N.
    let mut small = [0; SLOTS];
    let mut input = context.new_plaintext();
    batching.encode_to(&[2, 4, 7], &mut small);
    batching.embed_to(&small, input.as_mut());
    let mut rng = StdRng::seed_from_u64(0x09bf_5107);
    let mut client = BfvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let mut ciphertext = encryptor.encrypt_centered(&input, &mut rng);

    // A constant polynomial scales every slot. Switch into a level-one output.
    let mut evaluator = BfvEvaluator::new(&context, 0);
    let mut three = context.new_plaintext();
    three.as_mut()[0] = 3;
    evaluator.mul_plain_assign(&mut ciphertext, &three, PlaintextEmbedding::Centered);
    let mut reduced = context.new_ciphertext(1);
    BfvModulusSwitch::new(&context, 0).switch_to(&ciphertext, &mut reduced);

    let decoded = client.decrypt(&reduced);
    batching.extract_to(decoded.as_ref(), &mut small);
    let mut expected = [0; SLOTS];
    expected[..3].copy_from_slice(&[6, 12, 21]);
    assert_eq!(batching.decode(&small), expected);
    println!("BFV: recovered [6, 12, 21] and zero spare slots after one prime drop.");
    Ok(())
}
