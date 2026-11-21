//! Multiply encrypted subring slots, drop one prime and move both rows.
//! Run: cargo run -p primus_bgv --example leveled_slots --features batching

use primus_bgv::evaluation::{BgvAutomorphism, BgvModulusSwitch, BgvMultiplication};
use primus_bgv::{BgvClient, BgvContext, BgvParameters, ErrorDistribution, SecretKeyDistr};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_encoding::BatchingEncoder;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const N: usize = 128;
    const SLOTS: usize = 32;
    const P: u64 = 193;
    // Small demonstration parameters.
    let moduli = [1_125_899_906_248_961, 1_125_899_906_051_329].map(BarrettModulus::new);
    let context = BgvContext::try_with_levels(
        BgvParameters::try_coefficients(
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
    let batching =
        BatchingEncoder::try_new(PolyLength::new(SLOTS), context.parameters().plain_modulus())?;
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let mut rng = StdRng::seed_from_u64(0x10b6_5107);
    let mut client = BgvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let relin_key = client.relinearization_key(0, config, &mut rng)?;
    // The rotations consume level-one ciphertexts.
    let rotate_key = client.row_rotation_key(1, &batching, 1, config, &mut rng)?;
    let swap_key = client.row_swap_key(1, &batching, config, &mut rng)?;
    let mut multiplication = BgvMultiplication::try_new(&context, &relin_key)?;
    let mut rotate = BgvAutomorphism::try_new(&context, &rotate_key)?;
    let mut swap = BgvAutomorphism::try_new(&context, &swap_key)?;
    let mut drop = BgvModulusSwitch::new(&context, 0);

    let half = SLOTS / 2;
    let mut values = [0; SLOTS];
    values[..2].copy_from_slice(&[2, 3]);
    values[half] = 5;
    let mut small = [0; SLOTS];
    let mut a = context.new_plaintext();
    let mut b = context.new_plaintext();
    batching.encode_to(&values, &mut small);
    batching.embed_to(&small, a.as_mut());
    batching.encode_to(&[4; SLOTS], &mut small);
    batching.embed_to(&small, b.as_mut());

    let encrypted_a = encryptor.encrypt_centered(&a, &mut rng);
    let encrypted_b = encryptor.encrypt_centered(&b, &mut rng);
    let mut product = context.new_ciphertext(0);
    let mut lower = context.new_ciphertext(1);
    let mut rotated = context.new_ciphertext(1);
    let mut swapped = context.new_ciphertext(1);
    multiplication.multiply_to(&encrypted_a, &encrypted_b, &mut product);
    drop.switch_to(&product, &mut lower);
    rotate.apply_to(&lower, &mut rotated);
    swap.apply_to(&rotated, &mut swapped);

    let recovered = client.decrypt(&swapped);
    batching.extract_to(recovered.as_ref(), &mut small);
    let mut expected = values.map(|value| 4 * value % P);
    for row in expected.chunks_exact_mut(half) {
        row.rotate_left(1);
    }
    expected.rotate_left(half);
    assert_eq!(batching.decode(&small), expected);
    println!("BGV: recovered the slot products after a prime drop, row rotation and row swap.");
    Ok(())
}
