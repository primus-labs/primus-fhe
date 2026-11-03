//! Complete leveled BFV slots in a plaintext subring with full-ring secrets.

use primus_bfv::{
    BfvAutomorphism, BfvClient, BfvContext, BfvKeySwitcher, BfvModulusSwitch, BfvMultiplier,
    BfvParameters, BfvRelinearizer,
};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
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
        1_125_899_906_826_241,
        1_125_899_906_629_633,
        1_125_899_906_031_617,
    ]
    .map(BarrettModulus::new);
    let context = BfvContext::try_with_levels(
        BfvParameters::try_coefficients(
            PolyLength::new(N),
            BarrettModulus::new(P),
            &moduli,
            SecretKeyDistr::SparseTernary,
            0.849,
        )?,
        3,
    )?;
    let batching = BatchingEncoder::try_new(PolyLength::new(SLOTS), BarrettModulus::new(P))?;
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let mut rng = StdRng::seed_from_u64(0x10b6_5107);
    let alice = BfvClient::generate(&context, &mut rng);
    let mut bob = BfvClient::generate(&context, &mut rng);
    assert_eq!(alice.secret_key().rns_glwe_size().poly_length().get(), N);
    assert_eq!(bob.secret_key().rns_glwe_size().poly_length().get(), N);
    let public_key = alice.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let relin_key = alice.relinearization_key(0, config, &mut rng)?;
    let rotate_key = alice.automorphism_key(1, batching.rotation_exponent(1), config, &mut rng)?;
    let swap_key = alice.automorphism_key(1, batching.row_swap_exponent(), config, &mut rng)?;
    let switch_key = bob.key_switching_key(&alice, 1, config, &mut rng)?;
    let mut relin = BfvRelinearizer::try_new(&context, 0, &relin_key)?;
    let mut rotate = BfvAutomorphism::try_new(&context, 1, &rotate_key)?;
    let mut swap = BfvAutomorphism::try_new(&context, 1, &swap_key)?;
    let mut switch = BfvKeySwitcher::try_new(&context, 1, &switch_key)?;
    // These extra primes are computation-only; they do not enlarge the secret/key modulus.
    let mut multiplier = BfvMultiplier::try_new(
        &context,
        0,
        &[
            1_152_921_504_606_584_833,
            1_152_921_504_598_720_513,
            1_152_921_504_592_429_057,
        ],
    )?;
    let mut drop_first = BfvModulusSwitch::new(&context, 0);
    let mut drop_second = BfvModulusSwitch::new(&context, 1);
    let values: Vec<_> = (0..ACTIVE).map(|i| 7 * i as u64 + 1).collect();
    let factors: Vec<_> = (0..SLOTS).map(|i| 1 + i as u64 % 3).collect();
    let mut small = vec![0; SLOTS];
    let mut a = Polynomial::<Vec<u64>>::zero(N);
    let mut b = Polynomial::<Vec<u64>>::zero(N);
    batching.encode_to(&values, &mut small);
    batching.embed_to(&small, a.as_mut());
    batching.encode_to(&factors, &mut small);
    batching.embed_to(&small, b.as_mut());
    let mut encrypted_a = context.new_ciphertext(0);
    let mut encrypted_b = context.new_ciphertext(0);
    let mut quadratic = context.new_quadratic_ciphertext(0);
    let mut linear = context.new_ciphertext(0);
    let mut lower = context.new_ciphertext(1);
    let mut rotated = context.new_ciphertext(1);
    let mut swapped = context.new_ciphertext(1);
    let mut switched = context.new_ciphertext(1);
    let mut lowest = context.new_ciphertext(2);
    encryptor.encrypt_centered_to(&a, &mut encrypted_a, &mut rng);
    encryptor.encrypt_centered_to(&b, &mut encrypted_b, &mut rng);
    multiplier.multiply_to(&encrypted_a, &encrypted_b, &mut quadratic);
    relin.relinearize_to(&quadratic, &mut linear);
    multiplier.square_to(&linear, &mut quadratic);
    relin.relinearize_to(&quadratic, &mut linear);
    drop_first.switch_to(&linear, &mut lower);
    rotate.apply_to(&lower, &mut rotated);
    swap.apply_to(&rotated, &mut swapped);
    switch.switch_to(&swapped, &mut switched);
    drop_second.switch_to(&switched, &mut lowest);
    let recovered = bob.decrypt(&lowest, 2);
    assert!(
        recovered
            .as_ref()
            .iter()
            .enumerate()
            .all(|(i, &value)| i % (N / SLOTS) == 0 || value == 0)
    );
    batching.extract_to(recovered.as_ref(), &mut small);
    let mut slots = vec![0; SLOTS];
    let mut scratch = vec![0; SLOTS];
    batching.decode_to(&small, &mut slots, &mut scratch);

    let original: Vec<_> = (0..SLOTS)
        .map(|i| {
            if i < ACTIVE {
                let product = values[i] * factors[i] % P;
                product * product % P
            } else {
                0
            }
        })
        .collect();
    let half = SLOTS / 2;
    let rotated: Vec<_> = (0..SLOTS)
        .map(|i| original[(i / half) * half + (i % half + 1) % half])
        .collect();
    let expected: Vec<_> = (0..SLOTS).map(|i| rotated[(i + half) % SLOTS]).collect();
    assert_eq!(slots, expected);
    assert_eq!(
        slots.iter().filter(|&&value| value == 0).count(),
        SLOTS - ACTIVE
    );
    println!(
        "Validated BFV slots (a*b)^2, relinearization, row rotation/swap, Alice->Bob switching and two prime drops: {ACTIVE}/{SLOTS} active, full secret/ciphertext N={N}, moved spare slots zero."
    );
    Ok(())
}
