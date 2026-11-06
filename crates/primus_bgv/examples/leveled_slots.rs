//! Advanced: subring slots, row operations, key switching and two prime drops.
//! Run: cargo run -p primus_bgv --example leveled_slots --features batching

use primus_bgv::{
    BgvAutomorphism, BgvClient, BgvContext, BgvKeySwitcher, BgvModulusSwitch, BgvMultiplication,
    BgvParameters,
};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_encoding::BatchingEncoder;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
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
    let context = BgvContext::try_with_levels(
        BgvParameters::try_coefficients(
            PolyLength::new(N),
            BarrettModulus::new(P),
            &moduli,
            SecretKeyDistr::SparseTernary,
            0.849,
        )?,
        3,
    )?;
    let batching =
        BatchingEncoder::try_new(PolyLength::new(SLOTS), context.parameters().plain_modulus())?;
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let mut rng = StdRng::seed_from_u64(0x10b6_5107);
    let alice = BgvClient::generate(&context, &mut rng);
    let mut bob = BgvClient::generate(&context, &mut rng);
    let public_key = alice.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let relin_key = alice.relinearization_key(0, config, &mut rng)?;
    let rotate_key = alice.row_rotation_key(1, &batching, 1, config, &mut rng)?;
    let swap_key = alice.row_swap_key(1, &batching, config, &mut rng)?;
    let switch_key = bob.key_switching_key(&alice, 1, config, &mut rng)?;
    let mut multiplication = BgvMultiplication::try_new(&context, &relin_key)?;
    let mut rotate = BgvAutomorphism::try_new(&context, &rotate_key)?;
    let mut swap = BgvAutomorphism::try_new(&context, &swap_key)?;
    let mut switch = BgvKeySwitcher::try_new(&context, &switch_key)?;
    let mut drop_first = BgvModulusSwitch::new(&context, 0);
    let mut drop_second = BgvModulusSwitch::new(&context, 1);
    let values: Vec<_> = (0..ACTIVE).map(|i| 7 * i as u64 + 1).collect();
    let factors: Vec<_> = (0..SLOTS).map(|i| 1 + i as u64 % 3).collect();
    let mut small = vec![0; SLOTS];
    let mut a = context.new_plaintext();
    let mut b = context.new_plaintext();
    batching.encode_to(&values, &mut small);
    batching.embed_to(&small, a.as_mut());
    batching.encode_to(&factors, &mut small);
    batching.embed_to(&small, b.as_mut());
    let mut encrypted_a = context.new_ciphertext(0);
    let mut encrypted_b = context.new_ciphertext(0);
    let mut linear = context.new_ciphertext(0);
    let mut lower = context.new_ciphertext(1);
    let mut rotated = context.new_ciphertext(1);
    let mut swapped = context.new_ciphertext(1);
    let mut switched = context.new_ciphertext(1);
    let mut lowest = context.new_ciphertext(2);
    encryptor.encrypt_centered_to(&a, &mut encrypted_a, &mut rng);
    encryptor.encrypt_centered_to(&b, &mut encrypted_b, &mut rng);
    multiplication.multiply_to(&encrypted_a, &encrypted_b, &mut linear);
    multiplication.square_assign(&mut linear);
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
        "Validated BGV slots (a*b)^2, relinearization, row rotation/swap, Alice->Bob switching and two prime drops: {ACTIVE}/{SLOTS} active, full secret/ciphertext N={N}, moved spare slots zero."
    );
    Ok(())
}
