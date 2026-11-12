//! Complete native BFV coefficient evaluation and a switch to another secret.
//! Run: cargo run -p primus_bfv --example leveled_coefficients

use primus_bfv::evaluation::{
    BfvAutomorphism, BfvKeySwitcher, BfvModulusSwitch, BfvMultiplication,
};
use primus_bfv::{BfvClient, BfvContext, BfvParameters, ErrorDistribution, SecretKeyDistr};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 32;
const P: u64 = 193;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Small deterministic demonstration parameters.
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
            ErrorDistribution::Gaussian {
                standard_deviation: 0.849,
            },
        )?,
        3,
    )?;
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let mut rng = StdRng::seed_from_u64(0x10b6_c0ef);
    let alice = BfvClient::generate(&context, &mut rng);
    let mut bob = BfvClient::generate(&context, &mut rng);
    let public_key = alice.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;

    // Each key is generated for the level at which its operation runs.
    let relin_key = alice.relinearization_key(0, config, &mut rng)?;
    let auto_key = alice.automorphism_key(1, 5, config, &mut rng)?;
    let switch_key = bob.key_switching_key(&alice, 1, config, &mut rng)?;
    let mut auto = BfvAutomorphism::try_new(&context, &auto_key)?;
    let mut switch = BfvKeySwitcher::try_new(&context, &switch_key)?;
    let mut multiplication = BfvMultiplication::try_new(&context, &relin_key)?;
    let mut drop_first = BfvModulusSwitch::new(&context, 0);
    let mut drop_second = BfvModulusSwitch::new(&context, 1);
    let mut a = context.new_plaintext();
    let mut b = context.new_plaintext();
    a.as_mut()[..2].copy_from_slice(&[1, 2]);
    b.as_mut()[..2].copy_from_slice(&[1, 1]);
    let encrypted_a = encryptor.encrypt_centered(&a, &mut rng);
    let encrypted_b = encryptor.encrypt_centered(&b, &mut rng);
    let mut linear = context.new_ciphertext(0);
    let mut lower = context.new_ciphertext(1);
    let mut transformed = context.new_ciphertext(1);
    let mut switched = context.new_ciphertext(1);
    let mut lowest = context.new_ciphertext(2);

    multiplication.multiply_to(&encrypted_a, &encrypted_b, &mut linear);
    multiplication.square_assign(&mut linear);
    drop_first.switch_to(&linear, &mut lower);
    auto.apply_to(&lower, &mut transformed);
    switch.switch_to(&transformed, &mut switched);
    drop_second.switch_to(&switched, &mut lowest);
    let recovered = bob.decrypt(&lowest);

    // ((1 + 2X)(1 + X))² = 1 + 6X + 13X² + 12X³ + 4X⁴.
    let mut expected = [0; N];
    for (degree, value) in [1, 6, 13, 12, 4].into_iter().enumerate() {
        expected[5 * degree] = value;
    }
    assert_eq!(recovered.as_ref(), expected);
    println!("BFV: Bob recovered ((1 + 2X⁵)(1 + X⁵))² after two prime drops.");
    Ok(())
}
