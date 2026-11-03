//! Encrypt, evaluate dense coefficient polynomials, and drop two RNS primes.
//!
//! Run: cargo run -p primus_bfv --example leveled_coefficients
//! These small diagnostic parameters are not a security preset.

use primus_bfv::{
    BfvClient, BfvContext, BfvEvaluator, BfvModulusSwitch, BfvParameters, PlaintextEmbedding,
};
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

// Independent coefficient arithmetic in Z_t[X]/(X^N+1), without NTT or codecs.
fn negacyclic_product(lhs: &[u64], rhs: &[u64], modulus: u64) -> Polynomial<Vec<u64>> {
    let n = lhs.len();
    let mut result = vec![0_i128; n];
    for (i, &a) in lhs.iter().enumerate() {
        for (j, &b) in rhs.iter().enumerate() {
            let product = i128::from(a) * i128::from(b);
            if i + j < n {
                result[i + j] += product;
            } else {
                result[i + j - n] -= product;
            }
        }
    }
    Polynomial(
        result
            .into_iter()
            .map(|value| value.rem_euclid(i128::from(modulus)) as u64)
            .collect(),
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const N: usize = 32;
    const T: u64 = 257;
    let parameters = BfvParameters::try_coefficients(
        PolyLength::new(N),
        BarrettModulus::new(T),
        &[
            1_125_899_906_826_241,
            1_125_899_906_629_633,
            1_125_899_906_031_617,
        ]
        .map(BarrettModulus::new),
        SecretKeyDistr::UniformBinary,
        3.2,
    )?;
    // Level 0 uses the complete Q basis. Levels 1 and 2 successively remove
    // its last prime; every requested level owns its prepared recovery codec.
    let context = BfvContext::try_with_levels(parameters, 3)?;
    let mut rng = StdRng::seed_from_u64(0x4246_565f_4c56_4c31);
    let mut client = BfvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut public_encryptor = context.public_key_encryptor(&public_key)?;
    let message = Polynomial((0..N).map(|i| (i as u64 * 13) % T).collect::<Vec<_>>());
    let addend = Polynomial((0..N).map(|i| [1, T - 1, 0][i % 3]).collect::<Vec<_>>());
    let multiplier = Polynomial((0..N).map(|i| [T - 1, 1][i % 2]).collect::<Vec<_>>());
    let sum = Polynomial(
        message
            .as_ref()
            .iter()
            .zip(addend.as_ref())
            .map(|(&a, &b)| (a + b) % T)
            .collect::<Vec<_>>(),
    );
    let expected = negacyclic_product(sum.as_ref(), multiplier.as_ref(), T);

    let mut private_ciphertext = context.new_ciphertext(0);
    let mut public_ciphertext = context.new_ciphertext(0);
    let mut linear = context.new_ciphertext(0);
    let mut product = context.new_ciphertext(0);
    let mut level_one = context.new_ciphertext(1);
    let mut level_two = context.new_ciphertext(2);
    let mut decoded = Polynomial::<Vec<u64>>::zero(N);
    let mut evaluator = BfvEvaluator::new(&context, 0);
    let mut switch_zero = BfvModulusSwitch::new(&context, 0);
    let mut switch_one = BfvModulusSwitch::new(&context, 1);

    client.encrypt_centered_to(&message, &mut private_ciphertext, &mut rng);
    public_encryptor.encrypt_centered_to(&message, &mut public_ciphertext, &mut rng);
    // A ciphertext may be viewed without copying its native [c0,c1] storage.
    evaluator.add_to(
        &private_ciphertext.as_view(),
        &public_ciphertext.as_view(),
        &mut linear.as_mut_view(),
    );
    evaluator.sub_assign(&mut linear, &private_ciphertext);
    evaluator.neg_assign(&mut linear);
    evaluator.neg_assign(&mut linear);
    client.decrypt_to(&linear, 0, &mut decoded);
    assert_eq!(decoded, message);

    evaluator.add_plain_assign(&mut linear, &addend, PlaintextEmbedding::Centered);
    evaluator.mul_plain_to(
        &linear,
        &multiplier,
        &mut product,
        PlaintextEmbedding::Centered,
    );
    client.decrypt_to(&product, 0, &mut decoded);
    assert_eq!(decoded, expected);
    switch_zero.switch_to(&product, &mut level_one);
    client.decrypt_to(&level_one, 1, &mut decoded);
    assert_eq!(decoded, expected);
    switch_one.switch_to(&level_one, &mut level_two);
    client.decrypt_to(&level_two, 2, &mut decoded);
    assert_eq!(decoded, expected);

    // Evaluation also binds directly to a lower level. Plaintext additions
    // use that level's Delta; multiplication lifts are not Delta-scaled.
    let mut lower_evaluator = BfvEvaluator::new(&context, 2);
    lower_evaluator.add_plain_assign(&mut level_two, &addend, PlaintextEmbedding::Centered);
    for (coefficient, &add) in decoded.as_mut().iter_mut().zip(addend.as_ref()) {
        *coefficient = (*coefficient + add) % T;
    }
    assert_eq!(client.decrypt(&level_two, 2), decoded);
    println!(
        "BFV private/public encryption, dense evaluation and two rounded level drops verified"
    );
    Ok(())
}
