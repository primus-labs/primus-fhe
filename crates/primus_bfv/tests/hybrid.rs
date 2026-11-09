//! Native Hybrid keys at each prefix, through ordinary public BFV operations.
use primus_bfv::evaluation::{
    BfvAutomorphism, BfvKeySwitcher, BfvModulusSwitch, BfvMultiplication,
};
use primus_bfv::{BfvCiphertext, BfvClient, BfvContext, BfvParameters};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 32;
const T: u64 = 193;
const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];
const KEY_P: [u64; 1] = [1_099_511_626_049];
fn context() -> BfvContext {
    BfvContext::try_with_levels(
        BfvParameters::try_coefficients(
            PolyLength::new(N),
            BarrettModulus::new(T),
            &Q.map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::Gaussian {
                standard_deviation: 0.849,
            },
        )
        .unwrap(),
        3,
    )
    .unwrap()
}
fn message() -> Polynomial<Vec<u64>> {
    Polynomial::new(
        (0..N)
            .map(|i| (i as i64 % 5 - 2).rem_euclid(T as i64) as u64)
            .collect(),
    )
}
fn square(input: &[u64]) -> Vec<u64> {
    let signed = |x: u64| {
        if x > T / 2 {
            x as i64 - T as i64
        } else {
            x as i64
        }
    };
    let mut result = vec![0i64; N];
    for (i, &a) in input.iter().enumerate() {
        for (j, &b) in input.iter().enumerate() {
            result[(i + j) % N] += if i + j < N {
                signed(a) * signed(b)
            } else {
                -signed(a) * signed(b)
            };
        }
    }
    result
        .into_iter()
        .map(|x| x.rem_euclid(T as i64) as u64)
        .collect()
}
#[test]
fn hybrid_roles_recover_at_all_prefixes_with_a_smaller_auxiliary_basis() {
    let context = context();
    let mut rng = StdRng::seed_from_u64(0x24bf0001);
    let mut alice = BfvClient::generate(&context, &mut rng);
    let mut bob = BfvClient::generate(&context, &mut rng);
    let plaintext = message();
    let expected_square = square(plaintext.as_ref());
    let mut input = alice.encrypt_centered(&plaintext, &mut rng);
    for level in 0..3 {
        let parameters = context.hybrid_key_parameters(level, 2, &KEY_P).unwrap();
        assert_eq!(parameters.hybrid_rns().partition_moduli_count(), 2);
        let key = alice
            .relinearization_key(level, parameters.clone(), &mut rng)
            .unwrap();
        let mut multiplication = BfvMultiplication::try_new(&context, &key).unwrap();
        let mut output = context.new_ciphertext(level);
        multiplication.square_to(&input, &mut output);
        assert_eq!(
            alice.decrypt_at_level(&output, level).as_ref(),
            expected_square
        );
        let switching_key = bob
            .key_switching_key(&alice, level, parameters.clone(), &mut rng)
            .unwrap();
        let mut switching = BfvKeySwitcher::try_new(&context, &switching_key).unwrap();
        switching.switch_to(&input, &mut output);
        assert_eq!(
            bob.decrypt_at_level(&output, level).as_ref(),
            plaintext.as_ref()
        );
        let auto_key = alice
            .automorphism_key(level, 3, parameters, &mut rng)
            .unwrap();
        let mut auto = BfvAutomorphism::try_new(&context, &auto_key).unwrap();
        auto.apply_to(&input, &mut output);
        let mut expected = vec![0; N];
        for (i, &x) in plaintext.as_ref().iter().enumerate() {
            expected[(3 * i) % N] = if (3 * i / N).is_multiple_of(2) {
                x
            } else {
                (T - x) % T
            };
        }
        assert_eq!(alice.decrypt_at_level(&output, level).as_ref(), expected);
        if level + 1 < 3 {
            let mut lower = context.new_ciphertext(level + 1);
            BfvModulusSwitch::new(&context, level).switch_to(&input, &mut lower);
            input = lower;
        }
    }
}
#[test]
fn hybrid_binding_and_complete_lengths_reject_before_output_writes() {
    let context = context();
    let mut rng = StdRng::seed_from_u64(0x24bfbad0);
    let client = BfvClient::generate(&context, &mut rng);
    let wrong_level = context.hybrid_key_parameters(1, 2, &KEY_P).unwrap();
    assert!(
        client
            .relinearization_key(0, wrong_level, &mut rng)
            .is_err()
    );
    assert!(context.hybrid_key_parameters(0, 0, &KEY_P).is_err());
    assert!(context.hybrid_key_parameters(0, 2, &[Q[0]]).is_err());
    assert!(context.hybrid_key_parameters(0, 2, &[49_601]).is_err());
    let parameters = context.hybrid_key_parameters(0, 2, &KEY_P).unwrap();
    let key = client
        .key_switching_key(&client, 0, parameters, &mut rng)
        .unwrap();
    let mut switch = BfvKeySwitcher::try_new(&context, &key).unwrap();
    let valid = context.new_ciphertext(0);
    for size in [0, valid.as_ref().len() - 1, valid.as_ref().len() + 1] {
        let bad = BfvCiphertext::from_raw(vec![77; size]);
        let mut output = BfvCiphertext::from_raw(vec![55; valid.as_ref().len()]);
        assert!(catch_unwind(AssertUnwindSafe(|| switch.switch_to(&bad, &mut output))).is_err());
        assert!(output.as_ref().iter().all(|&x| x == 55));
        let mut bad_output = BfvCiphertext::from_raw(vec![55; size]);
        assert!(
            catch_unwind(AssertUnwindSafe(
                || switch.switch_to(&valid, &mut bad_output)
            ))
            .is_err()
        );
        assert!(bad_output.as_ref().iter().all(|&x| x == 55));
    }
}
