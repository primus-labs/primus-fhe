//! Ordinary prepared multiplication, in-place square and complete-length boundaries.
use primus_bgv::advanced::tensor_to;
use primus_bgv::evaluation::{BgvMultiplication, BgvRelinearizer};
use primus_bgv::{BgvCiphertext, BgvClient, BgvContext, BgvParameters, ErrorDistribution};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 32;
const P: u64 = 193;
const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];

fn context(n: usize, p: u64, moduli: &[u64]) -> BgvContext {
    BgvContext::try_with_levels(
        BgvParameters::try_coefficients(
            PolyLength::new(n),
            BarrettModulus::new(p),
            &moduli
                .iter()
                .copied()
                .map(BarrettModulus::new)
                .collect::<Vec<_>>(),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::Gaussian {
                standard_deviation: 0.849,
            },
        )
        .unwrap(),
        moduli.len(),
    )
    .unwrap()
}

fn config() -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    }
}

#[test]
fn prepared_request_derives_each_level_and_matches_staged_operations() {
    let context = context(N, P, &Q);
    let mut rng = StdRng::seed_from_u64(0x012b_6001);
    let mut client = BgvClient::generate(&context, &mut rng);
    let mut a = Polynomial::<Vec<u64>>::zero(N);
    let mut b = Polynomial::<Vec<u64>>::zero(N);
    a.as_mut()[..2].copy_from_slice(&[3, 2]);
    b.as_mut()[..2].copy_from_slice(&[5, 1]);
    let encrypted_a = client.encrypt(&a, &mut rng);
    let encrypted_b = client.encrypt_centered(&b, &mut rng);
    let full_len = context.rns_poly_len(0);
    for level in 0..context.level_count() {
        let length = context.rns_poly_len(level);
        // This fresh phase fits every prefix; this fixture is not an evaluated
        // prime-drop algorithm. Actual drops are tested via BgvModulusSwitch.
        let prefix = |input: &BgvCiphertext<Vec<u64>>| {
            let (c0, c1) = input.c0_c1(full_len);
            BgvCiphertext::from_raw([&c0.as_ref()[..length], &c1.as_ref()[..length]].concat())
        };
        let left = prefix(&encrypted_a);
        let right = prefix(&encrypted_b);
        let key = client
            .relinearization_key(level, config(), &mut rng)
            .unwrap();
        let mut request = BgvMultiplication::try_new(&context, &key).unwrap();
        let mut output = context.new_ciphertext(level);
        request.multiply_to(&left, &right, &mut output);
        let mut expected = vec![0; N];
        expected[..3].copy_from_slice(&[15, 13, 2]);
        assert_eq!(client.decrypt_at_level(&output, level).as_ref(), expected);

        let mut quadratic = context.new_quadratic_ciphertext(level);
        let mut staged = context.new_ciphertext(level);
        let mut relin = BgvRelinearizer::try_new(&context, &key).unwrap();
        tensor_to(&context, level, &left, &right, &mut quadratic);
        relin.relinearize_to(&quadratic, &mut staged);
        assert_eq!(output.as_ref(), staged.as_ref());
        request.square_to(&left, &mut output);
        let mut inplace = left;
        request.square_assign(&mut inplace);
        assert_eq!(output.as_ref(), inplace.as_ref());
        expected[..3].copy_from_slice(&[9, 12, 4]);
        assert_eq!(client.decrypt_at_level(&inplace, level).as_ref(), expected);
    }
}

#[test]
fn numerical_binding_and_complete_lengths_reject_before_output_writes() {
    let context = context(N, P, &Q);
    let mut rng = StdRng::seed_from_u64(0x012b_6bad);
    let client = BgvClient::generate(&context, &mut rng);
    let key = client.relinearization_key(2, config(), &mut rng).unwrap();
    for wrong in [
        self::context(N, P, &Q[..1]),
        self::context(64, P, &Q),
        self::context(N, 2, &Q),
        self::context(N, P, &[Q[2], Q[1], Q[0]]),
    ] {
        assert!(BgvMultiplication::try_new(&wrong, &key).is_err());
    }
    let mut request = BgvMultiplication::try_new(&context, &key).unwrap();
    let valid = context.new_ciphertext(2);
    let length = valid.as_ref().len();
    for bad in [0, length - 1, length + 1, 2 * length] {
        let mut malformed = BgvCiphertext::from_raw(vec![77; bad]);
        let mut output = BgvCiphertext::from_raw(vec![55; length]);
        for left_is_bad in [false, true] {
            let (lhs, rhs) = if left_is_bad {
                (&malformed, &valid)
            } else {
                (&valid, &malformed)
            };
            assert!(
                catch_unwind(AssertUnwindSafe(|| request.multiply_to(
                    lhs,
                    rhs,
                    &mut output
                )))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&x| x == 55));
        }
        assert!(
            catch_unwind(AssertUnwindSafe(
                || request.square_to(&malformed, &mut output)
            ))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&x| x == 55));
        assert!(catch_unwind(AssertUnwindSafe(|| request.square_assign(&mut malformed))).is_err());
        assert!(malformed.as_ref().iter().all(|&x| x == 77));
        assert!(
            catch_unwind(AssertUnwindSafe(|| request.multiply_to(
                &valid,
                &valid,
                &mut malformed
            )))
            .is_err()
        );
        assert!(malformed.as_ref().iter().all(|&x| x == 77));
        assert!(
            catch_unwind(AssertUnwindSafe(
                || request.square_to(&valid, &mut malformed)
            ))
            .is_err()
        );
        assert!(malformed.as_ref().iter().all(|&x| x == 77));
    }
}
