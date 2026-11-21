//! Ordinary prepared multiplication, in-place square and complete-length boundaries.
use primus_bfv::advanced::BfvMultiplier;
use primus_bfv::evaluation::{BfvModulusSwitch, BfvMultiplication, BfvRelinearizer};
use primus_bfv::{BfvCiphertext, BfvClient, BfvContext, BfvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 32;
const P: u64 = 193;
const Q: [u64; 3] = [
    1_125_899_906_826_241,
    1_125_899_906_629_633,
    1_125_899_906_248_961,
];

fn context(n: usize, p: u64, moduli: &[u64]) -> BfvContext {
    BfvContext::try_with_levels(
        BfvParameters::try_coefficients(
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
fn numerical_binding_and_complete_lengths_reject_before_output_writes() {
    let context = context(N, P, &Q);
    let mut rng = StdRng::seed_from_u64(0x012b_6bad);
    let client = BfvClient::generate(&context, &mut rng);
    let key = client.relinearization_key(2, config(), &mut rng).unwrap();
    for wrong in [
        self::context(N, P, &Q[..1]),
        self::context(64, P, &Q),
        self::context(N, 2, &Q),
        self::context(N, P, &[Q[2], Q[1], Q[0]]),
    ] {
        assert!(BfvMultiplication::try_new(&wrong, &key).is_err());
    }
    let mut request = BfvMultiplication::try_new(&context, &key).unwrap();
    assert_invalid_lengths_preserve_output(&mut request, &context.new_ciphertext(2));
}

fn assert_invalid_lengths_preserve_output(
    request: &mut BfvMultiplication<'_>,
    valid: &BfvCiphertext<Vec<u64>>,
) {
    let length = valid.as_ref().len();
    for bad in [0, length - 1, length + 1, 2 * length] {
        let mut malformed = BfvCiphertext::from_raw(vec![77; bad]);
        let mut output = BfvCiphertext::from_raw(vec![55; length]);
        for (lhs, rhs) in [(&malformed, valid), (valid, &malformed)] {
            rejects_without_writes(&mut output, |output| request.multiply_to(lhs, rhs, output));
        }
        rejects_without_writes(&mut output, |output| request.square_to(&malformed, output));
        rejects_without_writes(&mut malformed, |input| request.square_assign(input));
        rejects_without_writes(&mut malformed, |output| {
            request.multiply_to(valid, valid, output)
        });
        rejects_without_writes(&mut malformed, |output| request.square_to(valid, output));
    }
}

#[track_caller]
fn rejects_without_writes(
    buffer: &mut BfvCiphertext<Vec<u64>>,
    operation: impl FnOnce(&mut BfvCiphertext<Vec<u64>>),
) {
    let before = buffer.clone();
    assert!(catch_unwind(AssertUnwindSafe(|| operation(buffer))).is_err());
    assert_eq!(*buffer, before);
}

#[test]
fn prepared_requests_match_staged_exact_multiply_and_dense_oracles_at_every_level() {
    use primus_bfv::evaluation::BfvMultiplicationBackend::{Exact, HpsPOverQ};
    let context = context(N, P, &Q);
    let mut rng = StdRng::seed_from_u64(0x23bf_0001);
    let mut client = BfvClient::generate(&context, &mut rng);
    let a = Polynomial::new(
        (0..N)
            .map(|i| ((i as i64 % 7) - 3).rem_euclid(P as i64) as u64)
            .collect::<Vec<_>>(),
    );
    let b = Polynomial::new(
        (0..N)
            .map(|i| ((i as i64 % 5) - 2).rem_euclid(P as i64) as u64)
            .collect::<Vec<_>>(),
    );
    let convolution = |a: &[u64], b: &[u64]| {
        let mut out = vec![0i64; N];
        for (i, &x) in a.iter().enumerate() {
            for (j, &y) in b.iter().enumerate() {
                let degree = i + j;
                let term = (x * y) as i64;
                out[degree % N] += if degree < N { term } else { -term };
            }
        }
        out.into_iter()
            .map(|x| x.rem_euclid(P as i64) as u64)
            .collect::<Vec<_>>()
    };
    let expected = convolution(a.as_ref(), b.as_ref());
    let square = convolution(a.as_ref(), a.as_ref());
    let mut left = client.encrypt_centered(&a, &mut rng);
    let mut right = client.encrypt_centered(&b, &mut rng);
    for level in 0..context.level_count() {
        let key = client
            .relinearization_key(level, config(), &mut rng)
            .unwrap();
        let exact = BfvMultiplication::try_new(&context, &key).unwrap();
        let hps = BfvMultiplication::try_with_backend(&context, &key, HpsPOverQ).unwrap();
        let mut output = context.new_ciphertext(level);
        for (backend, mut request) in [(Exact, exact), (HpsPOverQ, hps)] {
            assert_eq!(request.backend(), backend);
            assert!(!request.auxiliary_moduli().is_empty());
            request.multiply_to(&left, &right, &mut output);
            assert_eq!(client.decrypt_at_level(&output, level).as_ref(), expected);
            if backend == Exact {
                let mut multiplier =
                    BfvMultiplier::try_with_default_basis(&context, level).unwrap();
                let mut quadratic = context.new_quadratic_ciphertext(level);
                let mut staged = context.new_ciphertext(level);
                let mut relin = BfvRelinearizer::try_new(&context, &key).unwrap();
                multiplier.multiply_to(&left, &right, &mut quadratic);
                relin.relinearize_to(&quadratic, &mut staged);
                assert_eq!(output, staged);
            }
            request.square_to(&left, &mut output);
            assert_eq!(client.decrypt_at_level(&output, level).as_ref(), square);
            let mut in_place = left.clone();
            request.square_assign(&mut in_place);
            assert_eq!(output, in_place);
        }
        if level + 1 < context.level_count() {
            let mut switch = BfvModulusSwitch::new(&context, level);
            let mut next_left = context.new_ciphertext(level + 1);
            let mut next_right = context.new_ciphertext(level + 1);
            switch.switch_to(&left, &mut next_left);
            switch.switch_to(&right, &mut next_right);
            left = next_left;
            right = next_right;
        }
    }
}

#[test]
fn hps_explicit_basis_and_complete_lengths_are_checked_before_writes() {
    use primus_bfv::evaluation::{BfvMultiplicationBackend::HpsPOverQ, BfvMultiplyError};
    let context = context(N, P, &Q);
    let mut rng = StdRng::seed_from_u64(0x23bf_bad0);
    let client = BfvClient::generate(&context, &mut rng);
    let key = client.relinearization_key(0, config(), &mut rng).unwrap();
    for basis in [
        &[][..],
        &[17],
        &[65],
        &[1_152_921_504_606_830_593, 1_152_921_504_606_830_593],
    ] {
        assert!(
            BfvMultiplication::try_with_backend_and_auxiliary_moduli(
                &context, &key, HpsPOverQ, basis
            )
            .is_err()
        );
    }
    assert!(matches!(
        BfvMultiplication::try_with_backend_and_auxiliary_moduli(
            &context,
            &key,
            HpsPOverQ,
            &[Q[0]]
        ),
        Err(BfvMultiplyError::NonCoprime { .. })
    ));
    let mut request = BfvMultiplication::try_with_backend_and_auxiliary_moduli(
        &context,
        &key,
        HpsPOverQ,
        &[1_152_921_504_606_830_593],
    )
    .unwrap();
    assert_invalid_lengths_preserve_output(&mut request, &context.new_ciphertext(0));
}
