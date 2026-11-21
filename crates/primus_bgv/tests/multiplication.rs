//! Ordinary prepared multiplication, in-place square and complete-length boundaries.
use primus_bgv::advanced::tensor_to;
use primus_bgv::evaluation::{BgvModulusSwitch, BgvMultiplication, BgvRelinearizer};
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
    let mut left = client.encrypt(&a, &mut rng);
    let mut right = client.encrypt_centered(&b, &mut rng);
    let mut expected_product = vec![0; N];
    expected_product[..3].copy_from_slice(&[15, 13, 2]);
    let mut expected_square = vec![0; N];
    expected_square[..3].copy_from_slice(&[9, 12, 4]);
    for level in 0..context.level_count() {
        let key = client
            .relinearization_key(level, config(), &mut rng)
            .unwrap();
        let mut request = BgvMultiplication::try_new(&context, &key).unwrap();
        let mut output = context.new_ciphertext(level);
        // Q uses primes congruent to 1 modulo P, so these raw views retain the
        // factor-one message convention through each prime drop.
        let raw_left = BgvCiphertext::from_raw(left.as_ref());
        let raw_right = BgvCiphertext::from_raw(right.as_ref());
        request.multiply_to(&raw_left, &raw_right, &mut output);
        assert_eq!(client.decrypt(&output).as_ref(), expected_product);

        let mut quadratic = context.new_quadratic_ciphertext(level);
        let mut staged = context.new_ciphertext(level);
        let mut relin = BgvRelinearizer::try_new(&context, &key).unwrap();
        tensor_to(&context, level, &left, &right, &mut quadratic);
        relin.relinearize_to(&quadratic, &mut staged);
        assert_eq!(output, staged);
        request.square_to(&raw_left, &mut output);
        let mut inplace = left.clone();
        request.square_assign(&mut inplace);
        assert_eq!(output, inplace);
        assert_eq!(client.decrypt(&inplace).as_ref(), expected_square);
        if level + 1 < context.level_count() {
            let mut drop = BgvModulusSwitch::new(&context, level);
            let mut next_left = context.new_ciphertext(level + 1);
            let mut next_right = context.new_ciphertext(level + 1);
            drop.switch_to(&left, &mut next_left);
            drop.switch_to(&right, &mut next_right);
            left = next_left;
            right = next_right;
        }
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
        for (lhs, rhs) in [(&malformed, &valid), (&valid, &malformed)] {
            rejects_without_writes(&mut output, |output| request.multiply_to(lhs, rhs, output));
        }
        rejects_without_writes(&mut output, |output| request.square_to(&malformed, output));
        rejects_without_writes(&mut malformed, |input| request.square_assign(input));
        rejects_without_writes(&mut malformed, |output| {
            request.multiply_to(&valid, &valid, output)
        });
        rejects_without_writes(&mut malformed, |output| request.square_to(&valid, output));
    }
}

#[track_caller]
fn rejects_without_writes(
    buffer: &mut BgvCiphertext<Vec<u64>>,
    operation: impl FnOnce(&mut BgvCiphertext<Vec<u64>>),
) {
    let before = buffer.clone();
    assert!(catch_unwind(AssertUnwindSafe(|| operation(buffer))).is_err());
    assert_eq!(*buffer, before);
}
