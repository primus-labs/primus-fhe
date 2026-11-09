//! Exact native phases and component products, without production transforms/codecs.
use primus_bgv::{
    BgvCiphertext, BgvClient, BgvContext, BgvEvaluator, BgvParameters, PlaintextEmbedding,
};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 32;
// Each independent prime is 1 modulo 64, 2, 254 and 257.
const Q: [u64; 2] = [1_125_899_874_704_257, 1_125_899_855_904_193];
// Independently generated smallest primitive 64-th root witnesses.
const ROOTS: [u64; 2] = [3_753_876_008_568, 41_405_469_103_074];
const SECRET: [i128; N] = [
    -1, 0, 1, 1, 0, -1, 1, 0, -1, 0, 1, 1, 0, -1, 1, 0, -1, 0, 1, 1, 0, -1, 1, 0, -1, 0, 1, 1, 0,
    -1, 1, 0,
];

fn context(p: u64) -> BgvContext {
    BgvContext::try_new(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(N),
            BarrettModulus::new(p),
            &Q.map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 3 },
        )
        .unwrap(),
    )
    .unwrap()
}
fn client(context: &BgvContext) -> BgvClient<'_> {
    let coefficients = GlweSecretKey::new(
        SECRET.iter().map(|&value| value as i64).collect::<Vec<_>>(),
        context.parameters().size().glwe_size(),
        SecretKeyDistr::SparseTernary,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficients, context.table());
    BgvClient::try_from_secret_key(context, key).unwrap()
}
fn mul(a: u64, b: u64, q: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(q)) as u64
}
fn pow(mut value: u64, mut exponent: u64, q: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = mul(result, value, q);
        }
        value = mul(value, value, q);
        exponent >>= 1;
    }
    result
}
fn points(limb: usize) -> [u64; N] {
    let q = Q[limb];
    let root = ROOTS[limb];
    assert_eq!(pow(root, N as u64, q), q - 1);
    std::array::from_fn(|i: usize| {
        let reversed = i.reverse_bits() >> (usize::BITS - N.ilog2());
        pow(root, (2 * reversed + 1) as u64, q)
    })
}
fn dft(coefficients: &[i128], limb: usize) -> Vec<u64> {
    let q = Q[limb];
    points(limb)
        .iter()
        .map(|&point| {
            coefficients.iter().rev().fold(0, |acc, &coefficient| {
                (mul(acc, point, q) + coefficient.rem_euclid(i128::from(q)) as u64) % q
            })
        })
        .collect()
}
fn inverse(values: &[u64], limb: usize) -> Vec<i128> {
    let q = Q[limb];
    let points = points(limb);
    (0..N)
        .map(|degree| {
            let sum = points.iter().zip(values).fold(0, |acc, (&point, &value)| {
                (acc + mul(value, pow(point, q - 1 - degree as u64, q), q)) % q
            });
            let value = mul(sum, pow(N as u64, q - 2, q), q);
            if value > q / 2 {
                i128::from(value) - i128::from(q)
            } else {
                i128::from(value)
            }
        })
        .collect()
}
fn product(lhs: &[i128], rhs: &[i128]) -> Vec<i128> {
    let mut result = vec![0; N];
    for (i, &left) in lhs.iter().enumerate() {
        for (j, &right) in rhs.iter().enumerate() {
            result[(i + j) % N] += left * right * if i + j < N { 1 } else { -1 };
        }
    }
    result
}
fn lift(message: &[u64], p: u64, embedding: PlaintextEmbedding) -> Vec<i128> {
    message
        .iter()
        .map(|&value| {
            if matches!(embedding, PlaintextEmbedding::Centered) && value >= p.div_ceil(2) {
                i128::from(value) - i128::from(p)
            } else {
                i128::from(value)
            }
        })
        .collect()
}
fn combine(lhs: &[i128], rhs: &[i128], sign: i128) -> Vec<i128> {
    lhs.iter().zip(rhs).map(|(&a, &b)| a + sign * b).collect()
}

// Both components are nontrivial. Build c0+c1*s=m+p*e using schoolbook
// coefficients and the independent DFT, without production encryption/encoding.
fn fixture(
    message: &[u64],
    p: u64,
    embedding: PlaintextEmbedding,
    offset: u64,
) -> (BgvCiphertext<Vec<u64>>, Vec<i128>) {
    let phase: Vec<_> = lift(message, p, embedding)
        .iter()
        .enumerate()
        .map(|(i, &message)| message + i128::from(p) * [-2, 0, 3, 1][i % 4])
        .collect();
    let c1: Vec<_> = (0..N)
        .map(|i| i128::from(offset) + i as i128 * 11)
        .collect();
    let c0 = combine(&phase, &product(&c1, &SECRET), -1);
    let mut ciphertext = vec![0; 4 * N];
    for limb in 0..2 {
        ciphertext[limb * N..(limb + 1) * N].copy_from_slice(&dft(&c0, limb));
        ciphertext[(2 + limb) * N..(3 + limb) * N].copy_from_slice(&dft(&c1, limb));
    }
    (BgvCiphertext::new(ciphertext), phase)
}
fn phase(ciphertext: &BgvCiphertext<Vec<u64>>, limb: usize) -> Vec<i128> {
    let q = Q[limb];
    let secret = dft(&SECRET, limb);
    let values: Vec<_> = (0..N)
        .map(|i| {
            (ciphertext.as_ref()[limb * N + i]
                + mul(ciphertext.as_ref()[(2 + limb) * N + i], secret[i], q))
                % q
        })
        .collect();
    inverse(&values, limb)
}
fn check(
    client: &mut BgvClient<'_>,
    ciphertext: &BgvCiphertext<Vec<u64>>,
    expected: &[i128],
    p: u64,
) {
    for limb in 0..2 {
        assert_eq!(phase(ciphertext, limb), expected);
    }
    assert_eq!(
        client.decrypt(ciphertext, 0).as_ref(),
        expected
            .iter()
            .map(|value| value.rem_euclid(i128::from(p)) as u64)
            .collect::<Vec<_>>()
    );
}

#[test]
fn linear_and_plaintext_operations_preserve_native_bgv_phase_and_components() {
    for p in [2, 254, 257] {
        let context = context(p);
        let mut client = client(&context);
        let mut evaluator = BgvEvaluator::new(&context, 0);
        let lhs_message: [u64; N] =
            std::array::from_fn(|i| [0, p - 1, p / 2, p.div_ceil(2), 1][i % 5]);
        let rhs_message: [u64; N] =
            std::array::from_fn(|i| [p - 1, p / 2, 1, 0, p.div_ceil(2)][i % 5]);
        let (lhs, lhs_phase) = fixture(&lhs_message, p, PlaintextEmbedding::Centered, 7);
        let (rhs, rhs_phase) = fixture(&rhs_message, p, PlaintextEmbedding::Unsigned, 29);
        let mut output = context.new_ciphertext(0);
        check(&mut client, &lhs, &lhs_phase, p);
        check(&mut client, &rhs, &rhs_phase, p);

        evaluator.add_to(&lhs.as_view(), &rhs.as_view(), &mut output.as_mut_view());
        check(&mut client, &output, &combine(&lhs_phase, &rhs_phase, 1), p);
        let mut assigned = lhs.clone();
        evaluator.add_assign(&mut assigned, &rhs);
        assert_eq!(assigned, output);
        evaluator.sub_to(&lhs, &rhs, &mut output);
        check(
            &mut client,
            &output,
            &combine(&lhs_phase, &rhs_phase, -1),
            p,
        );
        assigned = lhs.clone();
        evaluator.sub_assign(&mut assigned, &rhs);
        assert_eq!(assigned, output);
        evaluator.neg_to(&lhs, &mut output);
        check(&mut client, &output, &combine(&[0; N], &lhs_phase, -1), p);
        assigned = lhs.clone();
        evaluator.neg_assign(&mut assigned);
        assert_eq!(assigned, output);

        let plain = Polynomial(rhs_message.to_vec());
        for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
            let lifted = lift(&rhs_message, p, embedding);
            evaluator.add_plain_to(&lhs, &plain, &mut output, embedding);
            check(&mut client, &output, &combine(&lhs_phase, &lifted, 1), p);
            assert_eq!(&output.as_ref()[2 * N..], &lhs.as_ref()[2 * N..]);
            assigned = lhs.clone();
            evaluator.add_plain_assign(&mut assigned, &plain, embedding);
            assert_eq!(assigned, output);

            evaluator.mul_plain_to(&lhs, &plain, &mut output, embedding);
            check(&mut client, &output, &product(&lhs_phase, &lifted), p);
            // Checking both full native components catches a c0-only product,
            // even if phase/decode were accidentally tested with a zero secret.
            for component in 0..2 {
                for limb in 0..2 {
                    let start = (component * 2 + limb) * N;
                    let coefficients = inverse(&lhs.as_ref()[start..start + N], limb);
                    assert_eq!(
                        &output.as_ref()[start..start + N],
                        dft(&product(&coefficients, &lifted), limb)
                    );
                }
            }
            assigned = lhs.clone();
            evaluator.mul_plain_assign(&mut assigned, &plain, embedding);
            assert_eq!(assigned, output);
        }
    }
}

#[test]
fn invalid_lengths_and_plaintext_values_leave_outputs_unchanged() {
    let context = context(257);
    let mut evaluator = BgvEvaluator::new(&context, 0);
    let (input, _) = fixture(&[3; N], 257, PlaintextEmbedding::Centered, 7);
    let plain = Polynomial(vec![1; N]);
    let embedding = PlaintextEmbedding::Centered;
    for length in [0, 4 * N - 1, 4 * N + 1, 8 * N] {
        let wrong = BgvCiphertext::new(vec![0; length]);
        let mut output = BgvCiphertext::new(vec![0xfeed; 4 * N]);
        let before = output.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.add_to(
                &wrong,
                &input,
                &mut output
            )))
            .is_err()
        );
        assert_eq!(output, before);
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.sub_to(
                &input,
                &wrong,
                &mut output
            )))
            .is_err()
        );
        assert_eq!(output, before);
        assert!(catch_unwind(AssertUnwindSafe(|| evaluator.neg_to(&wrong, &mut output))).is_err());
        assert_eq!(output, before);
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.mul_plain_to(
                &wrong,
                &plain,
                &mut output,
                embedding
            )))
            .is_err()
        );
        assert_eq!(output, before);
        let mut wrong_output = BgvCiphertext::new(vec![0xfeed; length]);
        let before = wrong_output.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.add_to(
                &input,
                &input,
                &mut wrong_output
            )))
            .is_err()
        );
        assert_eq!(wrong_output, before);
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.add_plain_to(
                &input,
                &plain,
                &mut wrong_output,
                embedding
            )))
            .is_err()
        );
        assert_eq!(wrong_output, before);
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.mul_plain_to(
                &input,
                &plain,
                &mut wrong_output,
                embedding
            )))
            .is_err()
        );
        assert_eq!(wrong_output, before);
        let mut assigned = input.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(
                || evaluator.add_assign(&mut assigned, &wrong)
            ))
            .is_err()
        );
        assert_eq!(assigned, input);
        assert!(
            catch_unwind(AssertUnwindSafe(
                || evaluator.sub_assign(&mut assigned, &wrong)
            ))
            .is_err()
        );
        assert_eq!(assigned, input);
    }
    for values in [vec![], vec![0; N - 1], vec![0; N + 1], vec![257; N]] {
        let wrong = Polynomial(values);
        let mut output = BgvCiphertext::new(vec![0xfeed; 4 * N]);
        let before = output.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.add_plain_to(
                &input,
                &wrong,
                &mut output,
                embedding
            )))
            .is_err()
        );
        assert_eq!(output, before);
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.mul_plain_to(
                &input,
                &wrong,
                &mut output,
                embedding
            )))
            .is_err()
        );
        assert_eq!(output, before);
        let mut assigned = input.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.add_plain_assign(
                &mut assigned,
                &wrong,
                embedding
            )))
            .is_err()
        );
        assert_eq!(assigned, input);
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.mul_plain_assign(
                &mut assigned,
                &wrong,
                embedding
            )))
            .is_err()
        );
        assert_eq!(assigned, input);
    }
}
