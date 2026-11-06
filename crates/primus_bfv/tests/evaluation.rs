//! Linear/plaintext semantics checked with independent integer and direct-DFT oracles.

use primus_bfv::{
    BfvCiphertext, BfvClient, BfvContext, BfvEvaluator, BfvParameters, PlaintextEmbedding,
};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 32;
const Q: [u64; 2] = [1_125_899_906_826_241, 1_125_899_906_629_633];
// Independently fixed primitive 64th-root witnesses for the bit-reversed NTT order.
const ROOTS_64: [u64; 2] = [18_105_782_770_620, 34_361_371_622_355];
const SECRET: [i64; N] = [
    -1, 0, 1, 1, 0, -1, 1, 0, -1, 0, 1, 1, 0, -1, 1, 0, -1, 0, 1, 1, 0, -1, 1, 0, -1, 0, 1, 1, 0,
    -1, 1, 0,
];

fn context(t: u64) -> BfvContext {
    let parameters = BfvParameters::try_with_error_distribution(
        PolyLength::new(N),
        BarrettModulus::new(t),
        BarrettModulus::new(2_199_023_190_017),
        &Q.map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::CenteredBinomial { eta: 1 },
    )
    .unwrap();
    BfvContext::try_with_levels(parameters, 2).unwrap()
}

fn client(context: &BfvContext) -> BfvClient<'_> {
    let coefficient_key = GlweSecretKey::new(
        SECRET.to_vec(),
        context.parameters().size().glwe_size(),
        SecretKeyDistr::SparseTernary,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, context.table());
    BfvClient::try_from_secret_key(context, key).unwrap()
}

fn mul(left: u64, right: u64, q: u64) -> u64 {
    (u128::from(left) * u128::from(right) % u128::from(q)) as u64
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
    let root = ROOTS_64[limb];
    assert_eq!(pow(root, N as u64, q), q - 1);
    std::array::from_fn(|index| {
        let reversed = index.reverse_bits() >> (usize::BITS - N.ilog2());
        pow(root, (2 * reversed + 1) as u64, q)
    })
}

fn dft(input: &[u64], limb: usize) -> Vec<u64> {
    let q = Q[limb];
    points(limb)
        .iter()
        .map(|&point| {
            input
                .iter()
                .rev()
                .fold(0, |acc, &value| (mul(acc, point, q) + value) % q)
        })
        .collect()
}

fn lift(value: u64, t: u64, embedding: PlaintextEmbedding) -> i128 {
    if matches!(embedding, PlaintextEmbedding::Centered) && value >= t.div_ceil(2) {
        i128::from(value) - i128::from(t)
    } else {
        i128::from(value)
    }
}

fn encoded(message: &[u64], count: usize, t: u64, embedding: PlaintextEmbedding) -> Vec<u64> {
    let delta = Q[..count].iter().map(|&q| i128::from(q)).product::<i128>() / i128::from(t);
    Q[..count]
        .iter()
        .flat_map(|&q| {
            message.iter().map(move |&value| {
                (delta * lift(value, t, embedding)).rem_euclid(i128::from(q)) as u64
            })
        })
        .collect()
}

fn negacyclic(lhs: &[i128], rhs: &[i128]) -> Vec<i128> {
    let mut output = vec![0; N];
    for (i, &left) in lhs.iter().enumerate() {
        for (j, &right) in rhs.iter().enumerate() {
            output[(i + j) % N] += left * right * if i + j < N { 1 } else { -1 };
        }
    }
    output
}

// Construct native ciphertexts with nonzero c1 and exact scaled phases without
// production encoding, encryption, NTT or phase extraction. Tests below compare
// every output phase, so changing both components incorrectly cannot hide in a
// message-only round trip.
fn ciphertext(
    context: &BfvContext,
    level: usize,
    message: &[u64],
    embedding: PlaintextEmbedding,
    mask_offset: u64,
) -> BfvCiphertext<Vec<u64>> {
    let count = context.codec(level).moduli_count();
    let phase = encoded(message, count, context.codec(level).t(), embedding);
    let mut data = vec![0; 2 * N * count];
    let secret: Vec<_> = SECRET.iter().map(|&value| i128::from(value)).collect();
    for (limb, &q) in Q[..count].iter().enumerate() {
        let c1: Vec<_> = (0..N)
            .map(|index| mask_offset + 11 * index as u64 + 7 * limb as u64)
            .collect();
        let product = negacyclic(
            &c1.iter()
                .map(|&value| i128::from(value))
                .collect::<Vec<_>>(),
            &secret,
        );
        let c0: Vec<_> = phase[limb * N..(limb + 1) * N]
            .iter()
            .zip(product)
            .map(|(&value, product)| (i128::from(value) - product).rem_euclid(i128::from(q)) as u64)
            .collect();
        data[limb * N..(limb + 1) * N].copy_from_slice(&dft(&c0, limb));
        data[(count + limb) * N..(count + limb + 1) * N].copy_from_slice(&dft(&c1, limb));
    }
    BfvCiphertext::from_raw(data)
}

fn phase(input: &BfvCiphertext<Vec<u64>>, count: usize) -> Vec<u64> {
    let mut output = Vec::with_capacity(count * N);
    for (limb, &q) in Q[..count].iter().enumerate() {
        let points = points(limb);
        let values: Vec<_> = points
            .iter()
            .enumerate()
            .map(|(index, &point)| {
                let secret = SECRET.iter().rev().fold(0, |acc, &value| {
                    (mul(acc, point, q) + i128::from(value).rem_euclid(i128::from(q)) as u64) % q
                });
                (input.as_ref()[limb * N + index]
                    + mul(input.as_ref()[(count + limb) * N + index], secret, q))
                    % q
            })
            .collect();
        let inverse_n = pow(N as u64, q - 2, q);
        for degree in 0..N {
            let sum = points.iter().zip(&values).fold(0, |acc, (&point, &value)| {
                (acc + mul(value, pow(point, q - 1 - degree as u64, q), q)) % q
            });
            output.push(mul(sum, inverse_n, q));
        }
    }
    output
}

fn combine(lhs: &[u64], rhs: &[u64], count: usize, sign: i128) -> Vec<u64> {
    lhs.iter()
        .zip(rhs)
        .enumerate()
        .map(|(index, (&left, &right))| {
            (i128::from(left) + sign * i128::from(right)).rem_euclid(i128::from(Q[index / N]))
                as u64
        })
        .take(count * N)
        .collect()
}

fn message_combine(lhs: &[u64], rhs: &[u64], t: u64, sign: i128) -> Vec<u64> {
    lhs.iter()
        .zip(rhs)
        .map(|(&left, &right)| {
            (i128::from(left) + sign * i128::from(right)).rem_euclid(i128::from(t)) as u64
        })
        .collect()
}

fn check(
    client: &mut BfvClient<'_>,
    input: &BfvCiphertext<Vec<u64>>,
    level: usize,
    expected_phase: &[u64],
    expected_message: &[u64],
) {
    assert_eq!(phase(input, Q.len() - level), expected_phase);
    assert_eq!(
        client.decrypt_at_level(input, level).as_ref(),
        expected_message
    );
}

#[test]
fn linear_and_plaintext_operations_match_independent_phases_and_negacyclic_messages() {
    for t in [2, 254, 257] {
        let context = context(t);
        let mut client = client(&context);
        let lhs_message: [u64; N] = std::array::from_fn(|index| {
            [0, t - 1, t / 2, t.div_ceil(2), 1, 0, t - 1, 1][index % 8]
        });
        let rhs_message: [u64; N] =
            std::array::from_fn(|index| [t - 1, 1, 0, t / 2, 1, t - 1, 1, 0][index % 8]);
        for level in 0..context.level_count() {
            let count = Q.len() - level;
            let mut evaluator = BfvEvaluator::new(&context, level);
            let lhs = ciphertext(
                &context,
                level,
                &lhs_message,
                PlaintextEmbedding::Centered,
                3,
            );
            let rhs = ciphertext(
                &context,
                level,
                &rhs_message,
                PlaintextEmbedding::Unsigned,
                17,
            );
            let lhs_phase = phase(&lhs, count);
            let rhs_phase = phase(&rhs, count);
            let mut output = context.new_ciphertext(level);

            evaluator.add_to(&lhs.as_view(), &rhs.as_view(), &mut output.as_mut_view());
            check(
                &mut client,
                &output,
                level,
                &combine(&lhs_phase, &rhs_phase, count, 1),
                &message_combine(&lhs_message, &rhs_message, t, 1),
            );
            let mut assigned = lhs.clone();
            evaluator.add_assign(&mut assigned.as_mut_view(), &rhs.as_view());
            assert_eq!(assigned.as_ref(), output.as_ref());

            evaluator.sub_to(&lhs, &rhs, &mut output);
            check(
                &mut client,
                &output,
                level,
                &combine(&lhs_phase, &rhs_phase, count, -1),
                &message_combine(&lhs_message, &rhs_message, t, -1),
            );
            assigned = lhs.clone();
            evaluator.sub_assign(&mut assigned, &rhs);
            assert_eq!(assigned.as_ref(), output.as_ref());

            evaluator.neg_to(&lhs, &mut output);
            check(
                &mut client,
                &output,
                level,
                &combine(&vec![0; count * N], &lhs_phase, count, -1),
                &message_combine(&[0; N], &lhs_message, t, -1),
            );
            assigned = lhs.clone();
            evaluator.neg_assign(&mut assigned);
            assert_eq!(assigned.as_ref(), output.as_ref());

            let plain = Polynomial(rhs_message.to_vec());
            for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
                evaluator.add_plain_to(&lhs, &plain, &mut output, embedding);
                check(
                    &mut client,
                    &output,
                    level,
                    &combine(
                        &lhs_phase,
                        &encoded(&rhs_message, count, t, embedding),
                        count,
                        1,
                    ),
                    &message_combine(&lhs_message, &rhs_message, t, 1),
                );
                assert_eq!(
                    &output.as_ref()[count * N..],
                    &lhs.as_ref()[count * N..],
                    "plaintext addition retains the native c1 component"
                );
                assigned = lhs.clone();
                evaluator.add_plain_assign(&mut assigned, &plain, embedding);
                assert_eq!(assigned.as_ref(), output.as_ref());

                evaluator.mul_plain_to(&lhs, &plain, &mut output, embedding);
                let lifted: Vec<_> = rhs_message
                    .iter()
                    .map(|&value| lift(value, t, embedding))
                    .collect();
                let expected_phase: Vec<_> = lhs_phase
                    .as_chunks::<N>()
                    .0
                    .iter()
                    .enumerate()
                    .flat_map(|(limb, phase)| {
                        negacyclic(
                            &phase
                                .iter()
                                .map(|&value| i128::from(value))
                                .collect::<Vec<_>>(),
                            &lifted,
                        )
                        .into_iter()
                        .map(move |value| value.rem_euclid(i128::from(Q[limb])) as u64)
                    })
                    .collect();
                let expected_message: Vec<_> = negacyclic(
                    &lhs_message
                        .iter()
                        .map(|&value| i128::from(value))
                        .collect::<Vec<_>>(),
                    &rhs_message
                        .iter()
                        .map(|&value| i128::from(value))
                        .collect::<Vec<_>>(),
                )
                .into_iter()
                .map(|value| value.rem_euclid(i128::from(t)) as u64)
                .collect();
                check(
                    &mut client,
                    &output,
                    level,
                    &expected_phase,
                    &expected_message,
                );
                assigned = lhs.clone();
                evaluator.mul_plain_assign(&mut assigned, &plain, embedding);
                assert_eq!(assigned.as_ref(), output.as_ref());
            }
        }
    }
}

#[test]
fn rejected_boundaries_leave_complete_outputs_unchanged() {
    let context = context(257);
    let mut evaluator = BfvEvaluator::new(&context, 1);
    assert!(catch_unwind(|| BfvEvaluator::new(&context, 2)).is_err());
    let input = ciphertext(&context, 1, &[3; N], PlaintextEmbedding::Unsigned, 1);
    let rhs = ciphertext(&context, 1, &[7; N], PlaintextEmbedding::Centered, 2);
    let plain = Polynomial(vec![1; N]);
    let embedding = PlaintextEmbedding::Centered;
    for length in [0, 2 * N - 1, 2 * N + 1, 4 * N] {
        let wrong = BfvCiphertext::from_raw(vec![0; length]);
        let mut output = BfvCiphertext::from_raw(vec![0xfeed; 2 * N]);
        let before = output.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.add_to(
                &wrong,
                &rhs,
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
            catch_unwind(AssertUnwindSafe(|| evaluator.add_plain_to(
                &wrong,
                &plain,
                &mut output,
                embedding
            )))
            .is_err()
        );
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
        let mut wrong_output = BfvCiphertext::from_raw(vec![0xfeed; length]);
        let before = wrong_output.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.add_to(
                &input,
                &rhs,
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
    }
    for values in [vec![], vec![0; N - 1], vec![0; N + 1], vec![257; N]] {
        let wrong = Polynomial(values);
        let mut output = BfvCiphertext::from_raw(vec![0xfeed; 2 * N]);
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
