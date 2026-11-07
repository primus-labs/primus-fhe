//! Degree-two native tensor components and phases against schoolbook/DFT oracles.

use dashu_int::UBig;
use primus_bgv::advanced::{BgvQuadraticCiphertext, square_to, tensor_to};
use primus_bgv::{BgvCiphertext, BgvContext, BgvParameters};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 32;
const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];

fn context(p: u64) -> BgvContext {
    BgvContext::try_with_levels(
        BgvParameters::try_coefficients(
            PolyLength::new(N),
            BarrettModulus::new(p),
            &Q.map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
        3,
    )
    .unwrap()
}

fn multiply(a: u64, b: u64, q: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(q)) as u64
}

fn power(mut value: u64, mut exponent: u64, q: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, value, q);
        }
        value = multiply(value, value, q);
        exponent >>= 1;
    }
    result
}

fn evaluation_points(q: u64) -> Vec<u64> {
    // The documented backend convention picks the smallest primitive 2N-th root.
    // Find it independently; no NTT table or production transform is used here.
    let witness = (2..)
        .map(|candidate| power(candidate, (q - 1) / (2 * N) as u64, q))
        .find(|&root| power(root, N as u64, q) == q - 1)
        .unwrap();
    let root = (0..N)
        .map(|index| power(witness, (2 * index + 1) as u64, q))
        .min()
        .unwrap();
    (0usize..N)
        .map(|index| {
            let reversed = index.reverse_bits() >> (usize::BITS - N.ilog2());
            power(root, (2 * reversed + 1) as u64, q)
        })
        .collect()
}

fn dft(coefficients: &[i128], q: u64) -> Vec<u64> {
    evaluation_points(q)
        .iter()
        .map(|&point| {
            coefficients.iter().rev().fold(0, |value, &coefficient| {
                (multiply(value, point, q) + coefficient.rem_euclid(i128::from(q)) as u64) % q
            })
        })
        .collect()
}

fn product(lhs: &[i128], rhs: &[i128]) -> Vec<i128> {
    let mut output = vec![0; N];
    for (i, &left) in lhs.iter().enumerate() {
        for (j, &right) in rhs.iter().enumerate() {
            output[(i + j) % N] += left * right * if i + j < N { 1 } else { -1 };
        }
    }
    output
}

fn add(lhs: &[i128], rhs: &[i128]) -> Vec<i128> {
    lhs.iter()
        .zip(rhs)
        .map(|(&left, &right)| left + right)
        .collect()
}

fn ciphertext(components: &[Vec<i128>; 2], count: usize) -> BgvCiphertext<Vec<u64>> {
    BgvCiphertext::from_raw(
        components
            .iter()
            .flat_map(|component| Q[..count].iter().flat_map(|&q| dft(component, q)))
            .collect::<Vec<_>>(),
    )
}

fn verify_quadratic(
    output: &BgvQuadraticCiphertext<Vec<u64>>,
    expected_components: &[Vec<i128>; 3],
    expected_phase: &[i128],
    secret: &[i128],
    count: usize,
) {
    let length = N * count;
    assert_eq!(output.as_ref().len(), 3 * length);
    for (component, expected) in output
        .as_ref()
        .chunks_exact(length)
        .zip(expected_components)
    {
        for (actual, &q) in component.as_chunks::<N>().0.iter().zip(&Q[..count]) {
            assert_eq!(actual.as_slice(), dft(expected, q));
        }
    }
    // Evaluate the s² phase independently, so a rank-2 reinterpretation using
    // unrelated linear secrets cannot pass merely by returning correct lengths.
    for (limb, &q) in Q[..count].iter().enumerate() {
        let s = dft(secret, q);
        let expected = dft(expected_phase, q);
        for i in 0..N {
            let c0 = output.as_ref()[limb * N + i];
            let c1 = output.as_ref()[length + limb * N + i];
            let c2 = output.as_ref()[2 * length + limb * N + i];
            assert_eq!(
                (c0 + multiply(c1, s[i], q) + multiply(c2, multiply(s[i], s[i], q), q)) % q,
                expected[i]
            );
        }
    }
}

#[test]
fn dense_and_monomial_tensors_and_squares_match_independent_phases_at_every_level() {
    let product_q = Q
        .iter()
        .fold(UBig::ONE, |product, &q| product * UBig::from(q));
    assert!(product_q > UBig::from(u128::MAX));
    let secret: Vec<_> = (0..N).map(|i| [-1, 1, 0, 1][i % 4]).collect();
    for p in [2, 193] {
        let context = context(p);
        for monomial in [false, true] {
            let lhs: [Vec<i128>; 2] = std::array::from_fn(|component| {
                (0..N)
                    .map(|i| {
                        if monomial {
                            if i == N - 1 - component { -7 } else { 0 }
                        } else {
                            ((i * 7 + component * 3) % 13) as i128 - 6
                        }
                    })
                    .collect()
            });
            let rhs: [Vec<i128>; 2] = std::array::from_fn(|component| {
                (0..N)
                    .map(|i| {
                        if monomial {
                            if i == 2 + component { 5 } else { 0 }
                        } else {
                            ((i * 11 + component * 5) % 17) as i128 - 8
                        }
                    })
                    .collect()
            });
            let lhs_phase = add(&lhs[0], &product(&lhs[1], &secret));
            let rhs_phase = add(&rhs[0], &product(&rhs[1], &secret));
            for level in 0..context.level_count() {
                let count = Q.len() - level;
                let left = ciphertext(&lhs, count);
                let right = ciphertext(&rhs, count);
                let mut output = context.new_quadratic_ciphertext(level);
                tensor_to(&context, level, &left, &right, &mut output);
                verify_quadratic(
                    &output,
                    &[
                        product(&lhs[0], &rhs[0]),
                        add(&product(&lhs[0], &rhs[1]), &product(&lhs[1], &rhs[0])),
                        product(&lhs[1], &rhs[1]),
                    ],
                    &product(&lhs_phase, &rhs_phase),
                    &secret,
                    count,
                );
                square_to(&context, level, &left, &mut output);
                verify_quadratic(
                    &output,
                    &[
                        product(&lhs[0], &lhs[0]),
                        product(&lhs[0], &lhs[1])
                            .iter()
                            .map(|value| 2 * value)
                            .collect(),
                        product(&lhs[1], &lhs[1]),
                    ],
                    &product(&lhs_phase, &lhs_phase),
                    &secret,
                    count,
                );
                let squared = output.clone();
                tensor_to(&context, level, &left, &left, &mut output);
                assert_eq!(squared, output);
            }
        }
    }
}

#[test]
fn tensor_rejects_malformed_and_other_level_storage_before_writes() {
    let context = context(193);
    for level in 0..context.level_count() {
        let input = context.new_ciphertext(level);
        let length = context.rns_poly_len(level);
        for bad_length in [0, 2 * length - 1, 2 * length + 1, 3 * length] {
            let malformed = BgvCiphertext::from_raw(vec![0; bad_length]);
            let mut output = BgvQuadraticCiphertext::from_raw(vec![0xfeed; 3 * length]);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    tensor_to(&context, level, &malformed, &input, &mut output);
                }))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    tensor_to(&context, level, &input, &malformed, &mut output);
                }))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
            assert!(
                catch_unwind(AssertUnwindSafe(|| square_to(
                    &context,
                    level,
                    &malformed,
                    &mut output
                )))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
        }
        for bad_length in [0, 3 * length - 1, 3 * length + 1, 2 * length] {
            let mut output = BgvQuadraticCiphertext::from_raw(vec![0xfeed; bad_length]);
            assert!(
                catch_unwind(AssertUnwindSafe(|| tensor_to(
                    &context,
                    level,
                    &input,
                    &input,
                    &mut output
                )))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
            assert!(
                catch_unwind(AssertUnwindSafe(|| square_to(
                    &context,
                    level,
                    &input,
                    &mut output
                )))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
        }
        for other_level in (0..context.level_count()).filter(|&other| other != level) {
            let wrong_level = context.new_ciphertext(other_level);
            let mut output = BgvQuadraticCiphertext::from_raw(vec![0xfeed; 3 * length]);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    tensor_to(&context, level, &input, &wrong_level, &mut output);
                }))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
        }
    }
}
