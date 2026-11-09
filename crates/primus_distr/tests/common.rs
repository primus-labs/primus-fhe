use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    panic::{AssertUnwindSafe, catch_unwind},
};

use primus_distr::{
    SecretKeyDistr, SecretKeySampler, sample_crt_sparse_ternary_values_to,
    sample_fixed_hamming_weight_ternary_values_to, sample_sparse_ternary_values_to,
    sample_ternary_values_with_probabilities_to, sample_uniform_ternary_values_to,
};
use rand::{Rng, SeedableRng, TryCryptoRng, TryRng, rngs::StdRng};

// A scripted source solely for deterministic sampling-boundary tests.
struct Words(std::vec::IntoIter<u64>);
impl TryRng for Words {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.0.next().expect("scripted u32") as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.0.next().expect("scripted u64"))
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Infallible> {
        for chunk in output.chunks_mut(8) {
            chunk.copy_from_slice(&self.try_next_u64()?.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}
impl TryCryptoRng for Words {}

/// Scripted words make packed-bit order and partial-block RNG consumption deterministic.
#[test]
fn sparse_ternary_preserves_bit_order_and_random_word_count() {
    // Low-to-high pairs from 0xe4e4_1b1b, followed by the low pair of 2.
    let expected = [-1i8, 1, 0, 0, -1, 1, 0, 0, 0, 0, 1, -1, 0, 0, 1, -1, 1];
    for length in [0usize, 1, 15, 16, 17] {
        let script = [0xe4e4_1b1bu64, 2][..length.div_ceil(16)].to_vec();
        let mut rng = Words(script.into_iter());
        let mut output = vec![19i8; length];
        sample_sparse_ternary_values_to(&mut output, -1, &mut rng);
        assert_eq!(output, expected[..length]);
        assert!(rng.0.next().is_none());
    }
}

/// Probe exact integer thresholds and ensure invalid public inputs fail before writes or RNG use.
#[test]
fn ternary_threshold_boundaries_and_public_validation() {
    let quarter = 1u64 << 62;
    for (negative, positive, words, expected) in [
        (
            0.25,
            0.5,
            vec![
                0,
                quarter - 1,
                quarter,
                3 * quarter - 1,
                3 * quarter,
                u64::MAX,
            ],
            vec![-1, -1, 1, 1, 0, 0],
        ),
        (
            0.25,
            0.75,
            vec![0, quarter - 1, quarter, u64::MAX],
            vec![-1, -1, 1, 1],
        ),
        (2.0f64.powi(-64), 0.0, vec![0, 1, u64::MAX], vec![-1, 0, 0]),
        (0.0, 0.0, vec![0; 3], vec![0; 3]),
        (1.0, 0.0, vec![0; 3], vec![-1; 3]),
        (0.0, 1.0, vec![0; 3], vec![1; 3]),
    ] {
        let mut output = vec![19; expected.len()];
        sample_ternary_values_with_probabilities_to(
            &mut output,
            -1,
            negative,
            positive,
            &mut Words(words.clone().into_iter()),
        );
        assert_eq!(output, expected);
        let sampler = SecretKeySampler::<u32>::new(SecretKeyDistr::ternary(negative, positive));
        sampler.sample_signed_to(&mut output, &mut Words(words.into_iter()));
        assert_eq!(output, expected);
    }
    for (negative, positive) in [(-0.5, 0.5), (0.5, -0.5), (f64::NAN, 0.0), (0.7, 0.4)] {
        let mut output = [19; 6];
        let mut rng = StdRng::seed_from_u64(401);
        let mut expected_rng = StdRng::seed_from_u64(401);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                sample_ternary_values_with_probabilities_to(
                    &mut output,
                    -1,
                    negative,
                    positive,
                    &mut rng,
                )
            }))
            .is_err()
        );
        assert_eq!(output, [19; 6]);
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}

/// Enumerate every accepted base-three block and exercise byte rejection with scripted RNG.
#[test]
fn uniform_ternary_blocks_cover_all_five_trit_patterns() {
    // Reject these first four bytes, then enumerate all 3^5 accepted bytes.
    let mut words = vec![0xffff_fefd];
    words.extend(
        (0..244u32)
            .step_by(4)
            .map(|i| u64::from(i | ((i + 1) << 8) | ((i + 2) << 16) | ((i + 3) << 24))),
    );
    let mut output = vec![19i32; 243 * 5];
    sample_uniform_ternary_values_to(&mut output, -1, &mut Words(words.into_iter()));
    assert!(output.iter().all(|&v| (-1..=1).contains(&v)));
    assert_eq!(
        output
            .as_chunks::<5>()
            .0
            .iter()
            .collect::<BTreeSet<_>>()
            .len(),
        243
    );
}

/// Enumerate a tiny complete sample space; equal counts prove support without a statistical threshold.
#[test]
fn fixed_weight_ternary_has_uniform_support_and_independent_signs() {
    // For n=3,h=2, enumerate all 2*3 insertion choices and all four sign pairs.
    // There are 12 possible signed vectors, each reached by two choice sequences.
    let mut counts = BTreeMap::new();
    for first in 0..2u64 {
        for second in 0..3u64 {
            for signs in 0..4 {
                // Midpoints of the Uniform<usize> sampler's u32 acceptance bins.
                let words = vec![
                    signs,
                    ((2 * first + 1) << 31) / 2,
                    ((2 * second + 1) << 31) / 3,
                ];
                let mut output = [19i32; 3];
                sample_fixed_hamming_weight_ternary_values_to(
                    &mut output,
                    -1,
                    2,
                    &mut Words(words.into_iter()),
                );
                assert_eq!(output.iter().filter(|&&v| v != 0).count(), 2);
                *counts.entry(output).or_insert(0) += 1;
            }
        }
    }
    assert_eq!(counts.len(), 12);
    assert!(counts.values().all(|&count| count == 2));
}

/// Residues across each CRT row must encode the same signed sample, including tile boundaries.
#[test]
fn crt_tiles_encode_one_shared_logical_sample() {
    // Include q=2, where the positive and negative residue are indistinguishable.
    let minus_ones = [1u64, 96, 192, u64::MAX];
    for length in [1, 15, 16, 17, 255, 256, 257, 513] {
        let mut expected = vec![19i32; length];
        sample_sparse_ternary_values_to(&mut expected, -1, &mut StdRng::seed_from_u64(402));
        let mut output = vec![19u64; length * minus_ones.len()];
        sample_crt_sparse_ternary_values_to(
            &mut output,
            length,
            &minus_ones,
            &mut StdRng::seed_from_u64(402),
        );
        for (limb, minus_one) in output.chunks_exact(length).zip(minus_ones) {
            for (&actual, &signed) in limb.iter().zip(&expected) {
                assert_eq!(
                    actual,
                    match signed {
                        -1 => minus_one,
                        0 => 0,
                        1 => 1,
                        _ => unreachable!(),
                    }
                );
            }
        }
    }
}
