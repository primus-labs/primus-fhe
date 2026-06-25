//! Statistical analysis of discrete Gaussian samples in modular representation.
//!
//! This module provides allocation-free utilities for computing mean, standard
//! deviation, and cumulative probability counts from FHE noise samples.

use primus_integer::FheUint;

/// Convert a modular value to a centered i128 and f64 in one step.
///
/// Both representations share a single `half_q` check:
/// - `(i128)` — exact, used for high-precision sum accumulation.
/// - `(f64)` — used for absolute-value comparison against sigma limits.
///
/// Values in `[0, half_q]` are treated as non-negative; values in
/// `(half_q, modulus)` are treated as negative (`x - modulus`).
#[inline]
fn to_centered_parts<T: FheUint>(x: T, half_q: T, modulus_i128: i128) -> (i128, f64) {
    if x <= half_q {
        let signed: i128 = x.as_into();
        (signed, signed as f64)
    } else {
        let val: i128 = x.as_into();
        let signed = val - modulus_i128;
        (signed, signed as f64)
    }
}

/// Convert a modular value to a centered f64.
///
/// Used in the variance pass where we only need f64.
#[inline]
fn to_centered_f64<T: FheUint>(x: T, half_q: T, modulus_f64: f64) -> f64 {
    if x <= half_q {
        x.as_into()
    } else {
        let val: f64 = x.as_into();
        val - modulus_f64
    }
}

/// Compute (mean, standard deviation) and cumulative counts for discrete
/// Gaussian samples given in modular representation.
///
/// The sum is accumulated in `i128` for exactness; counts use `f64`
/// comparison (lossless for modulus values up to 2^53).
///
/// # Parameters
/// - `samples` — modular values in `[0, modulus)`.
/// - `modulus` — the ring modulus `Q`; the upper half `(Q/2, Q)` is
///   interpreted as negative values.
/// - `sigma` — expected standard deviation (only used for the
///   `ranges * sigma` limits).
/// - `ranges` — sigma multipliers for cumulative counting.
/// - `counts` — output buffer (same length as `ranges`).
///   On return, `counts[i]` = number of samples with
///   `|x_centered| <= ranges[i] * sigma`.
///
/// # Returns
/// `(mean, std_dev)` where `std_dev` is the square root of the
/// population variance.
///
/// # Panics
/// - If `counts.len() != ranges.len()`.
pub fn gaussian_stats<T: FheUint>(
    samples: &[T],
    modulus: T,
    sigma: f64,
    ranges: &[f64],
    counts: &mut [usize],
) -> (f64, f64) {
    assert_eq!(
        counts.len(),
        ranges.len(),
        "counts must have the same length as ranges"
    );

    let n = samples.len();
    if n == 0 {
        counts.fill(0);
        return (0.0, 0.0);
    }

    let half_q = modulus >> 1u32;
    let modulus_f64: f64 = modulus.as_into();
    let modulus_i128: i128 = modulus.as_into();

    // Precompute sigma * range limits (small, constant-size allocation)
    let limits_f64: Vec<f64> = ranges.iter().map(|&r| (r * sigma).floor()).collect();

    // First pass: i128 sum (exact) and cumulative counts (f64 comparison)
    let mut sum: i128 = 0;
    counts.fill(0);

    for &x in samples {
        let (signed_i128, signed_f64) = to_centered_parts(x, half_q, modulus_i128);
        sum += signed_i128;

        let abs_val = signed_f64.abs();
        for (j, &limit) in limits_f64.iter().enumerate() {
            if abs_val <= limit {
                counts[j] += 1;
            }
        }
    }

    let mean = sum as f64 / n as f64;

    // Second pass: variance (f64 is sufficient — Gaussian samples are
    // tightly concentrated around the mean)
    let mut variance_sum = 0.0f64;
    for &x in samples {
        let diff = to_centered_f64(x, half_q, modulus_f64) - mean;
        variance_sum += diff * diff;
    }

    let std_dev = (variance_sum / n as f64).sqrt();

    (mean, std_dev)
}

/// Compute theoretical cumulative probabilities under a truncated discrete
/// Gaussian.
///
/// For each `r` in `ranges`, computes `P(|X| <= r * sigma)` under the
/// discrete distribution `p(k) ∝ exp(-k² / (2σ²))`, truncated at
/// `|k| <= sigma * tail_cut`.
///
/// # Parameters
/// - `sigma` — standard deviation of the underlying continuous Gaussian.
/// - `tail_cut` — truncation radius in multiples of `sigma` (must match the
///   sampler's internal parameter, typically `12.0`).
/// - `ranges` — sigma multipliers at which to evaluate cumulative probability.
/// - `out` — output buffer (same length as `ranges`).
///   On return, `out[i] = P(|X| <= ranges[i] * sigma)`.
///
/// # Panics
/// - If `out.len() != ranges.len()`.
pub fn theoretical_cumulative_probs(sigma: f64, tail_cut: f64, ranges: &[f64], out: &mut [f64]) {
    assert_eq!(
        out.len(),
        ranges.len(),
        "out must have the same length as ranges"
    );

    let gaussian_pdf = |k: i64| -> f64 {
        let k_f = k as f64;
        (-k_f * k_f / (2.0 * sigma * sigma)).exp()
    };

    // Normalisation constant (sum of truncated PDF)
    let norm_limit = (sigma * tail_cut).ceil() as i64;
    let mut z = gaussian_pdf(0);
    for k in 1..=norm_limit {
        z += 2.0 * gaussian_pdf(k);
    }

    // Compute cumulative probability for each range
    for (i, &n_sigma) in ranges.iter().enumerate() {
        let limit = (n_sigma * sigma).floor() as i64;
        let mut prob = gaussian_pdf(0);
        for k in 1..=limit {
            prob += 2.0 * gaussian_pdf(k);
        }
        out[i] = prob / z;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A modulus small enough for hand-calculated expected values.
    // Q = 17 makes 0..=8 the non-negative half and 9..=16 the negative half
    // (where 9 represents -8, 10 = -7, ..., 16 = -1).
    const Q: u64 = 17;
    const HALF_Q: u64 = Q >> 1; // = 8

    // -----------------------------------------------------------------------
    // to_centered_parts / to_centered_f64
    // -----------------------------------------------------------------------

    #[test]
    fn test_centered_parts_zero() {
        let (i, f) = to_centered_parts(0u64, HALF_Q, Q as i128);
        assert_eq!(i, 0);
        assert_eq!(f, 0.0);
    }

    #[test]
    fn test_centered_parts_half_q() {
        // 8 is exactly at the boundary → non-negative
        let (i, f) = to_centered_parts(8u64, HALF_Q, Q as i128);
        assert_eq!(i, 8);
        assert_eq!(f, 8.0);
    }

    #[test]
    fn test_centered_parts_negative_one() {
        // 16 in Q=17 means -1 (16 - 17 = -1)
        let (i, f) = to_centered_parts(16u64, HALF_Q, Q as i128);
        assert_eq!(i, -1);
        assert_eq!(f, -1.0);
    }

    #[test]
    fn test_centered_parts_negative_max() {
        // 9 in Q=17 means -8 (9 - 17 = -8)
        let (i, f) = to_centered_parts(9u64, HALF_Q, Q as i128);
        assert_eq!(i, -8);
        assert_eq!(f, -8.0);
    }

    #[test]
    fn test_centered_f64_matches_parts() {
        // to_centered_f64 should produce the same f64 as to_centered_parts
        let modulus_f64 = Q as f64;
        for x in [0u64, 3, 8, 12, 16] {
            let (_, f_from_parts) = to_centered_parts(x, HALF_Q, Q as i128);
            let f_direct = to_centered_f64(x, HALF_Q, modulus_f64);
            assert_eq!(f_from_parts, f_direct, "mismatch for x={x}");
        }
    }

    // -----------------------------------------------------------------------
    // gaussian_stats
    // -----------------------------------------------------------------------

    #[test]
    fn test_gaussian_stats_empty() {
        let mut counts = [0usize; 3];
        let (mean, std) = gaussian_stats(&[] as &[u64], Q, 1.0, &[1.0, 2.0, 3.0], &mut counts);
        assert_eq!(mean, 0.0);
        assert_eq!(std, 0.0);
        assert_eq!(counts, [0, 0, 0]);
    }

    #[test]
    fn test_gaussian_stats_all_zeros() {
        // Centred value of 0 is 0 — mean 0, std 0, all counts = n.
        let samples = [0u64; 100];
        let mut counts = [0usize; 3];
        let (mean, std) = gaussian_stats(&samples, Q, 1.0, &[1.0, 2.0, 3.0], &mut counts);
        assert!((mean - 0.0).abs() < 1e-10);
        assert!((std - 0.0).abs() < 1e-10);
        // |0| <= any positive limit
        assert_eq!(counts, [100, 100, 100]);
    }

    #[test]
    fn test_gaussian_stats_known_values() {
        // Centered values: +1,+2,+3,+4, -1,-1,-2,-2,-3,-4
        // Sum = -3, mean = -0.3.
        // Sum of squares = 65.
        // Population variance = 65/10 - (-0.3)² = 6.5 - 0.09 = 6.41.
        // Std = sqrt(6.41).
        // With sigma=2: limits = 2, 4, 6.
        //   |x|<=2: +1,+2,-1,-1,-2,-2 = 6
        //   |x|<=4: +3,+4,-3,-4 on top = 10
        //   |x|<=6: all 10
        let samples = [1u64, 2, 3, 4, 16, 16, 15, 15, 14, 13];
        let mut counts = [0usize; 3];

        let (mean, std) = gaussian_stats(&samples, Q, 2.0, &[1.0, 2.0, 3.0], &mut counts);

        let expected_std = 6.41f64.sqrt();
        assert!((mean - (-0.3)).abs() < 1e-10);
        assert!((std - expected_std).abs() < 1e-10);
        assert_eq!(counts, [6, 10, 10]);
    }

    #[test]
    fn test_gaussian_stats_negative_values() {
        // All values are in the upper half → all negative
        let samples = [16u64; 10]; // 16 = -1
        let mut counts = [0usize; 3];
        let (mean, std) = gaussian_stats(&samples, Q, 2.0, &[1.0, 2.0, 3.0], &mut counts);
        assert!((mean - (-1.0)).abs() < 1e-10);
        assert!((std - 0.0).abs() < 1e-10);
        // |-1| = 1, sigma=2 → limits 2,4,6 → all counts = 10
        assert_eq!(counts, [10, 10, 10]);
    }

    #[test]
    #[should_panic(expected = "counts must have the same length as ranges")]
    fn test_gaussian_stats_mismatched_counts() {
        let samples = [1u64, 2, 3];
        let mut counts = [0usize; 4]; // 4 != 3
        gaussian_stats(&samples, Q, 1.0, &[1.0, 2.0, 3.0], &mut counts);
    }

    // -----------------------------------------------------------------------
    // theoretical_cumulative_probs
    // -----------------------------------------------------------------------

    #[test]
    fn test_theoretical_probs_monotonic() {
        let ranges = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let mut out = [0f64; 6];
        theoretical_cumulative_probs(3.19, 12.0, &ranges, &mut out);

        // Probabilities should strictly increase with range
        for w in out.windows(2) {
            assert!(w[0] < w[1], "not monotonic: {} >= {}", w[0], w[1]);
        }

        // P(|X| <= 0*σ) = 0, P(|X| <= large) ≈ 1
        assert!(out[0] > 0.0);
        assert!(out[5] > 0.9999, "6-sigma prob too low: {}", out[5]);
    }

    #[test]
    fn test_theoretical_probs_small_sigma_symmetry() {
        // At sigma = 1.0, PDF is concentrated at 0.
        // P(|X| <= 1σ) should be high since most mass is at k=0, ±1.
        let ranges = [1.0, 2.0, 3.0];
        let mut out = [0f64; 3];
        theoretical_cumulative_probs(1.0, 12.0, &ranges, &mut out);

        // After normalisation with tail_cut=12, the mass at k=0 is
        // proportional to exp(0) = 1. k=±1: exp(-0.5) ≈ 0.6065 each.
        // norm_z ≈ 1 + 2*0.6065 + 2*exp(-2) + ... ≈ 1+1.213+2*0.135+...
        // P(|X|<=1) = (1 + 2*0.6065) / norm_z ≈ 2.213 / ~2.56 ≈ 0.864
        assert!(out[0] > 0.85, "P(|X|<=1σ) too low: {}", out[0]);
        assert!(out[2] > 0.999, "P(|X|<=3σ) too low: {}", out[2]);
    }

    #[test]
    #[should_panic(expected = "out must have the same length as ranges")]
    fn test_theoretical_probs_mismatched_output() {
        let mut out = [0f64; 3]; // 3 != 4
        theoretical_cumulative_probs(3.19, 12.0, &[1.0, 2.0, 3.0, 4.0], &mut out);
    }

    #[test]
    fn test_theoretical_probs_tail_cut_effect() {
        // A small tail_cut truncates more mass, so normalised probabilities
        // should differ from a large tail_cut.
        let mut small_tail = [0f64; 1];
        let mut large_tail = [0f64; 1];
        theoretical_cumulative_probs(3.19, 3.0, &[1.0], &mut small_tail);
        theoretical_cumulative_probs(3.19, 12.0, &[1.0], &mut large_tail);

        // The short tail loses mass in the tails → normalisation factor Z is
        // smaller → density at k=0 receives more relative weight →
        // P(|X|<=1σ) is higher with short tail cut.
        assert!(small_tail[0] > large_tail[0]);
    }
}
