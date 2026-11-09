//! Tiny deterministic fixtures validate diagnostic math without statistical sampling.
use primus_distr::stats::{gaussian_stats, theoretical_cumulative_probs};

const Q: u64 = 17;

/// Hand-computed signed moments validate centering and range counts on ten fixed samples.
#[test]
fn gaussian_stats_centers_samples_and_computes_moments() {
    let samples = [1u64, 2, 3, 4, 16, 16, 15, 15, 14, 13];
    let mut counts = [0usize; 3];
    let (mean, std) = gaussian_stats(&samples, Q, 2.0, &[1.0, 2.0, 3.0], &mut counts);

    assert!((mean - (-0.3)).abs() < 1e-10);
    assert!((std - 6.41f64.sqrt()).abs() < 1e-10);
    assert_eq!(counts, [6, 10, 10]);
}

/// Cumulative mass is monotone and saturates at the configured truncated support.
#[test]
fn theoretical_probabilities_are_clamped_to_truncated_support() {
    let ranges = [0.0, 1.0, 3.0, 12.0, 100.0];
    let mut out = [0.0; 5];
    theoretical_cumulative_probs(3.19, 12.0, &ranges, &mut out);

    for w in out.windows(2) {
        assert!(w[0] <= w[1]);
    }
    assert!(out[0] > 0.0);
    assert_eq!(out[3], 1.0);
    assert_eq!(out[4], 1.0);
}
