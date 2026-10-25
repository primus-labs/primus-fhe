//! Statistical analysis of discrete Gaussian samples in modular representation.
//!
//! These diagnostics favor explicit numeric contracts over support for every
//! integer representation. They are intended for validation tools, not sampler
//! hot paths.

use primus_integer::FheUint;

use crate::gaussian_core::GaussianParameters;

const MAX_EXACT_F64_INTEGER: u128 = 1 << 53;

/// Converts a canonical residue to its exact centered representative.
#[inline]
fn to_centered(x: u128, half_q: u128, modulus: u128) -> i128 {
    if x <= half_q {
        x as i128
    } else {
        x as i128 - modulus as i128
    }
}

/// Compute (mean, standard deviation) and cumulative counts for discrete
/// Gaussian samples given in modular representation.
///
/// The modulus is restricted to `2^53` so every canonical residue and centered
/// representative is exact in both `i128` and `f64`. A small temporary vector
/// of `ranges.len()` integer limits is allocated once per call. The sample sum
/// is exact: limiting both the modulus and sample count to `2^53` bounds its
/// magnitude below `2^105`, within `i128`.
///
/// # Parameters
/// - `samples` — modular values in `[0, modulus)`.
/// - `modulus` — the ring modulus `Q`; the upper half `(Q/2, Q)` is
///   interpreted as negative values.
/// - `sigma` — finite, positive expected standard deviation, used only for the
///   `ranges * sigma` limits.
/// - `ranges` — finite, non-negative sigma multipliers for cumulative counting.
/// - `counts` — output buffer (same length as `ranges`).
///   On return, `counts[i]` = number of samples with
///   `|x_centered| <= ranges[i] * sigma`.
///
/// # Returns
/// `(mean, std_dev)` where `std_dev` is the square root of the
/// population variance.
///
/// # Panics
/// Panics if the output length differs from `ranges.len()`, the modulus is zero
/// or larger than `2^53`, a sample is not in `[0, modulus)`, a floating-point
/// parameter is invalid, the sample count cannot be represented exactly as an
/// `f64`.
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

    let modulus: u128 = modulus.as_into();
    assert!(modulus > 0, "modulus must be positive");
    assert!(
        modulus <= MAX_EXACT_F64_INTEGER,
        "modulus must not exceed 2^53"
    );
    assert!(
        sigma.is_finite() && sigma > 0.0,
        "sigma must be finite and positive"
    );
    assert!(
        samples.len() as u128 <= MAX_EXACT_F64_INTEGER,
        "sample count must not exceed 2^53"
    );

    let half_q = modulus >> 1;
    let limits: Vec<i128> = ranges
        .iter()
        .map(|&range| {
            assert!(
                range.is_finite() && range >= 0.0,
                "ranges must be finite and non-negative"
            );
            let limit = range * sigma;
            assert!(limit.is_finite(), "range times sigma must be finite");
            limit.floor().min(half_q as f64) as i128
        })
        .collect();

    counts.fill(0);

    let n = samples.len();
    if n == 0 {
        return (0.0, 0.0);
    }

    let mut sum: i128 = 0;

    for &x in samples {
        let x: u128 = x.as_into();
        assert!(x < modulus, "samples must be canonical residues");
        let centered = to_centered(x, half_q, modulus);
        sum += centered;

        let magnitude = centered.abs();
        for (count, &limit) in counts.iter_mut().zip(&limits) {
            if magnitude <= limit {
                *count += 1;
            }
        }
    }

    let mean = sum as f64 / n as f64;

    let mut variance_sum = 0.0f64;
    for &x in samples {
        let x: u128 = x.as_into();
        let diff = to_centered(x, half_q, modulus) as f64 - mean;
        variance_sum += diff * diff;
    }

    let std_dev = (variance_sum / n as f64).sqrt();

    (mean, std_dev)
}

/// Compute theoretical cumulative probabilities under a truncated discrete
/// Gaussian.
///
/// For each `r` in `ranges`, computes `P(|X| <= r * sigma)` under the
/// discrete distribution `p(k) ∝ exp(-k² / (2σ²))`, truncated at the sampler's
/// inclusive support `max(1, floor(sigma * tail_cut))`. Ranges beyond that
/// support are clamped and therefore return exactly `1.0`.
///
/// # Parameters
/// - `sigma` — finite, positive standard deviation of the underlying
///   continuous Gaussian.
/// - `tail_cut` — finite, positive truncation radius in multiples of `sigma`
///   (must match the sampler's internal parameter, typically `12.0`).
/// - `ranges` — finite, non-negative sigma multipliers at which to evaluate
///   cumulative probability.
/// - `out` — output buffer (same length as `ranges`).
///   On return, `out[i] = P(|X| <= ranges[i] * sigma)`.
///
/// # Panics
/// Panics if the output length differs from `ranges.len()`, the Gaussian
/// parameters are outside the sampler's supported domain, the truncated
/// support exceeds `2^53`, or a range is invalid.
pub fn theoretical_cumulative_probs(sigma: f64, tail_cut: f64, ranges: &[f64], out: &mut [f64]) {
    assert_eq!(
        out.len(),
        ranges.len(),
        "out must have the same length as ranges"
    );

    let parameters = GaussianParameters::new(sigma, tail_cut)
        .unwrap_or_else(|error| panic!("invalid Gaussian parameters: {error}"));
    let support = parameters.maximum_magnitude();
    assert!(
        u128::from(support) <= MAX_EXACT_F64_INTEGER,
        "truncated support must not exceed 2^53"
    );
    let variance = sigma * sigma;

    let gaussian_pdf = |k: u64| -> f64 {
        let k_f = k as f64;
        (-k_f * k_f / (2.0 * variance)).exp()
    };

    let mut z = gaussian_pdf(0);
    for k in 1..=support {
        z += 2.0 * gaussian_pdf(k);
    }

    for (i, &n_sigma) in ranges.iter().enumerate() {
        assert!(
            n_sigma.is_finite() && n_sigma >= 0.0,
            "ranges must be finite and non-negative"
        );
        let scaled_range = n_sigma * sigma;
        assert!(scaled_range.is_finite(), "range times sigma must be finite");
        let limit = scaled_range.floor().min(support as f64) as u64;
        if limit == support {
            out[i] = 1.0;
            continue;
        }

        let mut prob = gaussian_pdf(0);
        for k in 1..=limit {
            prob += 2.0 * gaussian_pdf(k);
        }
        out[i] = prob / z;
    }
}
