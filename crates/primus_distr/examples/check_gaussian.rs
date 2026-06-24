// cargo r -r -p primus_distr --example check_gaussian
//
// Validates discrete Gaussian sampler implementations by checking:
// - Standard deviation accuracy across multiple sigma values
// - Cumulative probability distribution P(|X| <= n*sigma) for n = 1..6
// - Convolution property: sum of CHUNK_SIZE independent N(0, sigma^2)
//   samples should follow N(0, CHUNK_SIZE * sigma^2)
//
// Edit main() to choose which sampler to validate (CDTSampler or
// DiscreteZiggurat), or uncomment both blocks to test side by side.

use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use primus_distr::stats;
use rand::distr::Distribution;

type ValueT = u64;

// Modulus for discrete Gaussian sampling
const Q: ValueT = 1125899906826241;

// Number of samples for statistical analysis (2^20 = 1,048,576)
const N: usize = 1 << 20;

// Number of distributions to sum for convolution test
const CHUNK_SIZE: usize = 10;

// Tail cut for discrete Gaussian (must match the sampler's tail_cut parameter)
const TAIL_CUT: f64 = 12.0;

// Sigma ranges to test for cumulative probability
const SIGMA_RANGES: [f64; 6] = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];

// Quality thresholds for standard deviation error (percentage)
const QUALITY_EXCELLENT: f64 = 0.1;
const QUALITY_VERY_GOOD: f64 = 0.5;
const QUALITY_GOOD: f64 = 1.0;
const QUALITY_ACCEPTABLE: f64 = 2.0;

// Probability difference thresholds for colour coding
const PROB_DIFF_RED_THRESHOLD: f64 = 0.01;
const PROB_DIFF_YELLOW_THRESHOLD: f64 = 0.005;
const PROB_DIFF_PCT_RED_THRESHOLD: f64 = 1.0;
const PROB_DIFF_PCT_YELLOW_THRESHOLD: f64 = 0.5;

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

fn quality_level(error_pct: f64) -> &'static str {
    let abs_error = error_pct.abs();
    if abs_error < QUALITY_EXCELLENT {
        "✓ Excellent"
    } else if abs_error < QUALITY_VERY_GOOD {
        "✓ Very Good"
    } else if abs_error < QUALITY_GOOD {
        "○ Good"
    } else if abs_error < QUALITY_ACCEPTABLE {
        "△ Acceptable"
    } else {
        "✗ Poor"
    }
}

fn coloured_diff_cell(diff: f64) -> Cell {
    let colour = if diff.abs() > PROB_DIFF_RED_THRESHOLD {
        Color::Red
    } else if diff.abs() > PROB_DIFF_YELLOW_THRESHOLD {
        Color::Yellow
    } else {
        Color::Green
    };
    Cell::new(format!("{:+.6}", diff)).fg(colour)
}

fn coloured_pct_cell(diff_pct: f64) -> Cell {
    let colour = if diff_pct.abs() > PROB_DIFF_PCT_RED_THRESHOLD {
        Color::Red
    } else if diff_pct.abs() > PROB_DIFF_PCT_YELLOW_THRESHOLD {
        Color::Yellow
    } else {
        Color::Green
    };
    Cell::new(format!("{:+.2}%", diff_pct)).fg(colour)
}

// ---------------------------------------------------------------------------
// Report output
// ---------------------------------------------------------------------------

fn report_std_dev(sigma: f64, actual_std: f64, label: &str) {
    let std_error = actual_std - sigma;
    let std_error_pct = (std_error / sigma) * 100.0;

    println!("\n{}", "─".repeat(80));
    if label.is_empty() {
        println!("  Standard Deviation Analysis (σ = {:.2})", sigma);
    } else {
        println!(
            "  {} — Standard Deviation Analysis (σ = {:.2})",
            label, sigma
        );
    }
    println!("{}", "─".repeat(80));
    println!("  Expected:  {:.10}", sigma);
    println!("  Actual:    {:.10}", actual_std);
    println!("  Error:     {:+.10} (absolute)", std_error);
    println!("             {:+.4}% (relative)", std_error_pct);
    println!("  Quality:   {}", quality_level(std_error_pct));
}

fn report_cumulative_probs(sigma: f64, counts: &[usize], theoretical_probs: &[f64], label: &str) {
    let actual_probs: Vec<f64> = counts.iter().map(|&c| c as f64 / N as f64).collect();

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Range").add_attribute(Attribute::Bold),
        Cell::new("σ Value").add_attribute(Attribute::Bold),
        Cell::new("Actual P(|X| ≤ nσ)").add_attribute(Attribute::Bold),
        Cell::new("Expected P(|X| ≤ nσ)").add_attribute(Attribute::Bold),
        Cell::new("Diff").add_attribute(Attribute::Bold),
        Cell::new("Diff %").add_attribute(Attribute::Bold),
    ]);

    for i in 0..SIGMA_RANGES.len() {
        let n_sigma = SIGMA_RANGES[i];
        let actual = actual_probs[i];
        let expected = theoretical_probs[i];
        let diff = actual - expected;
        let diff_pct = if expected > 0.0 {
            diff / expected * 100.0
        } else {
            0.0
        };

        table.add_row(vec![
            Cell::new(format!("±{}σ", n_sigma)),
            Cell::new(format!("±{:.2}", n_sigma * sigma)),
            Cell::new(format!("{:.6} ({:.2}%)", actual, actual * 100.0)),
            Cell::new(format!("{:.6} ({:.2}%)", expected, expected * 100.0)),
            coloured_diff_cell(diff),
            coloured_pct_cell(diff_pct),
        ]);
    }

    if label.is_empty() {
        println!(
            "\n  Cumulative Probability Distribution (σ = {:.2}):",
            sigma
        );
    } else {
        println!(
            "\n  {} — Cumulative Probability Distribution (σ = {:.2}):",
            label, sigma
        );
    }
    println!("{}", table);
}

// ---------------------------------------------------------------------------
// Core validation logic (generic over the sampler)
// ---------------------------------------------------------------------------

/// Run the full validation suite (std dev, cumulative probs, convolution)
/// for a single sampler at a single sigma value.
///
/// `distr` is taken by reference — `rand` provides a blanket impl of
/// [`Distribution`] for `&D`, so no clone overhead is incurred.
fn validate_sampler<D>(sampler_name: &str, sigma: f64, distr: &D, rng: &mut impl rand::Rng)
where
    D: Distribution<ValueT>,
{
    let mut data = vec![0u64; N];

    println!("[{sampler_name}] Testing σ = {:.2}...", sigma);

    // Sample data
    data.iter_mut()
        .zip(distr.sample_iter(&mut *rng))
        .for_each(|(d, v)| *d = v);

    // Compute statistics
    let mut counts = [0usize; SIGMA_RANGES.len()];
    let (_mean, actual_std) = stats::gaussian_stats(&data, Q, sigma, &SIGMA_RANGES, &mut counts);
    let mut theoretical_probs = [0f64; SIGMA_RANGES.len()];
    stats::theoretical_cumulative_probs(sigma, TAIL_CUT, &SIGMA_RANGES, &mut theoretical_probs);

    // Report
    report_std_dev(sigma, actual_std, sampler_name);
    report_cumulative_probs(sigma, &counts, &theoretical_probs, sampler_name);

    // --- Convolution test ---
    // Sum of CHUNK_SIZE independent N(0, sigma^2) samples should be
    // distributed as N(0, CHUNK_SIZE * sigma^2).
    println!(
        "\n  Testing convolution property (sum of {} independent distributions)...",
        CHUNK_SIZE
    );

    // Accumulate CHUNK_SIZE batches into convolved, modulo Q
    let mut convolved = vec![0u64; N];
    for (c, s) in convolved
        .iter_mut()
        .zip(distr.sample_iter(&mut *rng).take(N))
    {
        *c = s;
    }
    for _ in 1..CHUNK_SIZE {
        for (c, s) in convolved.iter_mut().zip(distr.sample_iter(&mut *rng)) {
            *c = (*c + s) % Q;
        }
    }

    let conv_sigma = (CHUNK_SIZE as f64).sqrt() * sigma;
    let mut conv_counts = [0usize; SIGMA_RANGES.len()];
    let (_conv_mean, conv_actual_std) =
        stats::gaussian_stats(&convolved, Q, conv_sigma, &SIGMA_RANGES, &mut conv_counts);
    let mut conv_theoretical_probs = [0f64; SIGMA_RANGES.len()];
    stats::theoretical_cumulative_probs(
        conv_sigma,
        TAIL_CUT,
        &SIGMA_RANGES,
        &mut conv_theoretical_probs,
    );

    let conv_label = format!("Convolution ({sampler_name})");
    report_std_dev(conv_sigma, conv_actual_std, &conv_label);
    report_cumulative_probs(
        conv_sigma,
        &conv_counts,
        &conv_theoretical_probs,
        &conv_label,
    );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let mut rng = rand::rng();

    println!("\n{}", "═".repeat(80));
    println!("Discrete Gaussian Sampler Validation");
    println!("Samples per test: {}", N);
    println!("{}\n", "═".repeat(80));

    // ---- Choose sampler(s) to validate (edit / uncomment below) ----

    // CDTSampler (f64 precision, portable; efficient for sigma <= 20):
    {
        let sigmas = [0.7, 0.8, 0.9, 1.0, 3.19, 10.0, 15.0, 20.0];
        for &sigma in &sigmas {
            let distr = primus_distr::CDTSampler::<ValueT>::new(sigma, TAIL_CUT, Q - 1);
            validate_sampler("CDTSampler", sigma, &distr, &mut rng);
        }
    }

    // DiscreteZiggurat (efficient for sigma >= 10):
    // {
    //     let sigmas = [10.0, 15.0, 20.0, 25.0, 30.0];
    //     for &sigma in &sigmas {
    //         let distr = primus_distr::DiscreteZiggurat::<ValueT>::new(sigma, TAIL_CUT, Q - 1);
    //         validate_sampler("DiscreteZiggurat", sigma, &distr, &mut rng);
    //     }
    // }

    println!("\n{}", "═".repeat(80));
    println!("All tests completed!");
    println!("{}", "═".repeat(80));
}
