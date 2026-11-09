// cargo r -r -p primus_distr --example compare_samplers -- 3.19
//
// Compares the accuracy of available discrete Gaussian samplers at one or more
// requested sigma values. Results are descriptive and non-gating; use the
// Criterion benchmarks for construction and throughput measurements.
//   - CDTSampler (f64 precision, portable, default while its support fits)
//   - DiscreteZiggurat (large σ)
//   - PreciseCDTSampler (256-bit precision, high_precision feature only)

use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use rand::{SeedableRng, distr::Distribution, rngs::StdRng};
use std::{env, process};

use primus_distr::{
    CDTSampler, DiscreteGaussian, DiscreteZiggurat, MIN_STANDARD_DEVIATION, stats::gaussian_stats,
};

#[cfg(feature = "high_precision")]
use primus_distr::PreciseCDTSampler;

type ValueT = u64;

// Modulus for discrete Gaussian sampling
const Q: ValueT = 1125899906826241;

// Number of samples for statistical analysis (2^20 = 1,048,576)
const N: usize = 1 << 20;
const SEED: u64 = 0x434f_4d50_4152_452d;

// Tail cut for discrete Gaussian
const TAIL_CUT: f64 = 12.0;

// Sigma ranges to test for cumulative probability
const SIGMA_RANGES: [f64; 6] = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

fn coloured_pct_cell(diff_pct: f64) -> Cell {
    let colour = if diff_pct.abs() > 1.0 {
        Color::Red
    } else if diff_pct.abs() > 0.5 {
        Color::Yellow
    } else {
        Color::Green
    };
    Cell::new(format!("{:+.2}%", diff_pct)).fg(colour)
}

// ---------------------------------------------------------------------------
// Per-sampler statistics
// ---------------------------------------------------------------------------

struct SamplerStats {
    name: String,
    actual_std: f64,
    std_error_pct: f64,
    cumulative_probs: Vec<f64>,
}

// ---------------------------------------------------------------------------
// Display tables
// ---------------------------------------------------------------------------

fn display_accuracy_table(sigma: f64, theoretical_probs: &[f64], all_stats: &[SamplerStats]) {
    println!("\n{}", "━".repeat(100));
    println!("Accuracy (σ = {:.4})", sigma);
    println!("{}", "━".repeat(100));

    let mut table = Table::new();
    table
        .load_style(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Sampler").add_attribute(Attribute::Bold),
        Cell::new("Expected σ").add_attribute(Attribute::Bold),
        Cell::new("Actual σ").add_attribute(Attribute::Bold),
        Cell::new("σ Error %").add_attribute(Attribute::Bold),
        Cell::new("Avg Prob Err %").add_attribute(Attribute::Bold),
        Cell::new("Max Prob Err %").add_attribute(Attribute::Bold),
        Cell::new("Quality").add_attribute(Attribute::Bold),
    ]);

    for stats in all_stats {
        let error_colour = if stats.std_error_pct.abs() < 0.1 {
            Color::Green
        } else if stats.std_error_pct.abs() < 0.5 {
            Color::Yellow
        } else {
            Color::Red
        };

        let prob_errors: Vec<f64> = stats
            .cumulative_probs
            .iter()
            .zip(theoretical_probs.iter())
            .map(|(&actual, &expected)| {
                if expected > 0.0 {
                    ((actual - expected) / expected * 100.0).abs()
                } else {
                    0.0
                }
            })
            .collect();

        let avg_prob_error = prob_errors.iter().sum::<f64>() / prob_errors.len() as f64;
        let max_prob_error = prob_errors
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max);

        let quality = if stats.std_error_pct.abs() < 0.1 && avg_prob_error < 0.1 {
            Cell::new("★★★ Excellent").fg(Color::Green)
        } else if stats.std_error_pct.abs() < 0.5 && avg_prob_error < 0.5 {
            Cell::new("★★☆ Very Good").fg(Color::Cyan)
        } else if stats.std_error_pct.abs() < 1.0 && avg_prob_error < 1.0 {
            Cell::new("★☆☆ Good").fg(Color::Yellow)
        } else {
            Cell::new("☆☆☆ Acceptable").fg(Color::Red)
        };

        table.add_row(vec![
            Cell::new(&stats.name),
            Cell::new(format!("{:.10}", sigma)),
            Cell::new(format!("{:.10}", stats.actual_std)),
            Cell::new(format!("{:+.4}%", stats.std_error_pct)).fg(error_colour),
            Cell::new(format!("{:.4}%", avg_prob_error)),
            Cell::new(format!("{:.4}%", max_prob_error)),
            quality,
        ]);
    }

    println!("{}", table);
}

fn display_probability_table(sigma: f64, theoretical_probs: &[f64], all_stats: &[SamplerStats]) {
    println!("\n{}", "━".repeat(100));
    println!(
        "Cumulative Probability P(|X| <= n*σ) — Difference from Theory (σ = {:.2})",
        sigma
    );
    println!("{}", "━".repeat(100));

    let mut header: Vec<Cell> = vec![Cell::new("Sampler").add_attribute(Attribute::Bold)];
    for &n_sigma in SIGMA_RANGES.iter() {
        header.push(Cell::new(format!("±{}σ", n_sigma)).add_attribute(Attribute::Bold));
    }
    header.push(Cell::new("Avg |diff|%").add_attribute(Attribute::Bold));

    let mut table = Table::new();
    table
        .load_style(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(header);

    for stats in all_stats {
        let mut row = vec![Cell::new(&stats.name)];

        let mut avg_abs_diff = 0.0_f64;
        for (idx, &_n_sigma) in SIGMA_RANGES.iter().enumerate() {
            let actual = stats.cumulative_probs[idx];
            let expected = theoretical_probs[idx];
            let diff_pct = if expected > 0.0 {
                (actual - expected) / expected * 100.0
            } else {
                0.0
            };
            avg_abs_diff += diff_pct.abs();
            row.push(coloured_pct_cell(diff_pct));
        }

        avg_abs_diff /= SIGMA_RANGES.len() as f64;
        row.push(Cell::new(format!("{:.2}%", avg_abs_diff)));

        table.add_row(row);
    }

    println!("{}", table);
}

// ---------------------------------------------------------------------------
// Compare all samplers at a single sigma value
// ---------------------------------------------------------------------------

fn analyze_sampler<D>(name: &str, sigma: f64, sampler: &D) -> SamplerStats
where
    D: Distribution<ValueT>,
{
    let mut rng = StdRng::seed_from_u64(SEED);
    let data: Vec<ValueT> = sampler.sample_iter(&mut rng).take(N).collect();
    let mut counts = [0usize; SIGMA_RANGES.len()];
    let (_, actual_std) = gaussian_stats(&data, Q, sigma, &SIGMA_RANGES, &mut counts);

    SamplerStats {
        name: name.into(),
        actual_std,
        std_error_pct: ((actual_std - sigma) / sigma) * 100.0,
        cumulative_probs: counts.iter().map(|&c| c as f64 / N as f64).collect(),
    }
}

fn compare_samplers_at_sigma(sigma: f64) {
    println!("\n{}", "═".repeat(100));
    println!("Comparing Samplers at σ = {:.2}", sigma);
    println!("{}", "═".repeat(100));

    let mut theoretical_probs = [0f64; SIGMA_RANGES.len()];
    primus_distr::stats::theoretical_cumulative_probs(
        sigma,
        TAIL_CUT,
        &SIGMA_RANGES,
        &mut theoretical_probs,
    );

    let mut all_stats: Vec<SamplerStats> = Vec::new();

    match CDTSampler::<ValueT>::new(sigma, TAIL_CUT, Q - 1) {
        Ok(sampler) => {
            println!("  Analyzing CDTSampler (f64 precision)...");
            all_stats.push(analyze_sampler("CDTSampler (f64)", sigma, &sampler));
        }
        Err(error) => println!("  CDTSampler unavailable: {error}"),
    }

    match DiscreteZiggurat::<ValueT>::new(sigma, TAIL_CUT, Q - 1) {
        Ok(sampler) => {
            println!("  Analyzing Discrete Ziggurat...");
            all_stats.push(analyze_sampler("Discrete Ziggurat", sigma, &sampler));
        }
        Err(error) => println!("  Discrete Ziggurat unavailable: {error}"),
    }

    #[cfg(feature = "high_precision")]
    match PreciseCDTSampler::<ValueT>::new(sigma, TAIL_CUT, Q - 1) {
        Ok(sampler) => {
            println!("  Analyzing PreciseCDTSampler (256-bit precision)...");
            all_stats.push(analyze_sampler("PreciseCDTSampler", sigma, &sampler));
        }
        Err(error) => println!("  PreciseCDTSampler unavailable: {error}"),
    }

    match DiscreteGaussian::<ValueT>::new(sigma, Q - 1) {
        Ok(DiscreteGaussian::Cdt(_)) => {
            println!("  DiscreteGaussian facade selection: CDTSampler")
        }
        Ok(DiscreteGaussian::Ziggurat(_)) => {
            println!("  DiscreteGaussian facade selection: Discrete Ziggurat")
        }
        Err(error) => println!("  DiscreteGaussian facade unavailable: {error}"),
    }
    display_accuracy_table(sigma, &theoretical_probs, &all_stats);
    display_probability_table(sigma, &theoretical_probs, &all_stats);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let sigmas = if arguments.is_empty() {
        vec![0.8, 1.5, 3.19, 9.0, 15.0, 20.0]
    } else {
        arguments
            .iter()
            .map(|argument| {
                let sigma = argument.parse::<f64>().unwrap_or_else(|_| {
                    eprintln!("invalid sigma: {argument}");
                    eprintln!(
                        "usage: cargo run --release -p primus_distr --example compare_samplers -- [SIGMA ...]"
                    );
                    process::exit(2);
                });
                if !sigma.is_finite() || sigma < MIN_STANDARD_DEVIATION {
                    eprintln!(
                        "sigma must be finite and at least {MIN_STANDARD_DEVIATION}: {argument}"
                    );
                    process::exit(2);
                }
                sigma
            })
            .collect()
    };

    println!("\n{}", "═".repeat(100));
    println!("Discrete Gaussian Sampler Accuracy Comparison (non-gating)");
    println!("Samples per test: {}", N);
    println!("Testing {} sigma values: {:?}", sigmas.len(), sigmas);
    println!("{}\n", "═".repeat(100));

    for sigma in sigmas {
        compare_samplers_at_sigma(sigma);
    }

    println!("\n{}", "═".repeat(100));
    println!("Exploratory comparison completed (non-gating).");
    println!("{}", "═".repeat(100));
}
