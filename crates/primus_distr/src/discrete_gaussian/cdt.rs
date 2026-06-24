use primus_integer::{AsInto, FheUint};
use rand::distr::Distribution;

/// CDT sampler using log-space computation
#[derive(Debug, Clone)]
pub struct CDTSampler<T: FheUint> {
    std_dev: f64,
    modulus_minus_one: T,
    cdt: Vec<u64>,
}

/// Log-sum-exp trick to compute log(sum(exp(log_values))) stably
/// This avoids numerical underflow when summing very small probabilities
fn log_sum_exp(log_values: &[f64]) -> f64 {
    if log_values.is_empty() {
        return f64::NEG_INFINITY;
    }

    // Find maximum value for numerical stability
    let max_log = log_values.iter().copied().fold(f64::NEG_INFINITY, f64::max);

    if max_log.is_infinite() && max_log.is_sign_negative() {
        return f64::NEG_INFINITY;
    }

    // Compute sum(exp(log_values - max_log))
    let sum_exp: f64 = log_values
        .iter()
        .map(|&log_val| (log_val - max_log).exp())
        .sum();

    max_log + sum_exp.ln()
}

impl<T: FheUint> CDTSampler<T> {
    /// Generate a CDT sampler using log-space arithmetic
    pub fn new(std_dev: f64, tail_cut: f64, modulus_minus_one: T) -> Self {
        let max_std_dev = std_dev * tail_cut;
        let mut length = max_std_dev.floor() as usize + 1;

        assert!(length <= 256, "CDT table too large: {}", length);
        if length <= 1 {
            length = 2;
        }

        // Compute PDF in log-space to avoid underflow
        // log(pdf[i]) = log(exp(-i²/(2σ²))) = -i²/(2σ²)
        let two_var = 2.0 * std_dev * std_dev; // 2σ²

        let mut log_pdf = vec![f64::NEG_INFINITY; length];

        // pdf[0] = 0.5 in linear space -> log(0.5) in log-space
        log_pdf[0] = 0.5f64.ln();

        // For i >= 1: log_pdf[i] = -i²/(2σ²)
        for (i, item) in log_pdf.iter_mut().enumerate().skip(1) {
            let i_f64 = i as f64;
            *item = -(i_f64 * i_f64) / two_var;
        }

        // Compute normalization constant in log-space
        // log(sum) = log_sum_exp(log_pdf)
        let log_sum = log_sum_exp(&log_pdf);

        // Normalize: log(pdf[i] / sum) = log_pdf[i] - log_sum
        let log_pdf_normalized: Vec<f64> = log_pdf.iter().map(|&log_p| log_p - log_sum).collect();

        // Convert to linear space for CDF computation
        let pdf_normalized: Vec<f64> = log_pdf_normalized
            .iter()
            .map(|&log_p| log_p.exp())
            .collect();

        // Build cumulative distribution
        let mut cdt_f64 = Vec::with_capacity(length + 1);
        let mut acc = 0.0;

        cdt_f64.push(0.0);
        for &p in pdf_normalized.iter() {
            acc += p;
            // Clamp to [0, 1] to handle floating-point errors
            cdt_f64.push(acc.min(1.0));
        }

        // Ensure last value is exactly 1.0
        if let Some(last) = cdt_f64.last_mut() {
            *last = 1.0;
        }

        assert_eq!(cdt_f64.len(), length + 1, "CDT length mismatch");

        // Map to u64 range [0, 2^64-1]
        let cdt: Vec<u64> = cdt_f64
            .into_iter()
            .map(|f| {
                // Use careful rounding to minimize quantization error
                let scaled = f * u64::MAX as f64;

                // Round to nearest u64
                if scaled >= u64::MAX as f64 {
                    u64::MAX
                } else {
                    (scaled + 0.5) as u64
                }
            })
            .collect();

        Self {
            std_dev,
            modulus_minus_one,
            cdt,
        }
    }

    /// Returns the standard deviation of this sampler
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.std_dev
    }
}

impl<T: FheUint> Distribution<T> for CDTSampler<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let r: u64 = rng.next_u64();

        let positive = (r & 1) == 1;

        // Binary search to find the right bin
        let idx = self.cdt.partition_point(|&x| x <= r) - 1;

        let v: T = idx.as_into();

        if v.is_zero() {
            return T::ZERO;
        }

        if positive {
            v
        } else {
            self.modulus_minus_one - v + T::ONE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_sum_exp() {
        // Test with widely separated values (others truly negligible)
        let values = vec![-1000.0, -1100.0, -1200.0];
        let result = log_sum_exp(&values);

        // Should be very close to max value since others are negligible
        // exp(-100) is on the order of 1e-44, so the contribution is truly negligible
        assert!((result - (-1000.0)).abs() < 1e-30);

        // Test with similar values
        let values = vec![0.0, 0.0, 0.0];
        let result = log_sum_exp(&values);
        // log(exp(0) + exp(0) + exp(0)) = log(3) ≈ 1.0986
        assert!((result - 3.0f64.ln()).abs() < 1e-10);

        // Test with moderately separated values
        let values = vec![-1000.0, -1001.0, -1002.0];
        let result = log_sum_exp(&values);
        // Result should be -1000 + ln(1 + exp(-1) + exp(-2)) ≈ -999.59
        let expected = -1000.0 + (1.0 + (-1.0f64).exp() + (-2.0f64).exp()).ln();
        assert!((result - expected).abs() < 1e-10);
    }

    #[test]
    fn test_sampler_creation() {
        let sampler = CDTSampler::<u64>::new(3.19, 12.0, u64::MAX - 1);
        assert!(!sampler.cdt.is_empty());

        // First value should be 0
        assert_eq!(sampler.cdt[0], 0);

        // Last value should be close to u64::MAX
        assert!(sampler.cdt.last().unwrap() >= &(u64::MAX - 1000));
    }
}
