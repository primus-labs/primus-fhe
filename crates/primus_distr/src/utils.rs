//! Shared numerical utilities used by Gaussian sampler implementations.

/// Log-sum-exp trick: compute `ln(Σ exp(x_i))` stably.
///
/// Avoids floating-point underflow when summing very small probabilities
/// represented in log-space.
pub(crate) fn log_sum_exp(log_values: &[f64]) -> f64 {
    if log_values.is_empty() {
        return f64::NEG_INFINITY;
    }
    let max_log = log_values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if max_log.is_infinite() && max_log.is_sign_negative() {
        return f64::NEG_INFINITY;
    }
    let sum_exp: f64 = log_values
        .iter()
        .map(|&log_val| (log_val - max_log).exp())
        .sum();
    max_log + sum_exp.ln()
}

/// Kahan compensated summation accumulator.
///
/// Reduces floating-point accumulation error from O(n·ε) to O(ε) by
/// tracking a running compensation term.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct KahanSum {
    sum: f64,
    compensation: f64,
}

impl KahanSum {
    /// Add `x` to the running total with compensation.
    #[inline]
    pub(crate) fn add(&mut self, x: f64) {
        let y = x - self.compensation;
        let t = self.sum + y;
        self.compensation = (t - self.sum) - y;
        self.sum = t;
    }

    /// Return the compensated sum.
    pub(crate) fn result(self) -> f64 {
        self.sum
    }
}
