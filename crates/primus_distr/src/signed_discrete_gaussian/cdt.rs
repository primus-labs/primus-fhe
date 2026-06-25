use std::marker::PhantomData;

use primus_integer::{AsInto, Integer};
use rand::distr::Distribution;

use crate::utils::log_sum_exp;

/// CDT sampler using log-space computation
#[derive(Debug, Clone)]
pub struct SignedCDTSampler<T: Integer> {
    std_dev: f64,
    cdt: Vec<u64>,
    phantom: PhantomData<T>,
}

impl<T: Integer> SignedCDTSampler<T> {
    /// Generate a CDT sampler using log-space arithmetic
    pub fn new(std_dev: f64, tail_cut: f64) -> Self {
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

        // Build CDF and quantize directly to u64 (single pass)
        let mut cdt = Vec::with_capacity(length + 1);
        let mut acc = 0.0_f64;
        cdt.push(0);

        for &p in pdf_normalized.iter() {
            acc += p;
            let scaled = acc.min(1.0) * (u64::MAX as f64);
            let val = if scaled >= u64::MAX as f64 {
                u64::MAX
            } else {
                (scaled + 0.5) as u64
            };
            cdt.push(val);
        }

        // Ensure last value is exactly MAX
        if let Some(last) = cdt.last_mut() {
            *last = u64::MAX;
        }

        assert_eq!(cdt.len(), length + 1, "CDT length mismatch");

        Self {
            std_dev,
            cdt,
            phantom: PhantomData,
        }
    }

    /// Returns the standard deviation of this sampler
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.std_dev
    }
}

impl<T: Integer> Distribution<T> for SignedCDTSampler<T> {
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

        if positive { v } else { T::ZERO - v }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sampler_creation() {
        let sampler = SignedCDTSampler::<i64>::new(3.19, 12.0);

        // First value should be 0
        assert_eq!(sampler.cdt[0], 0);

        // Last value should be close to u64::MAX
        assert!(sampler.cdt.last().unwrap() >= &(u64::MAX - 1000));
    }
}
