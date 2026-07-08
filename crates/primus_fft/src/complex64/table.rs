use std::f64::consts::PI;
use std::sync::Arc;

use num_complex::Complex64;
use rustfft::{Fft, FftPlanner};

use crate::error::FftError;
use crate::table::FftTable;
use crate::torus::TorusFftValue;

/// Full-length complex negacyclic FFT table backed by `rustfft`.
///
/// This is the **reference backend**: it stores the full `N` complex values
/// (`fourier_length == poly_length == N`). It is simple and correct, making it
/// suitable for testing and for verifying correctness of optimized backends.
///
/// # TFHE storage note
///
/// Production TFHE typically stores only `N / 2` complex values by exploiting
/// real-input conjugate symmetry. A `PackedComplex64FftTable` backend will be
/// added later to match this convention. Until then, Fourier ciphertext types
/// that use this table will carry the full-length representation.
///
/// Pre-computes twist factors `psi^j` for `j = 0..N-1` where
/// `psi = exp(pi * i / N)`, together with the scaled inverse twist factors
/// `conj(psi^j) / N` so the inverse transform only needs a single complex
/// multiply per coefficient.
pub struct FullComplex64FftTable {
    log_n: u32,
    poly_length: usize,
    fourier_length: usize,
    forward: Arc<dyn Fft<f64>>,
    inverse: Arc<dyn Fft<f64>>,
    twist: Vec<Complex64>,
    inv_twist_scaled: Vec<Complex64>,
}

impl FullComplex64FftTable {
    /// Returns `log2(N)`.
    #[inline]
    pub fn log_n(&self) -> u32 {
        self.log_n
    }
}

impl FftTable for FullComplex64FftTable {
    fn new(log_n: u32) -> Result<Self, FftError> {
        // Guard against overflow: 1usize << log_n must be valid.
        if log_n >= usize::BITS {
            return Err(FftError::InvalidLogN {
                log_n,
                max: usize::BITS - 1,
            });
        }

        let n = 1usize << log_n;

        let mut planner = FftPlanner::new();
        let forward = planner.plan_fft_forward(n);
        let inverse = planner.plan_fft_inverse(n);

        // Twist factors: psi^j where psi = exp(pi * i / N).
        // Using cis(PI * j / N) gives one rounding (the division) instead of
        // two (pre-rounding PI/N, then multiplying by j).  The iterative
        // z * psi approach is avoided because its round-off accumulates
        // over O(N) steps.
        let n_f64 = n as f64;
        let twist: Vec<Complex64> = (0..n)
            .map(|j| Complex64::cis(PI * j as f64 / n_f64))
            .collect();

        // Scaled inverse twist: conj(psi^j) / N = cis(-PI * j / N) / N.
        let inv_twist_scaled: Vec<Complex64> = (0..n)
            .map(|j| Complex64::cis(-PI * j as f64 / n_f64) / n_f64)
            .collect();

        Ok(Self {
            log_n,
            poly_length: n,
            fourier_length: n,
            forward,
            inverse,
            twist,
            inv_twist_scaled,
        })
    }

    #[inline]
    fn poly_length(&self) -> usize {
        self.poly_length
    }

    #[inline]
    fn fourier_length(&self) -> usize {
        self.fourier_length
    }

    fn forward_torus_slice<T: TorusFftValue>(&self, input: &[T], output: &mut [Complex64]) {
        debug_assert_eq!(input.len(), self.poly_length);
        debug_assert_eq!(output.len(), self.fourier_length);

        // Step 1: center and twist, writing directly into the output buffer.
        for (j, &val) in input.iter().enumerate() {
            let centered = val.into_f64_centered();
            output[j] = Complex64::new(centered, 0.0) * self.twist[j];
        }

        // Step 2: in-place FFT on the twisted values.
        self.forward.process(output);
    }

    fn inverse_torus_slice<T: TorusFftValue>(&self, input: &[Complex64], output: &mut [T]) {
        debug_assert_eq!(input.len(), self.fourier_length);
        debug_assert_eq!(output.len(), self.poly_length);

        // Step 1: copy input to a temporary buffer for in-place IFFT.
        // Allocation is acceptable for Milestone 1 correctness; future
        // milestones will add caller-provided scratch space.
        let mut buf: Vec<Complex64> = input.to_vec();

        // Step 2: in-place inverse FFT (rustfft does NOT scale by 1/N).
        self.inverse.process(&mut buf);

        // Step 3: untwist, take real part, round, and store as torus integer.
        for (j, val) in buf.iter().enumerate() {
            let v = *val * self.inv_twist_scaled[j];
            output[j] = T::from_f64_wrapping_rounded(v.re);
        }
    }
}
