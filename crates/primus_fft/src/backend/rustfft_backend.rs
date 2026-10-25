use primus_shape::PolyLength;
use std::{f64::consts::PI, sync::Arc};

use aligned_vec::{ABox, AVec, CACHELINE_ALIGN, avec};
use num_complex::Complex64;
use rustfft::{Fft, FftPlanner};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FftTable, TorusFftValue};

/// Reusable workspace for [`RustFftTable`].
/// The full, fixed-length buffers are securely erased on drop.
/// Explicit zeroization preserves lengths and allocations for reuse.
pub struct RustFftWorkspace {
    values: ABox<[Complex64]>,
    fft: ABox<[Complex64]>,
}

impl Zeroize for RustFftWorkspace {
    fn zeroize(&mut self) {
        for buffer in [&mut self.values, &mut self.fft] {
            // Complex64 has no Zeroize implementation. Erase both components
            // while preserving the lengths required by the plan. The boxed
            // slices have no spare capacity outside these initialized elements.
            for value in buffer.iter_mut() {
                value.re.zeroize();
                value.im.zeroize();
            }
        }
    }
}

impl ZeroizeOnDrop for RustFftWorkspace {}

impl Drop for RustFftWorkspace {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Negacyclic FFT wrapper backed by RustFFT.
/// Owned twist and workspace buffers use cache-line alignment. Caller-owned
/// slices only need their element type's normal alignment.
pub struct RustFftTable {
    poly_length: PolyLength,
    forward: Arc<dyn Fft<f64>>,
    inverse: Arc<dyn Fft<f64>>,
    twist: ABox<[Complex64]>,
    inverse_twist_scaled: ABox<[Complex64]>,
}

impl RustFftTable {
    // Pack a_j + i*a_{j+N/2}, then twist for negacyclic evaluation with an N/2
    // complex FFT. Conversion selects signed integers or native torus scaling;
    // the inverse twist contains the separate 1/(N/2) normalization.
    fn forward_with<T: Copy>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        convert: impl Fn(T) -> f64,
        workspace: &mut RustFftWorkspace,
    ) {
        assert_eq!(input.len(), self.poly_length.get());
        assert_eq!(output.len(), self.poly_length.fourier_poly_len());
        let (first, second) = input.split_at(self.poly_length.fourier_poly_len());
        for (((output, &re), &im), &twist) in output
            .iter_mut()
            .zip(first)
            .zip(second)
            .zip(self.twist.iter())
        {
            *output = Complex64::new(convert(re), convert(im)) * twist;
        }
        self.forward
            .process_with_scratch(output, &mut workspace.fft);
    }
}

impl FftTable for RustFftTable {
    type Workspace = RustFftWorkspace;

    fn new(poly_length: PolyLength) -> Self {
        let n = poly_length.get();
        let h = poly_length.fourier_poly_len();
        let mut planner = FftPlanner::new();
        let forward = planner.plan_fft_forward(h);
        let inverse = planner.plan_fft_inverse(h);
        let twist = AVec::from_iter(
            CACHELINE_ALIGN,
            (0..h).map(|j| Complex64::cis(PI * j as f64 / n as f64)),
        )
        .into_boxed_slice();
        let inverse_twist_scaled = AVec::from_iter(
            CACHELINE_ALIGN,
            (0..h).map(|j| Complex64::cis(-PI * j as f64 / n as f64) / h as f64),
        )
        .into_boxed_slice();
        Self {
            poly_length,
            forward,
            inverse,
            twist,
            inverse_twist_scaled,
        }
    }

    fn poly_length(&self) -> PolyLength {
        self.poly_length
    }

    fn automorphism_map(&self, degree: usize) -> Vec<(usize, bool)> {
        crate::automorphism::automorphism_map(self.poly_length, degree, core::convert::identity)
    }

    fn new_workspace(&self) -> Self::Workspace {
        let scratch_len = self
            .forward
            .get_inplace_scratch_len()
            .max(self.inverse.get_inplace_scratch_len());
        RustFftWorkspace {
            values: avec![Complex64::default(); self.poly_length.fourier_poly_len()]
                .into_boxed_slice(),
            fft: avec![Complex64::default(); scratch_len].into_boxed_slice(),
        }
    }

    fn forward_as_torus<T: TorusFftValue>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        workspace: &mut Self::Workspace,
    ) {
        self.forward_with(input, output, TorusFftValue::into_torus_f64, workspace);
    }

    fn forward_as_integer<T: TorusFftValue>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        workspace: &mut Self::Workspace,
    ) {
        self.forward_with(input, output, TorusFftValue::into_signed_f64, workspace);
    }

    fn backward_as_torus<T: TorusFftValue>(
        &self,
        input: &[Complex64],
        output: &mut [T],
        workspace: &mut Self::Workspace,
    ) {
        assert_eq!(input.len(), self.poly_length.fourier_poly_len());
        assert_eq!(output.len(), self.poly_length.get());
        let RustFftWorkspace { values, fft } = workspace;
        values.copy_from_slice(input);
        self.inverse.process_with_scratch(values, fft);
        let (first, second) = output.split_at_mut(self.poly_length.fourier_poly_len());
        for ((&value, &inverse_twist), (first, second)) in values
            .iter()
            .zip(self.inverse_twist_scaled.iter())
            .zip(first.iter_mut().zip(second))
        {
            let value = value * inverse_twist;
            *first = T::from_torus_f64(value.re);
            *second = T::from_torus_f64(value.im);
        }
    }
}
