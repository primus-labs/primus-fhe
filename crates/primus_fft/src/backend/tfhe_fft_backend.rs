use primus_shape::PolyLength;
use std::{f64::consts::PI, time::Duration};

use aligned_vec::{ABox, AVec, CACHELINE_ALIGN, avec};
use dyn_stack::{PodBuffer, PodStack};
use num_complex::Complex64;
use tfhe_fft::unordered::{Method, Plan};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FftTable, TorusFftValue};

/// Negacyclic FFT wrapper backed by the unordered tfhe-fft plan.
/// Owned twist and workspace buffers use cache-line alignment. Caller-owned
/// slices only need their element type's normal alignment.
pub struct TfheFftTable {
    poly_length: PolyLength,
    plan: Plan,
    twist: ABox<[Complex64]>,
    inverse_twist_scaled: ABox<[Complex64]>,
}

/// Reusable workspace for [`TfheFftTable`].
/// Contents, including backend work memory, are securely
/// erased on drop. Explicit zeroization preserves lengths and allocations.
pub struct TfheFftWorkspace {
    values: ABox<[Complex64]>,
    memory: PodBuffer,
}

impl Zeroize for TfheFftWorkspace {
    fn zeroize(&mut self) {
        // The boxed slice has no spare capacity beyond its initialized values.
        for value in self.values.iter_mut() {
            value.re.zeroize();
            value.im.zeroize();
        }
        // PodBuffer exposes the full initialized allocation, including any
        // alignment padding used by the dynamic stack. Keep its length intact.
        self.memory[..].zeroize();
    }
}

impl ZeroizeOnDrop for TfheFftWorkspace {}

impl Drop for TfheFftWorkspace {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl TfheFftTable {
    // Pack a_j + i*a_{j+N/2} with the negacyclic twist. Conversion selects
    // signed integers or native torus scaling; the plan determines spectrum
    // order, and the inverse twist includes 1/(N/2) normalization.
    fn forward_with<T: Copy>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        convert: impl Fn(T) -> f64,
        workspace: &mut TfheFftWorkspace,
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
        self.plan.fwd(output, PodStack::new(&mut workspace.memory));
    }
}

impl FftTable for TfheFftTable {
    type Workspace = TfheFftWorkspace;

    fn new(poly_length: PolyLength) -> Self {
        let n = poly_length.get();
        let h = poly_length.fourier_poly_len();
        let plan = Plan::new(h, Method::Measure(Duration::from_millis(10)));
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
            plan,
            twist,
            inverse_twist_scaled,
        }
    }

    fn poly_length(&self) -> PolyLength {
        self.poly_length
    }

    fn automorphism_map(&self, degree: usize) -> Vec<(usize, bool)> {
        // tfhe-fft 0.10 unordered::Plan stores standard bin i at bit_rev_twice(i),
        // as used by its Fourier-buffer serialization. The ordered base size is
        // plan-specific; equal transform lengths do not imply equal permutations.
        let bits = self.poly_length.fourier_poly_len().trailing_zeros();
        let base_bits = self.plan.algo().1.trailing_zeros();
        let low_mask = (1usize << base_bits) - 1;
        crate::automorphism::automorphism_map(self.poly_length, degree, |index| {
            let reversed = index.reverse_bits() >> (usize::BITS - bits);
            let low = if base_bits == 0 {
                0
            } else {
                reversed.reverse_bits() >> (usize::BITS - base_bits)
            };
            (reversed & !low_mask) | low
        })
    }

    fn new_workspace(&self) -> Self::Workspace {
        TfheFftWorkspace {
            values: avec![Complex64::default(); self.poly_length.fourier_poly_len()]
                .into_boxed_slice(),
            memory: PodBuffer::try_new(self.plan.fft_scratch())
                .expect("failed to allocate FFT workspace"),
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
        workspace.values.copy_from_slice(input);
        let TfheFftWorkspace { values, memory } = workspace;
        self.plan.inv(values, PodStack::new(memory));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FftEngine;
    use tfhe_fft::ordered::FftAlgo;

    #[test]
    fn automorphism_map_tracks_ordered_base_size() {
        let mut table = TfheFftTable::new(PolyLength::new(1024));
        // Force distinct unordered layouts rather than relying on the planner
        // to choose different base sizes on a particular CPU.
        for base_n in [
            table.poly_length.fourier_poly_len(),
            table.poly_length.fourier_poly_len() / 2,
            table.poly_length.fourier_poly_len() / 8,
        ] {
            table.plan = Plan::new(
                table.poly_length.fourier_poly_len(),
                Method::UserProvided {
                    base_algo: FftAlgo::Dif2,
                    base_n,
                },
            );
            let mut fft = FftEngine::new(&table);
            let mut coefficients = vec![0u32; table.poly_length.get()];
            coefficients[1] = 1;
            let mut input = vec![Complex64::default(); table.poly_length.fourier_poly_len()];
            let mut expected = input.clone();
            fft.forward_as_integer(&coefficients, &mut input);
            for degree in [
                3,
                5,
                table.poly_length.get() + 1,
                2 * table.poly_length.get() - 1,
            ] {
                coefficients.fill(0);
                coefficients[degree % table.poly_length.get()] = if degree < table.poly_length.get()
                {
                    1
                } else {
                    u32::MAX // Signed -1 at integer scale.
                };
                fft.forward_as_integer(&coefficients, &mut expected);
                for (&expected, (source, conjugate)) in
                    expected.iter().zip(table.automorphism_map(degree))
                {
                    let actual = if conjugate {
                        input[source].conj()
                    } else {
                        input[source]
                    };
                    assert!(
                        (actual - expected).norm() < 1e-12,
                        "base={base_n}, degree={degree}"
                    );
                }
            }
        }
    }
}
