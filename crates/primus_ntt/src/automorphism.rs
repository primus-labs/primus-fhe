//! Evaluation-point permutation in the standard bit-reversed NTT order.

use primus_modulus::PowOf2Modulus;
use primus_reduce::ReduceMul;
use primus_shape::PolyLength;

use crate::reverse::reverse_lsbs;

/// Identity uses a contiguous copy instead of an allocated gather table.
#[derive(Clone)]
enum NttOperation {
    Identity,
    Permutation(Vec<u32>),
}

/// Precomputed `X -> X^degree` permutation in [`crate::NttTable`]'s
/// bit-reversed evaluation order.
///
/// The map depends only on degree and polynomial length. It preserves the
/// input residue range and performs neither arithmetic nor key switching.
/// With `br` reversing the low `log2(N)` bits, it writes
/// `out[br(i)] = in[br(j)]`, where `j = ((degree*(2*i+1) mod 2N) - 1)/2`.
/// Identity allocates no table; other degrees store one `u32` per evaluation.
#[derive(Clone)]
pub struct NttAutomorphismPermutation {
    poly_length: PolyLength,
    operation: NttOperation,
}

impl NttAutomorphismPermutation {
    /// Constructs the permutation for an odd degree in `[1, 2N)`.
    ///
    /// # Panics
    /// Panics unless the degree is odd and less than `2N`.
    #[must_use]
    pub fn new(degree: usize, poly_length: PolyLength) -> Self {
        let n = poly_length.get();
        // The shared FHE bound makes both 2N and the stored u32 indices fit.
        let twice_n = 2 * n;
        assert!(
            degree < twice_n && degree & 1 == 1,
            "automorphism degree must be odd and less than 2N"
        );
        let operation = if degree == 1 {
            NttOperation::Identity
        } else {
            let log_n = poly_length.log_n();
            let modulus = PowOf2Modulus::new(twice_n);
            let mut sources = vec![0; n];
            // Natural index i evaluates at omega^(2i+1). Compose that exponent
            // with degree, then convert both indices to bit-reversed storage.
            for i in 0..n {
                let mapped_exponent = modulus.reduce_mul(degree, 2 * i + 1);
                let j = (mapped_exponent - 1) / 2;
                sources[reverse_lsbs(i, log_n)] = reverse_lsbs(j, log_n) as u32;
            }
            NttOperation::Permutation(sources)
        };
        Self {
            poly_length,
            operation,
        }
    }

    /// Returns the number of evaluations in this permutation.
    #[inline]
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.poly_length
    }

    /// Writes the permuted evaluations without changing their residue range.
    ///
    /// # Correctness
    /// Both slices have exactly [`Self::poly_length`] entries in the
    /// bit-reversed negacyclic order specified by [`crate::NttTable`].
    /// Complete layout validation belongs to the owning caller.
    pub fn apply_to<T: Copy>(&self, input: &[T], output: &mut [T]) {
        debug_assert_eq!(input.len(), self.poly_length().get());
        debug_assert_eq!(output.len(), self.poly_length().get());
        match &self.operation {
            NttOperation::Identity => output.copy_from_slice(input),
            NttOperation::Permutation(sources) => {
                for (output, &source) in output.iter_mut().zip(sources) {
                    *output = input[source as usize];
                }
            }
        }
    }
}
