//! Precomputed coefficient permutations for negacyclic automorphisms.

use primus_integer::{FheUint, WrappingNeg};
use primus_modulus::PowOf2Modulus;
use primus_reduce::{ReduceMul, RingContext};
use primus_shape::PolyLength;

/// One source index and its negacyclic sign, packed into four bytes.
/// PolyLength leaves the high bit free; the table is independent of word width.
#[derive(Clone, Copy)]
struct CoefficientSource(u32);

impl CoefficientSource {
    const NEGATE: u32 = 1 << 31;

    fn new(index: usize, negate: bool) -> Self {
        Self(index as u32 | if negate { Self::NEGATE } else { 0 })
    }

    fn index(self) -> usize {
        (self.0 & !Self::NEGATE) as usize
    }

    fn is_negated(self) -> bool {
        self.0 & Self::NEGATE != 0
    }
}

/// Special degrees need no index table or indirect coefficient loads.
#[derive(Clone)]
enum CoefficientOperation {
    Identity,
    NegateOdd,
    Permutation(Vec<CoefficientSource>),
}

/// Precomputed coefficient permutation for `X -> X^degree` modulo `X^N + 1`.
///
/// The map depends only on the degree and polynomial length, not on a modulus
/// or secret key. Build it once and reuse it. Applying it to a ciphertext does
/// not perform the key switch needed for homomorphic automorphism. Identity and
/// `degree = N + 1` allocate no table; other degrees store one `u32` per coefficient.
#[derive(Clone)]
pub struct CoeffAutomorphismPermutation {
    poly_length: PolyLength,
    operation: CoefficientOperation,
}

impl CoeffAutomorphismPermutation {
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
        let operation = match degree {
            1 => CoefficientOperation::Identity,
            // X^(N+1) = -X, so only odd coefficients change sign.
            d if d == n + 1 => CoefficientOperation::NegateOdd,
            _ => {
                let modulus = PowOf2Modulus::new(twice_n);
                let mut sources = vec![CoefficientSource::new(0, false); n];
                for source in 0..n {
                    let mapped = modulus.reduce_mul(source, degree);
                    sources[mapped & (n - 1)] = CoefficientSource::new(source, mapped >= n);
                }
                CoefficientOperation::Permutation(sources)
            }
        };
        Self {
            poly_length,
            operation,
        }
    }

    /// Returns the number of coefficient positions in this permutation.
    #[inline]
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.poly_length
    }

    /// Writes the automorphism of small signed integer coefficients.
    ///
    /// # Correctness
    /// Both slices contain exactly [`Self::poly_length`] coefficients. Every
    /// required negation must be representable in `T::SignedInteger`; in
    /// particular, a negated coefficient cannot be the signed minimum. This
    /// precondition is not checked. Use [`Self::apply_to`] on encoded residues
    /// when the full signed range must be supported.
    #[inline]
    pub fn apply_signed_to<T: FheUint>(
        &self,
        input: &[T::SignedInteger],
        output: &mut [T::SignedInteger],
    ) {
        debug_assert_eq!(input.len(), self.poly_length().get());
        debug_assert_eq!(output.len(), self.poly_length().get());
        match &self.operation {
            CoefficientOperation::Identity => output.copy_from_slice(input),
            CoefficientOperation::NegateOdd => {
                for (input, output) in input
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .zip(output.as_chunks_mut::<2>().0)
                {
                    output[0] = input[0];
                    output[1] = input[1].wrapping_neg();
                }
            }
            CoefficientOperation::Permutation(sources) => {
                for (output, &source) in output.iter_mut().zip(sources) {
                    let value = input[source.index()];
                    *output = if source.is_negated() {
                        value.wrapping_neg()
                    } else {
                        value
                    };
                }
            }
        }
    }

    /// Writes the automorphism of canonical coefficients modulo `modulus`.
    ///
    /// # Panics
    /// A general permutation panics if `input` is shorter than `N`; identity
    /// panics if the two lengths differ. Debug builds check both lengths are N.
    ///
    /// # Correctness
    /// Both slices contain exactly [`Self::poly_length`] coefficients. Input
    /// values are canonical modulo `modulus`; output is canonical too. Complete
    /// shape validation belongs to the owning caller.
    #[inline]
    pub fn apply_to<T, M>(&self, input: &[T], output: &mut [T], modulus: M)
    where
        T: FheUint,
        M: RingContext<T>,
    {
        debug_assert_eq!(input.len(), self.poly_length().get());
        debug_assert_eq!(output.len(), self.poly_length().get());
        match &self.operation {
            CoefficientOperation::Identity => output.copy_from_slice(input),
            CoefficientOperation::NegateOdd => {
                for (input, output) in input
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .zip(output.as_chunks_mut::<2>().0)
                {
                    output[0] = input[0];
                    output[1] = modulus.reduce_neg(input[1]);
                }
            }
            CoefficientOperation::Permutation(sources) => {
                // Establish the readable extent once, before the gather. The
                // private constructor stores only source indices below N.
                let input = &input[..self.poly_length.get()];
                for (output, &source) in output.iter_mut().zip(sources) {
                    // SAFETY: the checked prefix has N entries and every
                    // decoded source index was generated from 0..N.
                    let value = unsafe { *input.get_unchecked(source.index()) };
                    *output = if source.is_negated() {
                        modulus.reduce_neg(value)
                    } else {
                        value
                    };
                }
            }
        }
    }
}
