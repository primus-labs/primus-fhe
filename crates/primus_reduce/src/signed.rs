//! Bounded signed coefficients represented in a ciphertext modulus.

use primus_integer::FheUint;

use crate::Modulus;

/// Converts bounded signed coefficients to canonical residues without plaintext
/// scaling or general modular reduction.
///
/// Implemented by each modulus type. Native moduli use the signed value's
/// two's-complement bit pattern; explicit moduli map negative values to
/// `q - unsigned_abs(value)`.
pub trait EncodeSigned<T: FheUint>: Modulus<ValueT = T> {
    /// Returns the canonical modulus representation of `value`.
    ///
    /// # Correctness
    ///
    /// For an explicit modulus `q`, `value.unsigned_abs() < q` must hold.
    /// Every signed value, including the signed minimum, is valid for the
    /// native modulus. No general modular reduction is performed.
    #[must_use]
    fn encode_signed(self, value: T::SignedInteger) -> T;

    /// Overwrites `output` with canonical residues for the signed `input`.
    /// No allocation or plaintext scaling is performed. The default implementation
    /// checks lengths once, then statically calls [`Self::encode_signed`].
    ///
    /// # Correctness
    ///
    /// Every coefficient must satisfy [`Self::encode_signed`]'s magnitude bound.
    ///
    /// # Panics
    ///
    /// Panics before writing if the slice lengths differ.
    #[inline]
    fn encode_signed_slice_to(self, input: &[T::SignedInteger], output: &mut [T]) {
        assert_eq!(input.len(), output.len(), "signed encoding length mismatch");
        for (output, &input) in output.iter_mut().zip(input) {
            *output = self.encode_signed(input);
        }
    }
}

/// Modular dot product of canonical residues and bounded signed coefficients.
///
/// Implemented by each modulus backend independently of [`EncodeSigned`] and
/// [`ReduceDotProduct`](crate::ReduceDotProduct), so encoding can be fused with
/// scalar or SIMD multiplication without an intermediate encoded slice.
pub trait ReduceDotProductSigned<T: FheUint> {
    /// Returns the canonical residue of `sum(lhs[i] * rhs[i])`, without allocating.
    /// Empty slices return zero.
    ///
    /// # Correctness
    ///
    /// Each `lhs[i]` must be a canonical residue. For an explicit modulus `q`,
    /// each `rhs[i].unsigned_abs() < q` must hold, as for [`EncodeSigned`]. The
    /// native modulus accepts every signed value, including the signed minimum.
    ///
    /// # Panics
    ///
    /// Panics if the slices have different lengths.
    #[must_use]
    fn reduce_dot_product_signed(self, lhs: &[T], rhs: &[T::SignedInteger]) -> T;
}
