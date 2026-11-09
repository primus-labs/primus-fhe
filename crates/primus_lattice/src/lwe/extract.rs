//! Inverse sample extraction into a coefficient-domain GLWE layout.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_reduce::RingContext;

use super::Lwe;
use crate::glwe::Glwe;

impl<S, T> Lwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Inserts this LWE sample into a GLWE ciphertext so that compact sample
    /// extraction recovers the original LWE sample exactly.
    ///
    /// # Correctness
    ///
    /// For a nonzero LWE dimension `n` and `N = poly_length`, the output must contain
    /// `ceil(n / N) + 1` polynomials of length `N`. Unused coefficients in the
    /// final mask polynomial and all non-constant body coefficients are set to
    /// zero. `poly_length` must be nonzero.
    ///
    /// The LWE input must use canonical residues under `modulus`. The target
    /// GLWE key is the LWE secret padded with zeros to `ceil(n / N) * N`
    /// coefficients and grouped into length-`N` polynomials in storage order.
    /// Only extraction at index zero is inverted: zeroing nonconstant body
    /// coefficients does not imply zero nonconstant coefficients of the
    /// decrypted phase. Output is fully overwritten.
    ///
    /// # Panics
    ///
    /// Panics if `poly_length` is zero, the input is empty, or the output is
    /// shorter than one body polynomial. Other shape conditions are not
    /// systematically checked.
    pub fn inverse_extract_glwe_to<M, B>(
        &self,
        output: &mut Glwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        let output_mask_len = output.as_ref().len() - poly_length;

        debug_assert_eq!(
            output_mask_len,
            self.dimension().next_multiple_of(poly_length)
        );

        self.as_view()
            .inverse_extract_glwe_to_kernel(output.as_mut_view(), poly_length, modulus);
    }
}

impl<T: FheUint> Lwe<&[T]> {
    /// Inverts constant-term extraction block by block into the caller's GLWE
    /// layout. Clear first so unused mask slots and nonconstant body slots stay
    /// zero; a short final input block is placed at the ends of a full mask.
    fn inverse_extract_glwe_to_kernel<M>(
        &self,
        mut output: Glwe<&mut [T]>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
    {
        output.as_mut().fill(T::ZERO);

        let (input_mask, input_body) = self.a_b();
        let (output_mask, mut output_body) = output.a_b_mut(poly_length);

        // The input mask can end mid-polynomial; the output mask cannot.
        for (input, mut mask) in input_mask.chunks(poly_length).zip(output_mask) {
            let mask = mask.as_mut();
            mask[0] = input[0];
            for (output, &input) in mask[1..].iter_mut().rev().zip(&input[1..]) {
                *output = modulus.reduce_neg(input);
            }
        }

        output_body.as_mut()[0] = input_body;
    }
}
