//! Sample extraction from coefficient-domain GLWE ciphertexts.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_reduce::RingContext;

use super::Glwe;
use crate::lwe::Lwe;

impl<S, T> Glwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Extracts the constant coefficient as an LWE sample.
    ///
    /// # Correctness
    ///
    /// A GLWE with `k` mask polynomials of length `N` produces an LWE of
    /// dimension `kN`. `output` must therefore have length `kN + 1`.
    /// `N = poly_length` must be nonzero, and storage must contain exactly
    /// `k + 1` complete polynomials of length `N`.
    /// Input values must be canonical under `modulus`. The LWE secret is
    /// the GLWE mask secret flattened in polynomial/coefficient order. Output
    /// is overwritten, and its phase is the selected coefficient of the GLWE
    /// phase `b - sum(a_i * s_i)`.
    pub fn extract_lwe_to<M, B>(&self, output: &mut Lwe<B>, poly_length: usize, modulus: M)
    where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        self.extract_lwe_at_to(0, output, poly_length, modulus);
    }

    /// Extracts coefficient `index` as an LWE sample.
    ///
    /// # Correctness
    ///
    /// A GLWE with `k` mask polynomials of length `N` produces an LWE of
    /// dimension `kN`. `index` must be in `[0, N)`, and `output` must have
    /// dimension `kN`.
    /// `N = poly_length` must be nonzero, and storage must contain exactly
    /// `k + 1` complete polynomials of length `N`.
    /// Input values must be canonical under `modulus`. The LWE secret is
    /// the GLWE mask secret flattened in polynomial/coefficient order. Output
    /// is overwritten, and its phase is the selected coefficient of the GLWE
    /// phase `b - sum(a_i * s_i)`.
    pub fn extract_lwe_at_to<M, B>(
        &self,
        index: usize,
        output: &mut Lwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        debug_assert!(index < poly_length, "GLWE extraction index is out of range");

        let mask_len = self.as_ref().len() - poly_length;
        debug_assert_eq!(
            output.dimension(),
            mask_len,
            "LWE output dimension does not match the extracted GLWE key"
        );
        self.as_view()
            .extract_lwe_prefix_at_to(index, output.as_mut_view(), poly_length, modulus);
    }

    /// Extracts the constant coefficient as an LWE sample while omitting mask
    /// coefficients paired with a zero-padded secret-key suffix.
    ///
    /// # Correctness
    ///
    /// The active secret-key length is inferred from `output.dimension()` and
    /// must not exceed the full extracted dimension `kN`. For a GLWE key whose
    /// coefficient layout is `[s_lwe..., 0...]`, this directly produces an LWE
    /// sample under `s_lwe` without allocating an intermediate `kN`-dimension
    /// ciphertext.
    /// `N = poly_length` must be nonzero, storage must contain exactly `k + 1`
    /// complete polynomials, and the output dimension must be nonzero.
    /// Input values must be canonical under `modulus`. The LWE secret is
    /// the GLWE mask secret flattened in polynomial/coefficient order. Output
    /// is overwritten, and its phase is the selected coefficient of the GLWE
    /// phase `b - sum(a_i * s_i)`. Every omitted secret coefficient
    /// must be zero; a shorter output alone does not establish that condition.
    pub fn extract_compact_lwe_to<M, B>(&self, output: &mut Lwe<B>, poly_length: usize, modulus: M)
    where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        self.extract_compact_lwe_at_to(0, output, poly_length, modulus);
    }

    /// Extracts coefficient `index` as an LWE sample while omitting mask
    /// coefficients paired with a zero-padded secret-key suffix.
    ///
    /// # Correctness
    ///
    /// `index` must be in `[0, N)`. The active secret-key length is inferred
    /// from `output.dimension()` and must not exceed the full `kN` mask.
    /// `N = poly_length` must be nonzero, storage must contain exactly `k + 1`
    /// complete polynomials, and the output dimension must be nonzero.
    /// Input values must be canonical under `modulus`. The LWE secret is
    /// the GLWE mask secret flattened in polynomial/coefficient order. Output
    /// is overwritten, and its phase is the selected coefficient of the GLWE
    /// phase `b - sum(a_i * s_i)`. Every omitted secret coefficient
    /// must be zero; a shorter output alone does not establish that condition.
    pub fn extract_compact_lwe_at_to<M, B>(
        &self,
        index: usize,
        output: &mut Lwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        debug_assert!(index < poly_length, "GLWE extraction index is out of range");

        let mask_len = self.as_ref().len() - poly_length;
        debug_assert!(
            (1..=mask_len).contains(&output.dimension()),
            "compact LWE output dimension exceeds the GLWE mask"
        );
        self.as_view()
            .extract_lwe_prefix_at_to(index, output.as_mut_view(), poly_length, modulus);
    }
}

impl<T: FheUint> Glwe<&[T]> {
    /// Writes the selected mask prefix and body. The caller supplies valid index
    /// and output dimensions; entry points only debug-assert these conditions.
    /// Each mask is read as `a[index], ..., a[0]` followed by
    /// `-a[N-1], ..., -a[index+1]`, truncated to the active secret prefix.
    #[inline]
    fn extract_lwe_prefix_at_to<M>(
        &self,
        index: usize,
        mut output: Lwe<&mut [T]>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
    {
        let (input_mask, input_body) = self.a_b(poly_length);
        let (output_mask, output_body) = output.a_b_mut();

        // Compact extraction may end inside a mask polynomial: retain the
        // short final output chunk instead of using chunks_exact_mut here.
        for (mask, extracted) in input_mask.zip(output_mask.chunks_mut(poly_length)) {
            let mask = mask.as_ref();
            let positive_len = (index + 1).min(extracted.len());
            let (positive, negacyclic) = extracted.split_at_mut(positive_len);

            for (output, &input) in positive.iter_mut().zip(mask[..=index].iter().rev()) {
                *output = input;
            }
            for (output, &input) in negacyclic.iter_mut().zip(mask.iter().rev()) {
                *output = modulus.reduce_neg(input);
            }
        }
        *output_body = input_body[index];
    }
}
