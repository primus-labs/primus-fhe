use core::fmt;

use primus_integer::FheUint;
use primus_poly::PolynomialOwned;
use primus_reduce::{PrepareModulusSwitch, ReduceAdd, RingContext};
use primus_shape::PolyLength;

use crate::LookupTableError;

use super::{LookupTableEncoding, compile::compile_front_half};

/// Multiple lookup tables interleaved into one negacyclic accumulator of length `N`.
///
/// For `k = output_count()` functions, an output group contains `k` encoded
/// values followed by zero padding to `s = padded_output_count()` coefficients.
/// Each input's interval repeats its output group; interval lengths may differ.
/// Output `j` occupies coefficients `s*r + j`, so it has `N/s` coefficients in
/// total, including repetitions and the negacyclic tail.
///
/// `k` need not be a power of two; `s = next_power_of_two(k)` always is and divides
/// `N`. Compilation quantizes centers in `2N/s` positions. Blind rotation uses
/// the same quantization followed by multiplication by `s`. Since `s` divides
/// `N`, output indices modulo `s` are preserved even across negacyclic wrap.
/// Outputs are extracted at coefficients `0..k`.
///
/// The plaintext modulus need not be a power of two. Encoded centers must remain
/// distinct; the programmed input domain and noise budget still apply. Increasing
/// `s` reduces rotation resolution and increases per-coefficient rounding error.
#[derive(Clone)]
pub struct InterleavedLookupTable<T: FheUint> {
    polynomial: PolynomialOwned<T>,
    input_domain_len: usize,
    encoding: LookupTableEncoding<T>,
    output_count: usize,
}

impl<T: FheUint> fmt::Debug for InterleavedLookupTable<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InterleavedLookupTable")
            .field("coefficient_count", &self.polynomial.as_ref().len())
            .field("input_domain_len", &self.input_domain_len)
            .field("encoding", &self.encoding)
            .field("output_count", &self.output_count)
            .finish_non_exhaustive()
    }
}

impl<T: FheUint> InterleavedLookupTable<T> {
    /// Compiles encoded multi-output values into an interleaved negacyclic lookup
    /// table.
    ///
    /// Inherits [`super::LookupTable::try_new`]'s encoding and output contracts.
    /// `output_count` must be nonzero. With `s = output_count.next_power_of_two()`,
    /// `input_domain_len` must not exceed the `poly_length / s` coefficients
    /// available per output. The callback runs once per effective
    /// output and input, in input-major order; it is never called for padding slots.
    /// Callback errors and noncanonical outputs stop compilation; no partial
    /// table is returned.
    pub fn try_new<LM, M, F>(
        input_domain_len: usize,
        poly_length: PolyLength,
        output_count: usize,
        input_plaintext_modulus: T,
        input_ciphertext_modulus: LM,
        coefficient_modulus: M,
        encoded_output_at: F,
    ) -> Result<Self, LookupTableError>
    where
        M: RingContext<T>,
        LM: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
        F: Fn(usize, usize) -> Result<T, LookupTableError>,
    {
        let polynomial = compile_front_half(
            input_domain_len,
            poly_length,
            output_count,
            input_plaintext_modulus,
            input_ciphertext_modulus,
            coefficient_modulus,
            encoded_output_at,
        )?;

        Ok(Self {
            polynomial,
            input_domain_len,
            encoding: LookupTableEncoding {
                input_plaintext_modulus,
                input_ciphertext_modulus: input_ciphertext_modulus.explicit_value(),
                coefficient_modulus: coefficient_modulus.explicit_value(),
            },
            output_count,
        })
    }

    /// Returns the length of the programmed input prefix `0..D`.
    #[must_use]
    #[inline]
    pub fn input_domain_len(&self) -> usize {
        self.input_domain_len
    }

    /// Returns the Rounded input message modulus used to place rotation intervals.
    /// Distinct moduli can have the same front-half domain length.
    #[must_use]
    pub fn input_plaintext_modulus(&self) -> T {
        self.encoding.input_plaintext_modulus
    }

    /// Checks the polynomial length and input/accumulator encoding domains.
    ///
    /// Output scale is not compared: raw Boolean and gadget-scaled outputs
    /// need not use the input plaintext codec. This does not validate the key,
    /// noise or actual plaintext of a raw input ciphertext. The caller must
    /// respect the table's [`Self::input_domain_len`], which may be a shorter prefix.
    #[must_use]
    pub fn is_compatible(
        &self,
        poly_length: PolyLength,
        input_plaintext_modulus: T,
        input_ciphertext_modulus: Option<T>,
        coefficient_modulus: Option<T>,
    ) -> bool {
        self.polynomial.as_ref().len() == poly_length.get()
            && self.encoding.is_compatible(
                input_plaintext_modulus,
                input_ciphertext_modulus,
                coefficient_modulus,
            )
    }

    /// Checks the execution domain without fixing a plaintext modulus.
    /// The program already fixes its input encoding and geometry. Raw input
    /// ciphertexts must use that encoding; this check cannot establish it.
    #[must_use]
    pub fn is_compatible_with_ciphertext_domain(
        &self,
        poly_length: PolyLength,
        input_ciphertext_modulus: Option<T>,
        coefficient_modulus: Option<T>,
    ) -> bool {
        self.polynomial.as_ref().len() == poly_length.get()
            && self.encoding.input_ciphertext_modulus == input_ciphertext_modulus
            && self.encoding.coefficient_modulus == coefficient_modulus
    }

    /// Returns the interleaved encoded lookup-table polynomial.
    #[must_use]
    #[inline]
    pub fn polynomial(&self) -> &PolynomialOwned<T> {
        &self.polynomial
    }

    /// Returns the number of independently programmable outputs.
    #[must_use]
    #[inline]
    pub fn output_count(&self) -> usize {
        self.output_count
    }

    /// Returns the number of coefficients in an output group, including padding.
    /// This is `output_count().next_power_of_two()` and the blind-rotation step.
    #[must_use]
    #[inline]
    pub fn padded_output_count(&self) -> usize {
        self.output_count.next_power_of_two()
    }

    /// Decomposes this table into its polynomial and effective output count.
    #[must_use]
    #[inline]
    pub fn into_parts(self) -> (PolynomialOwned<T>, usize) {
        (self.polynomial, self.output_count)
    }
}
