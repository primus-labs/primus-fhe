use core::fmt;

use primus_integer::FheUint;
use primus_poly::PolynomialOwned;
use primus_reduce::{PrepareModulusSwitch, ReduceAdd, RingContext};
use primus_shape::PolyLength;

use crate::LookupTableError;

use super::{
    LookupTableEncoding,
    compile::{compile_front_half, compile_odd_full_domain},
};

/// A lookup table compiled into an encoded negacyclic polynomial.
///
/// An execution backend embeds this polynomial into its accumulator
/// representation when blind rotation begins. Compilation binds the input's
/// unsigned rounded encoding and both ciphertext moduli. Output residues may
/// use a different scale, as required by Boolean and circuit bootstrapping.
/// The table does not bind a secret key, ciphertext dimension or backend.
#[derive(Clone)]
pub struct LookupTable<T: FheUint> {
    polynomial: PolynomialOwned<T>,
    input_domain_len: usize,
    encoding: LookupTableEncoding<T>,
}

impl<T: FheUint> fmt::Debug for LookupTable<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LookupTable")
            .field("coefficient_count", &self.polynomial.as_ref().len())
            .field("input_domain_len", &self.input_domain_len)
            .field("encoding", &self.encoding)
            .finish_non_exhaustive()
    }
}

impl<T: FheUint> LookupTable<T> {
    /// Compiles already encoded outputs into a negacyclic lookup-table polynomial.
    ///
    /// The input uses unsigned rounded encoding with `input_plaintext_modulus`
    /// and `input_ciphertext_modulus`. Raw outputs must be canonical under
    /// `coefficient_modulus`, the modulus of the LUT polynomial and accumulator,
    /// but may use any output scale. `input_domain_len` is a non-empty prefix of
    /// the independently programmable front half. Only `0..input_domain_len`
    /// has callback-defined values; the unprogrammed tail is not an additional
    /// function domain. Invalid encoding, layout, rotation centers or outputs
    /// return an error.
    pub fn try_new<LM, M, F>(
        input_domain_len: usize,
        poly_length: PolyLength,
        input_plaintext_modulus: T,
        input_ciphertext_modulus: LM,
        coefficient_modulus: M,
        encoded_output_at: F,
    ) -> Result<Self, LookupTableError>
    where
        M: RingContext<T>,
        LM: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
        F: Fn(usize) -> Result<T, LookupTableError>,
    {
        let polynomial = compile_front_half(
            input_domain_len,
            poly_length,
            1,
            input_plaintext_modulus,
            input_ciphertext_modulus,
            coefficient_modulus,
            |input, _| encoded_output_at(input),
        )?;
        Ok(Self {
            polynomial,
            input_domain_len,
            encoding: LookupTableEncoding {
                input_plaintext_modulus,
                input_ciphertext_modulus: input_ciphertext_modulus.explicit_value(),
                coefficient_modulus: coefficient_modulus.explicit_value(),
            },
        })
    }

    /// Compiles already encoded outputs over the entire odd plaintext domain `0..t`.
    ///
    /// Inputs use unsigned rounded encoding. Requires odd `t >= 3`, `t <= N`,
    /// valid input encoding and distinct folded rotation centers. Each center is
    /// computed by encoding then modulus switching, as in [`Self::try_new`].
    /// Centers in `N..2N` fold back by `N` with a negated output, compensating
    /// for the sign introduced by negacyclic rotation. Output residues must be
    /// canonical under `coefficient_modulus`; their scale is independent of `t`.
    ///
    /// On success the callback is evaluated once per input, in folded-center
    /// order: `0, (t+1)/2, 1, (t+3)/2, ...`. Intervals select the nearest center,
    /// with midpoint ties going to the higher center, including the signed seam
    /// at `N`. With built-in moduli and a nonallocating callback, only the final
    /// polynomial is allocated.
    ///
    /// The typical center spacing is `N/t`, half that of front-half compilation.
    /// Distinct centers ensure representability, not a sufficient PBS noise
    /// budget; input error and coefficient-wise modulus switching must remain
    /// within the selected interval. Even-modulus full-domain functions are not
    /// supported by this constructor.
    pub fn try_new_odd_full_domain<LM, M, F>(
        poly_length: PolyLength,
        input_plaintext_modulus: T,
        input_ciphertext_modulus: LM,
        coefficient_modulus: M,
        encoded_output_at: F,
    ) -> Result<Self, LookupTableError>
    where
        M: RingContext<T>,
        LM: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
        F: Fn(usize) -> Result<T, LookupTableError>,
    {
        let (polynomial, input_domain_len) = compile_odd_full_domain(
            poly_length,
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
        })
    }

    /// Returns the length of the programmed input prefix `0..D`.
    #[must_use]
    #[inline]
    pub fn input_domain_len(&self) -> usize {
        self.input_domain_len
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

    /// Returns the encoded lookup-table polynomial.
    #[must_use]
    #[inline]
    pub fn polynomial(&self) -> &PolynomialOwned<T> {
        &self.polynomial
    }

    /// Decomposes this table into its encoded polynomial.
    #[must_use]
    #[inline]
    pub fn into_polynomial(self) -> PolynomialOwned<T> {
        self.polynomial
    }
}
