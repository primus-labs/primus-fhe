use primus_encoding::{PlaintextEmbedding, RoundedCodec, ScaledCodec};
use primus_integer::FheUint;
use primus_poly::{PolynomialIter, PolynomialOwned};
use primus_reduce::{PrepareModulusSwitch, ReduceAdd, RingContext};
use primus_shape::PolyLength;

use super::{
    LookupTableEncoding,
    compile::{compile_front_half_to, validate_front_half},
};
use crate::LookupTableError;

/// Fixed-scale multi-value bootstrapping (MVB) via negacyclic differences.
///
/// For each output, let `p_i` be the unscaled integer front-half LUT, including
/// its signed tail. This stores `V = (delta/2) * (1 + X + ... + X^(N-1))`
/// and `W_i = (1-X)*p_i`, so `V*W_i = delta*p_i` in `Z_q[X]/(X^N+1)`.
/// For odd explicit `q`, division by two is modular. For Native `q = 2^BITS`,
/// delta must be even and division is ordinary integer halving. In both cases
/// it occurs only in the noiseless public `V`. Factors are reduced modulo **q**,
/// never the plaintext modulus. Backends blind-rotate `V` once at step one, then
/// multiply by each factor. Output count does not reduce the input's rotation resolution.
///
/// Inputs use unsigned rounded encoding; all outputs share unsigned fixed-scale
/// encoding. Multiplication amplifies BR error by the integer factor: a bound is
/// `||W_i||_1 * ||e_BR||_infinity`. Compilation checks geometry and output values,
/// not a sufficient noise budget. The type owns no keys or transform tables.
#[derive(Clone, Debug)]
pub struct FactorizedLookupTable<T: FheUint> {
    common_polynomial: PolynomialOwned<T>,
    factors: Vec<T>,
    input_domain_len: usize,
    output_plaintext_modulus: T,
    encoding: LookupTableEncoding<T>,
}

impl<T: FheUint> FactorizedLookupTable<T> {
    /// Compiles `function(input, output_index)` over a nonempty front-half prefix.
    ///
    /// Requires `1 <= input_domain_len <= ceil(t_in/2)`, valid single-output
    /// rotation geometry, a positive `output_count` and either an explicit odd
    /// output ciphertext modulus or Native with an even output scale. Explicit
    /// even moduli remain unsupported. Output count need not be a power of two
    /// or at most N.
    /// Each result must be below `output_codec.plaintext_modulus()`.
    /// On success the callback runs once per pair, with `output_index` outermost
    /// and increasing input indices within each output.
    ///
    /// The input modulus may differ from the coefficient/output modulus in this
    /// shared representation; a backend may impose a stricter compatibility
    /// requirement. Retain `output_codec` to decode extracted LWE phases.
    pub fn try_new<LM, M, F>(
        input_domain_len: usize,
        poly_length: PolyLength,
        output_count: usize,
        input_codec: &RoundedCodec<T, LM>,
        output_codec: &ScaledCodec<T, M>,
        function: F,
    ) -> Result<Self, LookupTableError>
    where
        LM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        M: RingContext<T>,
        F: Fn(usize, usize) -> T,
    {
        if output_count == 0 {
            return Err(LookupTableError::EmptyOutputs);
        }
        let modulus = output_codec.ciphertext_modulus();
        let delta = output_codec.encode_value(T::ONE, PlaintextEmbedding::Unsigned);
        // Solve 2A = delta only for the noiseless common polynomial. Native
        // has no inverse of two; truncating an odd scale would change the LUT.
        let half_scale = match modulus.explicit_value() {
            Some(q) if q & T::ONE == T::ONE => modulus.reduce_mul(delta, q / T::TWO + T::ONE),
            Some(_) => return Err(LookupTableError::UnsupportedFactorizationModulus),
            None if delta & T::ONE == T::ZERO => delta / T::TWO,
            None => return Err(LookupTableError::OddFactorizationScale),
        };
        validate_front_half(
            input_domain_len,
            poly_length,
            1,
            input_codec.plaintext_modulus(),
            input_codec.ciphertext_modulus().explicit_value(),
        )?;
        let poly_length = poly_length.get();
        let factors_len = output_count
            .checked_mul(poly_length)
            .ok_or(LookupTableError::TableLengthOverflow)?;
        let mut factors = vec![T::ZERO; factors_len];
        for (output_index, coefficients) in factors.chunks_exact_mut(poly_length).enumerate() {
            compile_front_half_to(
                input_domain_len,
                1,
                input_codec.plaintext_modulus(),
                input_codec.ciphertext_modulus(),
                modulus,
                |input, _| {
                    let value = function(input, output_index);
                    if value >= output_codec.plaintext_modulus() {
                        return Err(LookupTableError::OutputOutOfRange { input });
                    }
                    Ok(value)
                },
                coefficients,
            )?;
            // Multiplication by (1-X) in the negacyclic ring: the wrapped
            // last coefficient adds at index zero. Reverse traversal keeps
            // each predecessor intact, including when the negative tail is empty.
            let seam = modulus.reduce_add(coefficients[0], coefficients[poly_length - 1]);
            for index in (1..poly_length).rev() {
                coefficients[index] =
                    modulus.reduce_sub(coefficients[index], coefficients[index - 1]);
            }
            coefficients[0] = seam;
        }
        Ok(Self {
            common_polynomial: PolynomialOwned::new(vec![half_scale; poly_length]),
            factors,
            input_domain_len,
            output_plaintext_modulus: output_codec.plaintext_modulus(),
            encoding: LookupTableEncoding {
                input_plaintext_modulus: input_codec.plaintext_modulus(),
                input_ciphertext_modulus: input_codec.ciphertext_modulus().explicit_value(),
                coefficient_modulus: modulus.explicit_value(),
            },
        })
    }

    /// Returns the programmed input prefix length.
    #[must_use]
    pub fn input_domain_len(&self) -> usize {
        self.input_domain_len
    }

    /// Returns the number of factors and extracted outputs, without padding.
    #[must_use]
    pub fn output_count(&self) -> usize {
        self.factors.len() / self.common_polynomial.len()
    }

    /// Returns the plaintext modulus of the shared unsigned Scaled output codec.
    #[must_use]
    pub fn output_plaintext_modulus(&self) -> T {
        self.output_plaintext_modulus
    }

    /// Checks the ring length and input/coefficient moduli, not keys or noise.
    /// The input message must also lie in [`Self::input_domain_len`].
    #[must_use]
    pub fn is_compatible(
        &self,
        poly_length: PolyLength,
        input_plaintext_modulus: T,
        input_ciphertext_modulus: Option<T>,
        coefficient_modulus: Option<T>,
    ) -> bool {
        self.common_polynomial.as_ref().len() == poly_length.get()
            && self.encoding.is_compatible(
                input_plaintext_modulus,
                input_ciphertext_modulus,
                coefficient_modulus,
            )
    }

    /// Checks the execution domain without fixing a plaintext modulus.
    /// Raw ciphertexts must use the input encoding selected by this program.
    #[must_use]
    pub fn is_compatible_with_ciphertext_domain(
        &self,
        poly_length: PolyLength,
        input_ciphertext_modulus: Option<T>,
        coefficient_modulus: Option<T>,
    ) -> bool {
        self.common_polynomial.as_ref().len() == poly_length.get()
            && self.encoding.input_ciphertext_modulus == input_ciphertext_modulus
            && self.encoding.coefficient_modulus == coefficient_modulus
    }

    /// Returns V in coefficient form, ready to initialize blind rotation.
    #[must_use]
    pub fn common_polynomial(&self) -> &PolynomialOwned<T> {
        &self.common_polynomial
    }

    /// Borrows the coefficient-domain W_i in output order from contiguous storage.
    /// Each factor contains N canonical residues modulo q.
    /// Use their small signed integer lifts when computing noise amplification.
    #[must_use]
    pub fn factors(&self) -> PolynomialIter<'_, T> {
        PolynomialIter::new(&self.factors, self.common_polynomial.len())
    }

    /// Consumes this table for backend preparation, returning V and contiguous W_i.
    /// The factor buffer contains `output_count() * N` coefficients in output
    /// order, where N is the length of V. No coefficient data is copied.
    #[must_use]
    pub fn into_polynomials(self) -> (PolynomialOwned<T>, Vec<T>) {
        (self.common_polynomial, self.factors)
    }
}
