//! CBS programs bind input geometry, output gadget scales and post-trace offsets.

use core::cell::Cell;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_poly::{Polynomial, PolynomialOwned};
use primus_reduce::RingContext;
use primus_shape::PolyLength;

use super::{InterleavedLookupTable, LookupTableEncoding, front_half_domain_len};
use crate::{LookupTableError, rotation::RotationModulusSwitch};

/// Input geometry of a circuit-bootstrap program, independent of its output gadget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CbsInputEncoding {
    /// Unsigned Rounded messages in `0..ceil(t/2)`, with a padding half-domain.
    #[default]
    Padded,
    /// Bits encoded as `0` and `round(q/2)`, with no padding bit.
    /// Supported by GLWE CBS; ordinary PBS and NTRU CBS keep their own encoding.
    MsbBoolean,
}

impl CbsInputEncoding {
    fn domain_len<T: FheUint, M: RingContext<T>>(
        self,
        codec: &RoundedCodec<T, M>,
    ) -> Result<usize, LookupTableError> {
        match self {
            Self::Padded => front_half_domain_len(codec.plaintext_modulus()),
            Self::MsbBoolean if codec.plaintext_modulus() == T::TWO => Ok(2),
            Self::MsbBoolean => Err(LookupTableError::InvalidInputEncoding),
        }
    }
}

/// A CBS program computing one integer function `F(m)` at every gadget scale.
///
/// Padded input uses the complete unsigned Rounded domain `0..ceil(t/2)` and
/// [`InterleavedLookupTable`]'s geometry. MSB Boolean input uses t=2 and a centered
/// sign polynomial. Its projected lanes require the retained offsets **after
/// full reverse trace**, before scheme switching. Polynomial, encoding, scales
/// and offsets cannot be independently replaced.
///
/// For MSB, with lane stride p, the separately quantized input exponent
/// E=R_p(b)-sum(R_p(a_i)*s_i) must satisfy signed |E-mN| < N/2 modulo 2N.
/// Endpoints are excluded. This includes encryption, input KS/MS and coefficient
/// quantization errors; projecting/scaling errors require a separate output budget.
///
/// Results are canonical ring integers, not codec-scaled messages. CMux requires
/// `F(m)` in `{0, 1}` throughout the domain; other results need an appropriate
/// external-product noise budget. Compilation does not establish that budget.
#[derive(Clone, Debug)]
pub struct CircuitBootstrapLookupTable<T: FheUint> {
    polynomial: PolynomialOwned<T>,
    encoding: LookupTableEncoding<T>,
    input_encoding: CbsInputEncoding,
    input_domain_len: usize,
    output_basis: ApproxSignedBasis<T>,
    post_trace_offsets: Box<[T]>,
}

impl<T: FheUint> CircuitBootstrapLookupTable<T> {
    /// Compiles F into all gadget lanes, calling it once per input in increasing order.
    /// Checks geometry and scales before calling F; each result must be `< Q`
    /// for explicit Q. Native accepts every word value.
    ///
    /// MSB requires t=2, a lane stride at most N/2, and even gadget weights when
    /// Q is even/native. Odd Q uses exact modular halves. Its ideal encoded bit
    /// centers must lie strictly inside their protection intervals. Prefer the
    /// family CBS parameter factory, which supplies the paired encoding and basis.
    pub fn try_from_fn<LM, M, F>(
        poly_length: PolyLength,
        input_codec: &RoundedCodec<T, LM>,
        input_encoding: CbsInputEncoding,
        output_basis: &ApproxSignedBasis<T>,
        coefficient_modulus: M,
        function: F,
    ) -> Result<Self, LookupTableError>
    where
        LM: RingContext<T>,
        M: RingContext<T>,
        F: Fn(usize) -> T,
    {
        let domain_len = input_encoding.domain_len(input_codec)?;
        Self::compile(
            domain_len,
            poly_length,
            input_codec,
            input_encoding,
            output_basis,
            coefficient_modulus,
            function,
        )
    }

    /// Compiles the complete slice of F values for the chosen input geometry.
    /// Inherits [`Self::try_from_fn`]'s contracts; rejects missing and extra entries.
    pub fn try_from_slice<LM: RingContext<T>, M: RingContext<T>>(
        poly_length: PolyLength,
        input_codec: &RoundedCodec<T, LM>,
        input_encoding: CbsInputEncoding,
        output_basis: &ApproxSignedBasis<T>,
        coefficient_modulus: M,
        values: &[T],
    ) -> Result<Self, LookupTableError> {
        let domain_len = input_encoding.domain_len(input_codec)?;
        if values.len() != domain_len {
            return Err(LookupTableError::DomainLengthMismatch {
                expected: domain_len,
                actual: values.len(),
            });
        }
        Self::compile(
            domain_len,
            poly_length,
            input_codec,
            input_encoding,
            output_basis,
            coefficient_modulus,
            |input| values[input],
        )
    }

    /// Both factories establish the complete input count before entering here;
    /// the slice factory additionally checks its storage without revalidating the domain.
    fn compile<LM: RingContext<T>, M: RingContext<T>>(
        domain_len: usize,
        poly_length: PolyLength,
        input_codec: &RoundedCodec<T, LM>,
        input_encoding: CbsInputEncoding,
        output_basis: &ApproxSignedBasis<T>,
        coefficient_modulus: M,
        function: impl Fn(usize) -> T,
    ) -> Result<Self, LookupTableError> {
        let q = coefficient_modulus.explicit_value();
        if output_basis.modulus() != q {
            return Err(LookupTableError::OutputBasisModulusMismatch);
        }
        let scalars: Vec<T> = output_basis.scalar_iter().collect();
        let checked_function = |input| {
            let value = function(input);
            if q.is_some_and(|q| value >= q) {
                Err(LookupTableError::EncodedOutputOutOfRange { input })
            } else {
                Ok(value)
            }
        };
        let (polynomial, post_trace_offsets) = match input_encoding {
            CbsInputEncoding::Padded => {
                // Input-major compilation evaluates F only at the first lane.
                // Even an Fn with interior state therefore agrees across all levels.
                let value = Cell::new(T::ZERO);
                let lut = InterleavedLookupTable::try_new(
                    domain_len,
                    poly_length,
                    scalars.len(),
                    input_codec.plaintext_modulus(),
                    input_codec.ciphertext_modulus(),
                    coefficient_modulus,
                    |input, level| {
                        if level == 0 {
                            value.set(checked_function(input)?);
                        }
                        Ok(coefficient_modulus.reduce_mul(scalars[level], value.get()))
                    },
                )?;
                (lut.into_parts().0, Box::default())
            }
            CbsInputEncoding::MsbBoolean => compile_msb(
                poly_length,
                input_codec,
                &scalars,
                coefficient_modulus,
                checked_function,
            )?,
        };
        Ok(Self {
            polynomial,
            encoding: LookupTableEncoding {
                input_plaintext_modulus: input_codec.plaintext_modulus(),
                input_ciphertext_modulus: input_codec.ciphertext_modulus().explicit_value(),
                coefficient_modulus: q,
            },
            input_encoding,
            input_domain_len: domain_len,
            output_basis: output_basis.clone(),
            post_trace_offsets,
        })
    }

    /// Checks N, input q, ring Q and the exact gadget basis. Binding must also
    /// check the operation's supported/configured [`Self::input_encoding`].
    /// This does not establish ciphertext encoding, secret identity or noise.
    /// In particular it does not compare the default message modulus of a
    /// context: inputs must use [`Self::input_plaintext_modulus`] and this
    /// program's encoding, which may intentionally differ from that default.
    #[must_use]
    pub fn is_compatible(
        &self,
        poly_length: PolyLength,
        input_ciphertext_modulus: Option<T>,
        output_basis: &ApproxSignedBasis<T>,
    ) -> bool {
        self.output_basis == *output_basis
            && self.polynomial.as_ref().len() == poly_length.get()
            && self.encoding.input_ciphertext_modulus == input_ciphertext_modulus
    }

    /// Returns the interleaved gadget-scaled coefficient polynomial.
    #[must_use]
    pub fn polynomial(&self) -> &PolynomialOwned<T> {
        &self.polynomial
    }

    /// Returns the complete programmed input-domain length.
    #[must_use]
    pub fn input_domain_len(&self) -> usize {
        self.input_domain_len
    }

    /// Returns the Rounded message modulus fixing this program's rotation centers.
    #[must_use]
    pub fn input_plaintext_modulus(&self) -> T {
        self.encoding.input_plaintext_modulus
    }

    /// Returns the input geometry; equal message moduli alone do not establish it.
    #[must_use]
    pub fn input_encoding(&self) -> CbsInputEncoding {
        self.input_encoding
    }

    /// Returns the rotation stride, including padding after effective gadget levels.
    #[must_use]
    pub fn padded_output_count(&self) -> usize {
        self.output_basis.level_count().get().next_power_of_two()
    }

    /// Returns the gadget basis used to compile every output lane.
    #[must_use]
    pub fn output_basis(&self) -> &ApproxSignedBasis<T> {
        &self.output_basis
    }

    /// Public constants to add to projected GLEV body coefficient zero, in gadget
    /// level order, **after full reverse trace** and before scheme switching.
    /// Padded programs return an empty slice and need no correction or extra storage.
    /// MSB programs return exactly one offset per effective output level.
    /// Moving these before native trace is invalid because its halving rounds.
    #[must_use]
    pub fn post_trace_offsets(&self) -> &[T] {
        &self.post_trace_offsets
    }
}

/// A centered sign LUT yields -h/h at bit 0/1. With h=g*(F(1)-F(0))/2,
/// adding g*F(0)+h after projection recovers both function values at scale g.
/// Lanes share the strict protection interval |E-mN| < N/2 for stride-aligned E;
/// unused lanes stay zero. The cut N/2 must itself align with that stride.
fn compile_msb<T: FheUint, LM: RingContext<T>, M: RingContext<T>>(
    poly_length: PolyLength,
    input_codec: &RoundedCodec<T, LM>,
    scalars: &[T],
    modulus: M,
    function: impl Fn(usize) -> Result<T, LookupTableError>,
) -> Result<(PolynomialOwned<T>, Box<[T]>), LookupTableError> {
    let n = poly_length.get();
    let stride = scalars.len().next_power_of_two();
    if stride > n / 2 {
        return Err(LookupTableError::InvalidMsbGeometry);
    }
    T::try_from(2 * n).map_err(|_| LookupTableError::RotationDomainTooLarge)?;
    let rotation = RotationModulusSwitch::new(input_codec.ciphertext_modulus(), 2 * n, stride);
    let center = rotation.exponent(input_codec.encode_value(T::ONE, PlaintextEmbedding::Unsigned));
    if center <= n / 2 || center >= n + n / 2 {
        return Err(LookupTableError::InvalidMsbGeometry);
    }
    let odd_modulus = modulus.explicit_value().filter(|q| *q & T::ONE != T::ZERO);
    if odd_modulus.is_none() && scalars.iter().any(|g| *g & T::ONE != T::ZERO) {
        return Err(LookupTableError::OddMsbGadgetScale);
    }
    let f0 = function(0)?;
    let difference = modulus.reduce_sub(function(1)?, f0);
    let mut polynomial = Polynomial::new(vec![T::ZERO; n]);
    let mut offsets = Vec::with_capacity(scalars.len());
    for (level, &scalar) in scalars.iter().enumerate() {
        // For odd Q an odd g needs a modular half, not floor(g/2).
        let half = match odd_modulus {
            Some(q) => modulus.reduce_mul(scalar, (q >> 1u32) + T::ONE),
            None => scalar >> 1u32,
        };
        let h = modulus.reduce_mul(half, difference);
        offsets.push(modulus.reduce_add(modulus.reduce_mul(scalar, f0), h));
        for (i, group) in polynomial.as_mut().chunks_exact_mut(stride).enumerate() {
            group[level] = if i * stride < n / 2 {
                modulus.reduce_neg(h)
            } else {
                h
            };
        }
    }
    Ok((polynomial, offsets.into_boxed_slice()))
}
