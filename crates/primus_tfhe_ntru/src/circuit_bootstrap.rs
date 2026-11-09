//! Shared parameter validation for NTRU circuit bootstrapping.

use primus_decompose::{DecompositionConfig, primitive::ApproxSignedBasis};
use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_modulus::NativeModulus;
use primus_ntru::NlevParameters;
use primus_reduce::RingContext;
use primus_shape::PolyLength;
use primus_tfhe::{CircuitBootstrapLookupTable, LookupTableError};

use crate::{CbsGadgetConfig, CircuitBootstrapParameterError, PbsParameters};

/// Optional CBS parameters, separate from ordinary PBS server-key parameters.
///
/// The TFHE context supplies BR parameters. Trace, scheme-switch and output
/// bases are independent. The scheme-switch key binds the complete output basis.
/// The BR basis must resolve the smallest programmed output gadget scale.
/// Construction checks domains and layouts; compilation checks ManyLUT capacity,
/// and backend program binding checks external q and the complete output basis.
/// Neither establishes a noise budget, failure probability or security. In particular the scheme-switch
/// key encrypts secret-dependent messages and multiplies errors by f and f²;
/// ordinary PBS parameters are not automatically valid CBS parameters.
#[derive(Clone)]
pub struct CbsGadgetParameters<T: FheUint, M: RingContext<T>> {
    trace: NlevParameters<T, M>,
    scheme_switch: NlevParameters<T, M>,
    output_basis: ApproxSignedBasis<T>,
    output_nlev_len: usize,
}

impl<T: FheUint, M: RingContext<T>> CbsGadgetParameters<T, M> {
    /// Derives CBS parameters from TFHE with independent gadget bases.
    ///
    /// Reuses the accumulator's validated ring and sampler state without preparing
    /// new samplers. All key rows use its fresh encryption noise and independent RNG draws.
    /// The derived components already share one domain; only new gadget layouts
    /// and the CBS-specific trace modulus condition are checked.
    /// Returns basis, layout or trace-modulus errors; input encoding and capacity belong to programs.
    /// The direct [`Self::try_new`] constructor also accepts prepared bases and
    /// independently constructed key parameters.
    ///
    /// Invalid trace and scheme-switch bases/layouts are returned with their key role.
    pub fn try_from_config<LM: RingContext<T>>(
        tfhe: &PbsParameters<T, M, LM>,
        config: CbsGadgetConfig,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        let accumulator = tfhe.accumulator_ntru();
        let modulus = accumulator.cipher_modulus_value();
        let output_basis = ApproxSignedBasis::try_from((config.output, modulus))?;
        let key_parameters = |role, decomposition: DecompositionConfig| {
            let basis =
                ApproxSignedBasis::try_from((decomposition, modulus)).map_err(|source| {
                    CircuitBootstrapParameterError::GadgetParameters {
                        role,
                        source: source.into(),
                    }
                })?;
            tfhe.blind_rotation()
                .try_with_new_basis(basis)
                .map_err(|source| CircuitBootstrapParameterError::GadgetParameters { role, source })
        };
        let trace = key_parameters("trace", config.trace)?;
        let scheme_switch = key_parameters("scheme-switch", config.scheme_switch)?;
        Self::try_from_matching_parts(output_basis, trace, scheme_switch)
    }

    /// Checks the accumulator ring, modulus and output layout independently of input encoding.
    /// The output layout is derived from the TFHE accumulator and `output_basis`.
    ///
    /// # Correctness
    ///
    /// Independently supplied trace and scheme-switch parameters must be used
    /// with the same actual NTRU secret and transform representation as BR.
    /// Matching dimensions, moduli or distribution labels do not establish
    /// that pairing or a usable CBS noise/security budget.
    pub fn try_new<LM: RingContext<T>>(
        tfhe: &PbsParameters<T, M, LM>,
        output_basis: ApproxSignedBasis<T>,
        trace: NlevParameters<T, M>,
        scheme_switch: NlevParameters<T, M>,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        if output_basis.modulus() != tfhe.accumulator_ntru().cipher_modulus_value() {
            return Err(CircuitBootstrapParameterError::OutputBasisModulusMismatch);
        }
        for (role, parameters) in [("trace", &trace), ("scheme-switch", &scheme_switch)] {
            if parameters.poly_length() != tfhe.poly_length() {
                return Err(CircuitBootstrapParameterError::PolynomialLengthMismatch { role });
            }
            if parameters.encryption_parameters().cipher_modulus_value()
                != tfhe.accumulator_ntru().cipher_modulus_value()
            {
                return Err(CircuitBootstrapParameterError::CipherModulusMismatch { role });
            }
        }
        Self::try_from_matching_parts(output_basis, trace, scheme_switch)
    }

    /// Checks the CBS trace requirement and derives output storage after the entry
    /// point has established a common accumulator domain. Ordinary TFHE parameters
    /// do not impose this trace condition, so both construction paths retain it.
    fn try_from_matching_parts(
        output_basis: ApproxSignedBasis<T>,
        trace: NlevParameters<T, M>,
        scheme_switch: NlevParameters<T, M>,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        // Explicit-modulus trace uses modular halving. Native trace instead
        // uses coefficient halving with a distinct rounding-error contract.
        if let Some(q) = trace.encryption_parameters().cipher_modulus_value()
            && (q & T::ONE != T::ONE || q >= T::ONE << (T::BITS - 1))
        {
            return Err(CircuitBootstrapParameterError::UnsupportedTraceModulus);
        }
        let poly_length = trace.poly_length();
        // N <= 2^17 and levels <= 32 keep their product within usize.
        let output_nlev_len = poly_length.get() * output_basis.level_count().get();
        Ok(Self {
            trace,
            scheme_switch,
            output_basis,
            output_nlev_len,
        })
    }

    /// Compiles the gadget-scaled identity for a selected Rounded input encoding.
    /// Inherits [`Self::compile_lookup_table_fn`]'s domain, capacity and noise contracts.
    pub fn compile_lookup_table<LM: RingContext<T>>(
        &self,
        input_codec: &RoundedCodec<T, LM>,
    ) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError> {
        self.compile_lookup_table_fn(input_codec, T::as_from)
    }

    /// Compiles `g_j * F(m) mod Q` for every output gadget level j.
    ///
    /// These parameters own Q; backend binding checks input q. Uses the complete
    /// unsigned front-half domain `0..ceil(t_in/2)`. Results must be canonical
    /// ring integers (less than explicit Q), rather than codec-scaled messages.
    /// The callback runs once per input during compilation; execution never calls it.
    /// Input geometry, capacity and results follow
    /// [`CircuitBootstrapLookupTable::try_from_fn`]. CMux requires every result
    /// in `{0, 1}`; other integers can be consumed by external products.
    /// Callers must budget BR, trace, scheme-switch and consumption noise.
    pub fn compile_lookup_table_fn<LM: RingContext<T>, F>(
        &self,
        input_codec: &RoundedCodec<T, LM>,
        function: F,
    ) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        CircuitBootstrapLookupTable::try_from_fn(
            self.poly_length(),
            input_codec,
            primus_tfhe::CbsInputEncoding::Padded,
            &self.output_basis,
            self.trace.encryption_parameters().cipher_modulus(),
            function,
        )
    }

    /// Compiles the complete slice of integer results indexed by input message.
    /// Inherits [`Self::compile_lookup_table_fn`]'s gadget, domain and noise contracts.
    /// Missing or extra entries return [`LookupTableError::DomainLengthMismatch`].
    pub fn compile_lookup_table_slice<LM: RingContext<T>>(
        &self,
        input_codec: &RoundedCodec<T, LM>,
        values: &[T],
    ) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError> {
        CircuitBootstrapLookupTable::try_from_slice(
            self.poly_length(),
            input_codec,
            primus_tfhe::CbsInputEncoding::Padded,
            &self.output_basis,
            self.trace.encryption_parameters().cipher_modulus(),
            values,
        )
    }

    /// Returns the gadget basis of the output ciphertext.
    #[must_use]
    #[inline]
    pub fn output_basis(&self) -> &ApproxSignedBasis<T> {
        &self.output_basis
    }

    /// Returns the accumulator polynomial length `N`.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.trace.poly_length()
    }

    /// Returns the number of coefficient or NTT values in the output NLev/NGSW.
    #[must_use]
    #[inline]
    pub fn output_nlev_len(&self) -> usize {
        self.output_nlev_len
    }

    /// Returns the reverse-trace key's encryption parameters.
    #[must_use]
    pub fn trace(&self) -> &NlevParameters<T, M> {
        &self.trace
    }

    /// Returns the scheme-switch key's encryption parameters.
    #[must_use]
    pub fn scheme_switch(&self) -> &NlevParameters<T, M> {
        &self.scheme_switch
    }

    /// Returns the LUT padded output count for the output gadget levels.
    #[must_use]
    pub fn lookup_table_padded_output_count(&self) -> usize {
        self.output_basis.level_count().get().next_power_of_two()
    }

    /// Checks the accumulator ring and modulus independently of message encoding.
    /// This does not establish noise margins or secret/transform identity.
    #[must_use]
    pub fn is_compatible<LM: RingContext<T>>(&self, tfhe: &PbsParameters<T, M, LM>) -> bool {
        self.poly_length() == tfhe.poly_length()
            && self.output_basis.modulus() == tfhe.accumulator_ntru().cipher_modulus_value()
    }
}

impl<T: FheUint> CbsGadgetParameters<T, NativeModulus<T>> {
    /// Returns the number of complex values in the output Fourier NLev/NGSW.
    #[must_use]
    #[inline]
    pub fn output_fourier_nlev_len(&self) -> usize {
        self.output_nlev_len / 2
    }
}
