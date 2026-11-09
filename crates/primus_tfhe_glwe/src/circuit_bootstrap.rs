//! Backend-independent parameters for GLWE circuit bootstrapping.

use primus_decompose::{DecompositionConfig, primitive::ApproxSignedBasis};
use primus_encoding::RoundedCodec;
use primus_glwe::{GadgetSize, GgswParameters, GlevParameters};
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{CircuitBootstrapLookupTable, LookupTableError};

use crate::{CbsGadgetConfig, CircuitBootstrapParameterError, PbsParameters};

/// Independent parameters for GLWE circuit bootstrapping.
///
/// The output basis controls GGSW gadget scalars; its layout comes from the TFHE
/// accumulator. Input encoding and ManyLUT capacity belong to program compilation,
/// allowing these keys to serve more than one message program.
/// Trace and scheme switching retain independent bases. The config constructor
/// shares their immutable encryption state with the TFHE accumulator.
/// The scheme-switch key binds the output layout, so another
/// output basis with the same level count can reuse it.
///
/// Construction checks modulus, layout and decomposition. Callers must select
/// these parameters using a CBS noise and security analysis. Matching parameters
/// do not establish secret or transform identity; execution backends specify
/// their representation and numerical requirements.
#[derive(Clone)]
pub struct CbsGadgetParameters<T: FheUint, M: RingContext<T>> {
    trace: GlevParameters<T, M>,
    scheme_switch: GgswParameters<T, M>,
    output_basis: ApproxSignedBasis<T>,
    output_size: GadgetSize,
}

impl<T: FheUint, M: RingContext<T>> CbsGadgetParameters<T, M> {
    /// Derives CBS parameters from TFHE with independent gadget bases.
    ///
    /// Reuses the accumulator's validated layout and sampler state without preparing
    /// new samplers. All key rows use its fresh encryption noise and independent RNG draws.
    /// The derived components already share one domain; only new gadget layouts are checked.
    /// Returns basis or layout errors. Program capacity is checked at compilation;
    /// evaluation binding checks the compiled program against the chosen domain.
    /// The direct [`Self::try_new`] constructor also accepts prepared bases and
    /// independently constructed key parameters.
    ///
    /// Invalid trace and scheme-switch bases/layouts are returned with their key role.
    pub fn try_from_config<LM: RingContext<T>>(
        tfhe: &PbsParameters<T, M, LM>,
        config: CbsGadgetConfig,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        let accumulator = tfhe.blind_rotation_params();
        let modulus = accumulator.cipher_modulus().explicit_value();
        let output_basis = ApproxSignedBasis::try_from((config.output, modulus))?;
        let key_parameters = |role, decomposition: DecompositionConfig| {
            let basis =
                ApproxSignedBasis::try_from((decomposition, modulus)).map_err(|source| {
                    CircuitBootstrapParameterError::GadgetParameters {
                        role,
                        source: source.into(),
                    }
                })?;
            accumulator
                .try_with_new_basis(basis)
                .map_err(|source| CircuitBootstrapParameterError::GadgetParameters { role, source })
        };
        let trace = key_parameters("trace", config.trace)?;
        let scheme_switch = key_parameters("scheme-switch", config.scheme_switch)?;
        Self::try_from_matching_parts(output_basis, trace, scheme_switch)
    }

    /// Derives the output layout from the TFHE accumulator and `output_basis`.
    ///
    /// Returns an error if bases or key layouts use another accumulator domain,
    /// or the output layout overflows. No message codec is required.
    ///
    /// # Correctness
    ///
    /// Independently supplied trace and scheme-switch parameters must describe
    /// key rows generated under the actual accumulator secret and transform
    /// representation. This constructor checks modulus/layout, not equality of
    /// distribution labels, coefficient support, secret identity or noise budgets.
    pub fn try_new<LM: RingContext<T>>(
        tfhe: &PbsParameters<T, M, LM>,
        output_basis: ApproxSignedBasis<T>,
        trace: GlevParameters<T, M>,
        scheme_switch: GgswParameters<T, M>,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        if output_basis.modulus() != tfhe.ring_modulus().explicit_value() {
            return Err(CircuitBootstrapParameterError::OutputBasisModulusMismatch);
        }
        let glwe = tfhe.blind_rotation_params();
        for (role, parameters) in [("trace", &trace), ("scheme-switch", &scheme_switch)] {
            if parameters.glwe_size() != glwe.glwe_size() {
                return Err(CircuitBootstrapParameterError::GlweLayoutMismatch { role });
            }
            if parameters.cipher_modulus().explicit_value()
                != glwe.cipher_modulus().explicit_value()
            {
                return Err(CircuitBootstrapParameterError::CipherModulusMismatch { role });
            }
        }

        Self::try_from_matching_parts(output_basis, trace, scheme_switch)
    }

    /// Derives the output layout after the entry point has established a common
    /// accumulator domain, either by construction or by checking supplied components.
    fn try_from_matching_parts(
        output_basis: ApproxSignedBasis<T>,
        trace: GlevParameters<T, M>,
        scheme_switch: GgswParameters<T, M>,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        let output_size = GadgetSize::try_new(trace.glwe_size(), output_basis.level_count())
            .map_err(|_| CircuitBootstrapParameterError::OutputDecompositionTooLarge)?;
        Ok(Self {
            output_basis,
            output_size,
            trace,
            scheme_switch,
        })
    }

    /// Compiles the gadget-scaled identity for a selected Rounded input encoding.
    /// Inherits [`Self::compile_lookup_table_fn`]'s domain, capacity and noise contracts.
    pub fn compile_lookup_table<LM: RingContext<T>>(
        &self,
        br_control_codec: &RoundedCodec<T, LM>,
        input_encoding: primus_tfhe::CbsInputEncoding,
    ) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError> {
        self.compile_lookup_table_fn(br_control_codec, input_encoding, T::as_from)
    }

    /// Compiles `g_j * F(m) mod Q` for every output gadget level j.
    ///
    /// Input q is independent of accumulator Q. Uses the complete
    /// padded front-half domain or the two MSB bits. Results must be canonical
    /// ring integers (less than explicit Q), rather than codec-scaled messages.
    /// The callback runs once per input during compilation; execution never calls it.
    /// Input geometry, capacity and results follow
    /// [`CircuitBootstrapLookupTable::try_from_fn`]. CMux requires every result
    /// in `{0, 1}`; other integers can be consumed by external products.
    /// Callers must budget BR, trace, scheme-switch and consumption noise.
    pub fn compile_lookup_table_fn<LM: RingContext<T>, F>(
        &self,
        br_control_codec: &RoundedCodec<T, LM>,
        input_encoding: primus_tfhe::CbsInputEncoding,
        function: F,
    ) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        CircuitBootstrapLookupTable::try_from_fn(
            self.output_size.glwe_size().poly_length(),
            br_control_codec,
            input_encoding,
            &self.output_basis,
            self.trace.cipher_modulus(),
            function,
        )
    }

    /// Compiles the complete slice of integer results indexed by input message.
    /// Inherits [`Self::compile_lookup_table_fn`]'s gadget, domain and noise contracts.
    /// Missing or extra entries return [`LookupTableError::DomainLengthMismatch`].
    pub fn compile_lookup_table_slice<LM: RingContext<T>>(
        &self,
        br_control_codec: &RoundedCodec<T, LM>,
        input_encoding: primus_tfhe::CbsInputEncoding,
        values: &[T],
    ) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError> {
        CircuitBootstrapLookupTable::try_from_slice(
            self.output_size.glwe_size().poly_length(),
            br_control_codec,
            input_encoding,
            &self.output_basis,
            self.trace.cipher_modulus(),
            values,
        )
    }

    /// Returns the gadget basis of the output ciphertext.
    #[must_use]
    #[inline]
    pub fn output_basis(&self) -> &ApproxSignedBasis<T> {
        &self.output_basis
    }

    /// Returns the output GGSW layout derived from the TFHE accumulator.
    #[must_use]
    #[inline]
    pub fn output_size(&self) -> GadgetSize {
        self.output_size
    }

    /// Returns the trace key's encryption parameters.
    #[must_use]
    #[inline]
    pub fn trace(&self) -> &GlevParameters<T, M> {
        &self.trace
    }

    /// Returns the gadget parameters of the scheme-switching key.
    #[must_use]
    #[inline]
    pub fn scheme_switch(&self) -> &GgswParameters<T, M> {
        &self.scheme_switch
    }

    /// Returns the LUT padded output count for the output gadget levels.
    #[must_use]
    #[inline]
    pub fn lookup_table_padded_output_count(&self) -> usize {
        self.output_basis.level_count().get().next_power_of_two()
    }

    /// Checks the accumulator layout and ciphertext modulus independently of message encoding.
    /// This does not check noise, secret identity or transform representation.
    #[must_use]
    pub fn is_compatible(&self, glwe: &primus_glwe::GgswParameters<T, M>) -> bool {
        self.output_size.glwe_size() == glwe.glwe_size()
            && self.output_basis.modulus() == glwe.cipher_modulus().explicit_value()
    }
}
