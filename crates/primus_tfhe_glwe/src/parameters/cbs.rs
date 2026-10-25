//! Complete ring-output CBS preparation, independent of transform representation.

use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{
    CbsInputEncoding, CircuitBootstrapLookupTable, LookupTableError, ModulusConfig,
    ModulusConfigError,
};

use crate::{
    CbsConfig, CbsGadgetConfig, CbsGadgetParameters, CircuitBootstrapParameterError,
    FourierTracePrecision, PbsParameters, TfheParameterError,
};

/// Complete CBS parameters: shared BR, gadgets, selector encoding and trace precision.
/// The PBS domain supplies KS for downstream LWE returns; CBS adds no
/// candidate-ring message codec. Both operations share the same PBS state.
/// Program capacity and the noise budget are checked separately.
#[derive(Clone)]
pub struct CbsParameters<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    pbs: PbsParameters<T, M, LM>,
    gadget: CbsGadgetParameters<T, M>,
    br_control_codec: RoundedCodec<T, LM>,
    input_encoding: CbsInputEncoding,
    fourier_trace_precision: FourierTracePrecision,
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> CbsParameters<T, M, LM> {
    /// Prepares one common domain, then adds CBS-specific gadgets and input encoding.
    pub fn try_from_config(config: CbsConfig<T, M, LM>) -> Result<Self, TfheParameterError>
    where
        M: TryFrom<ModulusConfig<M>, Error = ModulusConfigError>,
        LM: TryFrom<ModulusConfig<LM>, Error = ModulusConfigError>,
    {
        Self::try_with_config(
            PbsParameters::try_from_config(config.pbs)?,
            config.gadget,
            config.input_encoding,
            config.fourier_trace_precision,
        )
    }

    /// Adds CBS to an already prepared PBS domain without rebuilding its samplers.
    /// Padded encoding inherits PBS's input modulus; MSB Boolean uses t=2. KS state
    /// is shared with input preparation and downstream LWE returns. Split35 checks
    /// the native-u64/rank-one/bounded-secret requirements here; the Fourier
    /// backend checks feature availability when it binds the parameters.
    pub fn try_with_config(
        pbs: PbsParameters<T, M, LM>,
        gadget: CbsGadgetConfig,
        input_encoding: CbsInputEncoding,
        fourier_trace_precision: FourierTracePrecision,
    ) -> Result<Self, TfheParameterError> {
        if fourier_trace_precision == FourierTracePrecision::Split35 {
            let ring = pbs.blind_rotation_params();
            if T::BITS != 64
                || ring.cipher_modulus().explicit_value().is_some()
                || ring.glwe_size().dimension().get() != 1
                || ring
                    .encryption_parameters()
                    .secret_key_sampler()
                    .maximum_magnitude()
                    > T::ONE
            {
                return Err(TfheParameterError::CircuitBootstrap(
                    CircuitBootstrapParameterError::UnsupportedSplitTrace,
                ));
            }
        }
        let input_modulus = match input_encoding {
            CbsInputEncoding::Padded => pbs.messages().input_modulus,
            CbsInputEncoding::MsbBoolean => T::TWO,
        };
        let gadget = CbsGadgetParameters::try_from_config(&pbs, gadget)
            .map_err(TfheParameterError::CircuitBootstrap)?;
        let br_control_codec =
            RoundedCodec::try_new(input_modulus, pbs.small_lwe().cipher_modulus())
                .map_err(TfheParameterError::InputEncoding)?;
        Ok(Self {
            pbs,
            gadget,
            br_control_codec,
            input_encoding,
            fourier_trace_precision,
        })
    }

    /// Borrows the shared BR domain and selected algorithm.
    #[must_use]
    pub fn pbs_parameters(&self) -> &PbsParameters<T, M, LM> {
        &self.pbs
    }

    /// Borrows trace/scheme-switch parameters and the complete output basis.
    #[must_use]
    pub fn gadget(&self) -> &CbsGadgetParameters<T, M> {
        &self.gadget
    }

    /// Borrows the prepared Rounded encoding at small BR-input modulus q.
    /// KS→BR clients encrypt externally at Q; KS/MS prepares this small-q domain.
    #[must_use]
    pub fn br_control_codec(&self) -> &RoundedCodec<T, LM> {
        &self.br_control_codec
    }

    /// Compiles the gadget identity F(m)=m using the retained input encoding.
    /// The output is a gadget control, independently of ordinary PBS's output codec.
    /// Inherits [`Self::compile_lookup_table_fn`]'s domain and noise contracts.
    pub fn compile_lookup_table(&self) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError> {
        self.gadget
            .compile_lookup_table(&self.br_control_codec, self.input_encoding)
    }

    /// Compiles F on the configured domain: padded `0..ceil(t_in/2)` or MSB bits.
    /// Each result is a canonical ring integer; CMux requires every result to be
    /// a bit. Encoding validity and capacity do not establish a CBS noise margin.
    /// Inherits [`CbsGadgetParameters::compile_lookup_table_fn`]'s contracts.
    pub fn compile_lookup_table_fn<F>(
        &self,
        function: F,
    ) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        self.gadget
            .compile_lookup_table_fn(&self.br_control_codec, self.input_encoding, function)
    }

    /// Compiles the complete slice of F values for the configured input domain.
    /// Inherits [`Self::compile_lookup_table_fn`]'s domain, result and noise contracts;
    /// rejects both missing and extra entries before compilation.
    pub fn compile_lookup_table_slice(
        &self,
        values: &[T],
    ) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError> {
        self.gadget
            .compile_lookup_table_slice(&self.br_control_codec, self.input_encoding, values)
    }

    /// Returns the encoding used by CBS clients and compiled programs.
    #[must_use]
    pub fn input_encoding(&self) -> CbsInputEncoding {
        self.input_encoding
    }

    /// Returns the prepared trace representation; BR and SS remain ordinary.
    /// Fourier backends additionally check their `split-trace` feature at binding.
    #[must_use]
    pub fn fourier_trace_precision(&self) -> FourierTracePrecision {
        self.fourier_trace_precision
    }

    /// Recovers the shared PBS parameters, dropping only CBS-specific state.
    #[must_use]
    pub fn into_pbs_parameters(self) -> PbsParameters<T, M, LM> {
        self.pbs
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> AsRef<PbsParameters<T, M, LM>>
    for CbsParameters<T, M, LM>
{
    fn as_ref(&self) -> &PbsParameters<T, M, LM> {
        &self.pbs
    }
}
