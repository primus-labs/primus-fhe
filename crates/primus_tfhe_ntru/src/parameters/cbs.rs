//! Complete ring-output CBS preparation, independent of transform representation.

use crate::{CbsConfig, CbsGadgetConfig, CbsGadgetParameters, PbsParameters, TfheParameterError};
use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_reduce::RingContext;

/// Complete CBS/one-hot parameters: shared BR, prepared gadgets and selector encoding.
/// The PBS domain supplies KS for downstream LWE returns; CBS adds no
/// candidate-ring message codec. Both operations share the same PBS state.
/// Retains the NGSW-only projection method; the transform backend checks support.
/// Program capacity and one-hot geometry are checked when preparing the LUT.
/// The caller must establish a noise budget for the selected projection method.
#[derive(Clone)]
pub struct CbsParameters<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    pbs: PbsParameters<T, M, LM>,
    gadget: CbsGadgetParameters<T, M>,
    input_codec: RoundedCodec<T, LM>,
    projection: crate::NtruProjectionMethod,
    fourier_precision: crate::FourierCbsPrecision,
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> CbsParameters<T, M, LM> {
    /// Prepares one common domain, then adds CBS-specific gadgets and input encoding.
    pub fn try_from_config(config: CbsConfig<T, M, LM>) -> Result<Self, TfheParameterError>
    where
        M: TryFrom<primus_tfhe::ModulusConfig<M>, Error = primus_tfhe::ModulusConfigError>,
        LM: TryFrom<primus_tfhe::ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
    {
        let mut result = Self::try_with_config(
            PbsParameters::try_from_config(config.pbs)?,
            config.gadget,
            config.projection,
        )?;
        result.fourier_precision = config.fourier_precision;
        for (precision, basis, branches) in [
            (
                config.fourier_precision.blind_rotation,
                result.pbs.blind_rotation().basis(),
                3u128,
            ),
            (
                config.fourier_precision.trace,
                result.gadget.trace().basis(),
                1,
            ),
            (
                config.fourier_precision.scheme_switch,
                result.gadget.scheme_switch().basis(),
                1,
            ),
        ] {
            if let crate::FourierPrecision::Split { low_bits } = precision {
                if T::BITS != 64
                    || result
                        .pbs
                        .accumulator_ntru()
                        .cipher_modulus_value()
                        .is_some()
                    || !(1..64).contains(&low_bits)
                {
                    return Err(TfheParameterError::UnsupportedFourierPrecision);
                }
                // Leave one bit below signed-i128 saturation in the inverse
                // conversion. This bounds arithmetic range, not FFT accuracy.
                let factor = result.pbs.poly_length().get() as u128
                    * basis.level_count().get() as u128
                    * branches;
                let width = low_bits.max(64 - low_bits);
                let bound = factor
                    .checked_mul(1u128 << (basis.log_basis().get() - 1))
                    .and_then(|v| v.checked_mul((1u128 << width) - 1));
                if !bound.is_some_and(|v| v < (1u128 << 126)) {
                    return Err(TfheParameterError::UnsupportedFourierPrecision);
                }
            }
        }
        Ok(result)
    }

    /// Adds CBS to an already prepared PBS domain without rebuilding its samplers.
    /// Selector encoding uses the domain's input message modulus. KS state is
    /// shared with downstream LWE returns. Projection is explicit and retained
    /// unchanged; the transform backend checks whether it supports this method.
    pub fn try_with_config(
        pbs: PbsParameters<T, M, LM>,
        gadget: CbsGadgetConfig,
        projection: crate::NtruProjectionMethod,
    ) -> Result<Self, TfheParameterError> {
        let input_modulus = pbs.messages().input_modulus;
        let gadget = CbsGadgetParameters::try_from_config(&pbs, gadget)
            .map_err(TfheParameterError::CircuitBootstrap)?;
        let input_codec = RoundedCodec::try_new(input_modulus, pbs.external_lwe().cipher_modulus())
            .map_err(TfheParameterError::InputEncoding)?;
        Ok(Self {
            pbs,
            gadget,
            input_codec,
            projection,
            fourier_precision: crate::FourierCbsPrecision::ORDINARY,
        })
    }

    /// Returns the representation required of all three evaluation materials.
    #[must_use]
    pub fn fourier_precision(&self) -> crate::FourierCbsPrecision {
        self.fourier_precision
    }

    /// Returns the NGSW-only projection strategy. Backend construction checks support;
    /// shared preparation does not infer transform capabilities from the modulus.
    #[must_use]
    pub fn projection(&self) -> crate::NtruProjectionMethod {
        self.projection
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

    /// Borrows the prepared Rounded selector-input encoding.
    #[must_use]
    pub fn input_codec(&self) -> &RoundedCodec<T, LM> {
        &self.input_codec
    }

    /// Compiles the gadget identity F(m)=m using the retained input encoding.
    /// The output is a gadget control, independently of ordinary PBS's output codec.
    /// Inherits [`Self::compile_lookup_table_fn`]'s domain and noise contracts.
    pub fn compile_lookup_table(
        &self,
    ) -> Result<primus_tfhe::CircuitBootstrapLookupTable<T>, primus_tfhe::LookupTableError> {
        self.gadget.compile_lookup_table(&self.input_codec)
    }

    /// Compiles F on the complete unsigned Rounded domain `0..ceil(t_in/2)`.
    /// Each result is a canonical ring integer; CMux requires every result to be
    /// a bit. Encoding validity and capacity do not establish a CBS noise margin.
    /// Inherits [`CbsGadgetParameters::compile_lookup_table_fn`]'s contracts.
    pub fn compile_lookup_table_fn<F>(
        &self,
        function: F,
    ) -> Result<primus_tfhe::CircuitBootstrapLookupTable<T>, primus_tfhe::LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        self.gadget
            .compile_lookup_table_fn(&self.input_codec, function)
    }

    /// Compiles the complete F(0), ..., F(ceil(t_in/2)-1) slice.
    /// Inherits [`Self::compile_lookup_table_fn`]'s domain, result and noise contracts;
    /// rejects both missing and extra entries before compilation.
    pub fn compile_lookup_table_slice(
        &self,
        values: &[T],
    ) -> Result<primus_tfhe::CircuitBootstrapLookupTable<T>, primus_tfhe::LookupTableError> {
        self.gadget
            .compile_lookup_table_slice(&self.input_codec, values)
    }

    /// Recovers the shared PBS parameters, dropping CBS gadgets and Fourier precision.
    /// A new PBS-only context requires ordinary BR material; this conversion
    /// does not convert an existing split BSK into ordinary material.
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
