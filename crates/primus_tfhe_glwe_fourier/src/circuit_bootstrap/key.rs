use primus_fft::{FftTable, TorusFftValue};
#[cfg(feature = "split-trace")]
use primus_glwe::SplitFourierGlweTraceKey;
use primus_glwe::{
    FourierGlweSchemeSwitchKey, FourierGlweSecretKey, FourierGlweTraceKey, GlweSecretKey,
};
use primus_reduce::RingContext;

use super::CbsTraceKey;
use crate::FourierTracePrecision;
use crate::{KeyGenerationError, KeyGenerator, circuit_bootstrap::CbsGadgetParameters};

/// Optional trace-projection and GLev-to-Fourier-GGSW scheme-switch keys.
///
/// Both keys use the client's accumulator GLWE secret and the generating
/// context's FFT table. BR is owned separately by [`crate::key::BlindRotationKey`];
/// [`crate::CircuitBootstrapServerKey`] groups it with this CBS material.
/// Layout and basis equality do not establish secret or FFT representation
/// identity; consumers must use the same secret and FFT table instance as
/// generation; see [`crate::circuit_bootstrap::CircuitBootstrapEvaluator::try_new`].
pub struct CircuitBootstrapKey<T: TorusFftValue> {
    parameters: CbsGadgetParameters<T>,
    trace: CbsTraceKey<T>,
    scheme_switch: FourierGlweSchemeSwitchKey<T>,
}

// A checked pair of CBS material and the chosen output parameters. The key
// binds output layout; a compatible alternate output basis remains valid.
pub(super) struct CircuitBootstrapBinding<'a, T: TorusFftValue> {
    pub(super) key: &'a CircuitBootstrapKey<T>,
    pub(super) parameters: &'a CbsGadgetParameters<T>,
}

impl<'a, T: TorusFftValue> CircuitBootstrapBinding<'a, T> {
    // Check caller-supplied material and program before workspace preparation. Unlike NTRU,
    // GLWE can reuse scheme-switch material with another compatible output basis.
    pub(super) fn try_new(
        tfhe: &primus_tfhe_glwe::PbsEvaluationParameters<T, primus_modulus::NativeModulus<T>>,
        parameters: &'a CbsGadgetParameters<T>,
        key: &'a CircuitBootstrapKey<T>,
        lookup_table: &primus_tfhe::CircuitBootstrapLookupTable<T>,
    ) -> Result<Self, crate::TfheEvaluationError> {
        if !parameters.is_compatible(tfhe.blind_rotation_params()) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapParameters);
        }
        // Generation establishes the key's own retained parameter binding.
        // Only an independently supplied parameter object needs comparison.
        if !core::ptr::eq(parameters, key.parameters()) && !key.is_compatible(parameters) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapKey);
        }
        if !lookup_table.is_compatible(
            parameters.output_size().glwe_size().poly_length(),
            tfhe.small_modulus_value(),
            parameters.output_basis(),
        ) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable);
        }
        Ok(Self { key, parameters })
    }
}

impl<T: TorusFftValue> CircuitBootstrapKey<T> {
    /// Returns the CBS parameters selected when this material was generated.
    #[must_use]
    pub fn parameters(&self) -> &CbsGadgetParameters<T> {
        &self.parameters
    }

    pub(crate) fn is_compatible(&self, parameters: &CbsGadgetParameters<T>) -> bool {
        // Generation binds both keys to the same GLWE layout. The scheme-switch
        // key exposes that layout; the trace key only needs a basis comparison.
        self.scheme_switch.output_size() == parameters.output_size()
            && self.scheme_switch.key_size() == parameters.scheme_switch().size()
            && self.scheme_switch.key_basis() == parameters.scheme_switch().basis()
            && self.trace.basis() == parameters.trace().basis()
    }

    /// Returns the key for reverse-trace coefficient projection.
    #[must_use]
    #[inline]
    pub fn trace_key(&self) -> &CbsTraceKey<T> {
        &self.trace
    }

    /// Returns the GLev-to-Fourier-GGSW scheme-switch key.
    #[must_use]
    #[inline]
    pub fn scheme_switch_key(&self) -> &FourierGlweSchemeSwitchKey<T> {
        &self.scheme_switch
    }
}

impl<'a, T, Table, LM> KeyGenerator<'a, T, Table, LM>
where
    T: TorusFftValue,
    LM: RingContext<T>,
    Table: FftTable,
{
    /// Generates CBS keys from only the accumulator secret, reusing Fourier workspace.
    ///
    /// Rejects incompatible circuit parameters or accumulator secrets before sampling.
    ///
    /// # Correctness
    ///
    /// Both keys encrypt under `accumulator_secret`. Generate
    /// the ordinary PBS server key from the same accumulator secret and use this
    /// context's FFT table for evaluation. Compatibility checks cannot identify
    /// the actual secret or distinguish FFT representations with equal lengths.
    pub fn try_generate_circuit_bootstrap_key<R>(
        &mut self,
        accumulator_secret: &GlweSecretKey<T>,
        parameters: CbsGadgetParameters<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let tfhe = self.context.parameters();
        if !parameters.is_compatible(tfhe.blind_rotation_params()) {
            return Err(KeyGenerationError::IncompatibleCircuitBootstrapParameters);
        }
        tfhe.check_accumulator_secret_key(accumulator_secret)?;

        let fourier_secret =
            FourierGlweSecretKey::from_coeff_secret_key(accumulator_secret, &mut self.fft);

        Ok(self.generate_circuit_bootstrap_key_with_main(
            accumulator_secret,
            &fourier_secret,
            parameters,
            rng,
        ))
    }

    /// Uses the accumulator transform already prepared for ordinary PBS key generation.
    pub(crate) fn generate_circuit_bootstrap_key_with_main<R>(
        &mut self,
        accumulator_secret: &GlweSecretKey<T>,
        fourier_secret: &FourierGlweSecretKey,
        parameters: CbsGadgetParameters<T>,
        rng: &mut R,
    ) -> CircuitBootstrapKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let precision = self
            .context
            .cbs_parameters()
            .map_or(FourierTracePrecision::Ordinary, |parameters| {
                parameters.fourier_trace_precision()
            });
        let trace = match precision {
            FourierTracePrecision::Ordinary => {
                self.gadget.resize(parameters.trace().size());
                CbsTraceKey::Ordinary(FourierGlweTraceKey::generate(
                    accumulator_secret,
                    fourier_secret,
                    parameters.trace(),
                    &mut self.fft,
                    rng,
                    &mut self.gadget,
                ))
            }
            #[cfg(feature = "split-trace")]
            FourierTracePrecision::Split35 => {
                CbsTraceKey::Split35(SplitFourierGlweTraceKey::generate(
                    accumulator_secret,
                    parameters.trace(),
                    &mut self.fft,
                    rng,
                ))
            }
            // Context binding rejects this selection before key allocation.
            #[cfg(not(feature = "split-trace"))]
            FourierTracePrecision::Split35 => {
                panic!("split35 trace requires the split-trace Cargo feature")
            }
        };

        self.gadget.resize(parameters.scheme_switch().size());
        let scheme_switch = FourierGlweSchemeSwitchKey::generate(
            accumulator_secret,
            fourier_secret,
            parameters.output_size(),
            parameters.scheme_switch(),
            &mut self.fft,
            rng,
            &mut self.gadget,
        );

        CircuitBootstrapKey {
            parameters,
            trace,
            scheme_switch,
        }
    }
}
