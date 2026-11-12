//! Evaluation keys for patched NTT circuit bootstrapping.

use primus_glwe::{GlweSecretKey, NttGlweSchemeSwitchKey, NttGlweSecretKey, NttGlweTraceKey};
use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;
use primus_reduce::RingContext;

use crate::{KeyGenerationError, KeyGenerator, circuit_bootstrap::CbsGadgetParameters};

/// Trace-projection and scheme-switching keys used after PBSManyLUT.
///
/// BR is owned separately by [`crate::key::BlindRotationKey`]. This object contains
/// only the trace and scheme-switch material, combined with BR in
/// [`crate::CircuitBootstrapServerKey`] alongside the BR/KS [`crate::ServerKey`].
/// Both keys must use the same accumulator secret and the evaluator's
/// NTT representation; see [`crate::circuit_bootstrap::CircuitBootstrapEvaluator::try_new`].
pub struct CircuitBootstrapKey<T: FheUint> {
    parameters: CbsGadgetParameters<T>,
    trace: NttGlweTraceKey<T>,
    scheme_switch: NttGlweSchemeSwitchKey<T>,
}

// A checked pair of CBS material and the chosen output parameters. The key
// binds output layout; a compatible alternate output basis remains valid.
pub(super) struct CircuitBootstrapBinding<'a, T: FheUint> {
    pub(super) key: &'a CircuitBootstrapKey<T>,
    pub(super) parameters: &'a CbsGadgetParameters<T>,
}

impl<'a, T: FheUint> CircuitBootstrapBinding<'a, T> {
    // Check caller-supplied material and program before workspace preparation. Unlike NTRU,
    // GLWE can reuse scheme-switch material with another compatible output basis.
    pub(super) fn try_new(
        tfhe: &primus_tfhe_glwe::PbsEvaluationParameters<T, primus_modulus::BarrettModulus<T>>,
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

impl<T: FheUint> CircuitBootstrapKey<T> {
    /// Returns the CBS parameters selected when this material was generated.
    #[must_use]
    pub fn parameters(&self) -> &CbsGadgetParameters<T> {
        &self.parameters
    }

    pub(crate) fn is_compatible(&self, parameters: &CbsGadgetParameters<T>) -> bool {
        self.parameters.output_size() == parameters.output_size()
            && self.parameters.trace().size() == parameters.trace().size()
            && self.parameters.scheme_switch().size() == parameters.scheme_switch().size()
            && self.trace.basis() == parameters.trace().basis()
            && self.scheme_switch.key_basis() == parameters.scheme_switch().basis()
            && self.scheme_switch.output_size() == parameters.output_size()
            && self.scheme_switch.key_size() == parameters.scheme_switch().size()
    }

    /// Returns the trace key used for reverse-trace coefficient projection.
    #[must_use]
    #[inline]
    pub fn trace_key(&self) -> &NttGlweTraceKey<T> {
        &self.trace
    }

    /// Returns the GLev-to-GGSW scheme-switching key.
    #[must_use]
    #[inline]
    pub fn scheme_switch_key(&self) -> &NttGlweSchemeSwitchKey<T> {
        &self.scheme_switch
    }
}

impl<'a, T, Table, LM> KeyGenerator<'a, T, Table, LM>
where
    T: FheUint,
    LM: RingContext<T>,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Generates trace-projection and scheme-switching keys from only the accumulator secret.
    ///
    /// # Correctness
    ///
    /// For circuit bootstrapping, generate the ordinary server key from the same
    /// accumulator secret as `accumulator_secret` and use this context's NTT
    /// representation for generation and evaluation. The returned key uses
    /// `accumulator_secret`. Parameter/layout checks cannot
    /// establish that another server key uses that secret; see
    /// [`crate::circuit_bootstrap::CircuitBootstrapEvaluator::try_new`].
    /// Imported accumulator coefficients must also satisfy
    /// [`NttGlweSecretKey::from_coeff_secret_key`]'s unsigned-magnitude bound.
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

        let ntt_secret_key =
            NttGlweSecretKey::from_coeff_secret_key(accumulator_secret, self.context.table());

        Ok(self.generate_circuit_bootstrap_key_with_main(
            accumulator_secret,
            &ntt_secret_key,
            parameters,
            rng,
        ))
    }

    /// Uses the accumulator transform already prepared for ordinary PBS key generation.
    pub(crate) fn generate_circuit_bootstrap_key_with_main<R>(
        &mut self,
        accumulator_secret: &GlweSecretKey<T>,
        ntt_secret_key: &NttGlweSecretKey<T>,
        parameters: CbsGadgetParameters<T>,
        rng: &mut R,
    ) -> CircuitBootstrapKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        // Trace reuses the polynomial buffer. Scheme switching also needs level buffers.
        let trace = NttGlweTraceKey::generate(
            accumulator_secret,
            ntt_secret_key,
            parameters.trace(),
            self.context.table(),
            rng,
            &mut self.gadget,
        );

        self.gadget.resize(parameters.scheme_switch().size());
        let scheme_switch = NttGlweSchemeSwitchKey::generate(
            accumulator_secret,
            ntt_secret_key,
            parameters.output_size(),
            parameters.scheme_switch(),
            self.context.table(),
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
