//! Bound projection material under the accumulator secret.

use primus_integer::FheUint;
use primus_ntru::{
    NttNtruProjectionKey, NttNtruSchemeSwitchKey, NttNtruSecretKey, NttNtruTraceKey,
};
use primus_ntt::MonomialNttTable;

use crate::{KeyGenerator, TfheContext, circuit_bootstrap::CbsGadgetParameters};

/// Additional keys for NTRU CBS; ordinary BR material is owned by [`crate::key::BlindRotationKey`].
/// Projection material uses the accumulator secret, not the post-PBS client secret.
/// The NGSW-only method is fixed at generation. Ordinary trace/SS remain available
/// for NLEV-only and dual outputs; they do not change with that method.
/// Publishing the scheme-switch material requires the secret-dependent-message
/// security assumption documented on [`NttNtruProjectionKey`].
pub struct CircuitBootstrapKey<T: FheUint> {
    parameters: CbsGadgetParameters<T>,
    pub(super) projection: NttNtruProjectionKey<T>,
}

impl<T: FheUint> CircuitBootstrapKey<T> {
    /// Checks the key's fixed CBS parameters before preparing LUTs or buffers.
    /// NTRU cannot substitute a different output basis; compatibility does not
    /// establish actual secret or transform identity.
    pub(super) fn check_parameters<
        Table: MonomialNttTable<ValueT = T>,
        LM: primus_reduce::RingContext<T>,
    >(
        &self,
        context: &TfheContext<T, Table, LM>,
    ) -> Result<(), crate::TfheEvaluationError> {
        if !self.parameters.is_compatible(context.parameters()) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapParameters);
        }
        if context
            .cbs_parameters()
            .is_some_and(|parameters| !self.is_compatible(parameters))
        {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapKey);
        }
        Ok(())
    }

    /// Matches the configured projection and gadget decomposition; the evaluator separately
    /// validates its accumulator domain. NTRU scheme switching fixes the output basis.
    pub(crate) fn is_compatible<LM: primus_reduce::RingContext<T>>(
        &self,
        operation: &crate::CbsParameters<T, LM>,
    ) -> bool {
        let parameters = operation.gadget();
        self.projection_method() == operation.projection()
            && self.parameters.output_basis() == parameters.output_basis()
            && self.parameters.trace().basis() == parameters.trace().basis()
            && self.parameters.scheme_switch().basis() == parameters.scheme_switch().basis()
    }

    /// Returns the NGSW-only algorithm bound to this material.
    #[must_use]
    pub fn projection_method(&self) -> crate::NtruProjectionMethod {
        self.projection.method()
    }

    /// Returns the gadget parameters selected when this material was generated.
    #[must_use]
    pub fn parameters(&self) -> &CbsGadgetParameters<T> {
        &self.parameters
    }

    /// Returns the reverse-trace projection key under f_acc.
    #[must_use]
    pub fn trace_key(&self) -> &NttNtruTraceKey<T> {
        self.projection.trace_key()
    }

    /// Returns the NLev-to-NGSW key under f_acc.
    #[must_use]
    pub fn scheme_switch_key(&self) -> &NttNtruSchemeSwitchKey<T> {
        self.projection.scheme_switch_key()
    }
}

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Uses the accumulator transform already prepared for ordinary PBS key generation.
    pub(crate) fn generate_circuit_bootstrap_key_with_main<R>(
        &mut self,
        secret: &primus_ntru::NtruSecretKey<T>,
        transformed: &NttNtruSecretKey<T>,
        operation: &crate::CbsParameters<T, LM>,
        rng: &mut R,
    ) -> CircuitBootstrapKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = operation.gadget();
        let projection = NttNtruProjectionKey::generate(
            operation.projection(),
            secret,
            transformed,
            parameters.output_basis(),
            parameters.trace(),
            parameters.scheme_switch(),
            self.context.table(),
            rng,
            &mut self.gadget,
        );
        CircuitBootstrapKey {
            parameters: parameters.clone(),
            projection,
        }
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Pairs independently bound resources and a gadget key with configured CBS
    /// before compiling a default CBS/one-hot LUT or allocating projection storage.
    pub(crate) fn check_circuit_bootstrap_binding(
        &self,
        resources: &crate::bootstrap::BootstrapResources<'_, T, Table>,
        circuit_key: &CircuitBootstrapKey<T>,
    ) -> Result<&crate::CbsParameters<T, LM>, crate::TfheEvaluationError> {
        let parameters = self
            .cbs_parameters()
            .ok_or(crate::TfheEvaluationError::MissingCircuitBootstrapParameters)?;
        if !resources.context.is_same(self.evaluation_context()) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapParameters);
        }
        if !circuit_key.is_compatible(parameters) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapKey);
        }
        Ok(parameters)
    }
}
