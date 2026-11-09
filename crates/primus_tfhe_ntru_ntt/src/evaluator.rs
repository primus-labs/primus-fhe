use primus_integer::FheUint;
use primus_ntru::{LweReturnBatchWorkspace, LweReturnEvaluator};
use primus_ntt::MonomialNttTable;
use primus_tfhe::{
    InterleavedLookupTable, LookupTable, LweCiphertext, ProgrammableBootstrap,
    ProgrammableBootstrapInterleaved, TfheEvaluationError,
};

use crate::{Lwe, ServerKey, TfheContext, bootstrap::BootstrapResources, key::BlindRotationKey};

/// Allocation-free online evaluator for exact NTT NTRU programmable bootstrapping.
/// Owns common BR/EP and scalar/batch return resources. CBS/one-hot can borrow
/// the former; factorized MVB takes ownership of this evaluator.
/// Scalar PBS uses independent return scratch. A new interleaved/MVB request
/// discards pending batch samples from an unwind.
pub struct Evaluator<'a, T, Table, LM = primus_modulus::BarrettModulus<T>>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    pub(crate) resources: BootstrapResources<'a, T, Table>,
    pub(crate) lwe_return: LweReturnEvaluator<'a, T, LM>,
    scalar_return: primus_ntru::NtruLweKeySwitchingWorkspace<T>,
    pub(crate) batch_return: LweReturnBatchWorkspace<T>,
}

impl<'a, T, Table, LM> Evaluator<'a, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Creates reusable evaluation state after checking the server key once.
    ///
    /// # Correctness
    /// The server key must use the NTT representation of `context.table()`.
    /// Layout and basis checks do not establish transform or secret identity.
    pub fn try_new(
        context: &'a TfheContext<T, Table, LM>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let parameters = context.parameters();
        let return_key = server_key.key_switching_key();
        parameters.check_lwe_return_key(return_key)?;
        let resources = BootstrapResources::try_new(context, server_key.blind_rotation_key())?;
        Ok(Self::from_resources(
            resources,
            return_key,
            parameters.external_lwe().cipher_modulus(),
        ))
    }

    /// Binds independent BR and Q→q, f→s return material before allocating scratch.
    /// The keys must share actual secrets and this context's transform representation;
    /// layout, distribution, basis and modulus checks do not establish identity.
    pub fn try_from_parts(
        context: &'a TfheContext<T, Table, LM>,
        key_switching: &crate::LweKeySwitchingParameters<T, LM>,
        blind_rotation_key: &'a BlindRotationKey<T>,
        return_key: &'a primus_ntru::NtruLweKeySwitchingKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        context
            .parameters()
            .check_lwe_return_key_with_parameters(key_switching, return_key)?;
        let resources = BootstrapResources::try_new(context, blind_rotation_key)?;
        Ok(Self::from_resources(
            resources,
            return_key,
            context.parameters().external_lwe().cipher_modulus(),
        ))
    }

    /// Adds client-return buffers after the owning boundary checked return compatibility.
    #[must_use]
    fn from_resources(
        resources: BootstrapResources<'a, T, Table>,
        return_key: &'a primus_ntru::NtruLweKeySwitchingKey<T>,
        output_modulus: LM,
    ) -> Self {
        let lwe_return = LweReturnEvaluator::new(return_key, output_modulus);
        let scalar_return = lwe_return.new_scalar_workspace();
        let batch_return = lwe_return.new_batch_workspace();
        Self {
            resources,
            lwe_return,
            scalar_return,
            batch_return,
        }
    }

    /// Borrows the shared BR/EP resources to prepare an operation's own buffers.
    #[must_use]
    pub fn bootstrap_resources(&self) -> &BootstrapResources<'a, T, Table> {
        &self.resources
    }

    /// Lends common resources for CBS/one-hot or table products. Return buffers
    /// remain owned here, so ordinary PBS can resume after the short borrow ends.
    ///
    /// # Correctness
    /// Preserve the context and BR key binding: the retained return material and
    /// scratch were prepared for it. This borrow is not an evaluator-rebinding API.
    #[must_use]
    pub fn bootstrap_resources_mut(&mut self) -> &mut BootstrapResources<'a, T, Table> {
        &mut self.resources
    }

    /// Adds the configured return buffers to standalone CBS/BR resources.
    /// `context` supplies the return reducer; resources must belong to that context.
    /// Rejects foreign resources or incompatible return material before allocation.
    /// The return key must share the resources' accumulator secret and intended
    /// external secret; compatibility checks do not establish secret identity.
    pub fn try_from_resources(
        context: &'a TfheContext<T, Table, LM>,
        resources: BootstrapResources<'a, T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        if !resources.context.is_same(context.evaluation_context()) {
            return Err(TfheEvaluationError::IncompatibleLweReturnKey);
        }
        let return_key = server_key.key_switching_key();
        context.parameters().check_lwe_return_key(return_key)?;
        Ok(Self::from_resources(
            resources,
            return_key,
            context.parameters().external_lwe().cipher_modulus(),
        ))
    }

    /// Returns one coefficient of an accumulator ciphertext under the external LWE secret.
    /// Reuses the bound Q→q→signed extraction→f→s KS return and scalar scratch.
    /// Input is borrowed directly; no accumulator copy or allocation is needed.
    ///
    /// # Correctness
    /// Inherits [`primus_ntru::LweReturnEvaluator::return_at_to`]'s canonical
    /// coefficient, secret and joint error-budget requirements. No re-encoding
    /// occurs; use [`TfheContext::ring_return_decryptor`] with the original
    /// Scaled ring message modulus.
    ///
    /// # Panics
    /// Rejects an invalid index or input/output length before writes.
    pub fn return_ring_at_to(
        &mut self,
        input: primus_ntru::NtruCiphertext<&[T]>,
        index: usize,
        output: Lwe<&mut [T]>,
    ) {
        self.lwe_return
            .return_at_to(input, index, output, &mut self.scalar_return);
    }

    /// Applies a compiled lookup table and allocates the returned ciphertext.
    ///
    /// Inherits [`ProgrammableBootstrap::apply_lookup_table_to`]'s input encoding,
    /// key, noise and output-scale requirements.
    ///
    /// # Panics
    ///
    /// Panics on an incompatible input dimension or LUT encoding/moduli/length.
    #[must_use]
    pub fn apply_lookup_table(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &LookupTable<T>,
    ) -> LweCiphertext<T> {
        let dimension = self.resources.context.external_lwe_dimension();
        let mut output = LweCiphertext::zero(dimension.get());
        self.apply_lookup_table_to(input, lookup_table, output.as_mut_view());
        output
    }

    /// Applies a compiled lookup table into an existing LWE allocation.
    ///
    /// Inherits [`ProgrammableBootstrap::apply_lookup_table_to`]'s input encoding,
    /// key, noise and output-scale requirements.
    ///
    /// # Panics
    ///
    /// Panics before output writes on incompatible LUT encoding/moduli/length
    /// or ciphertext dimensions.
    pub fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &LookupTable<T>,
        output: Lwe<&mut [T]>,
    ) {
        let parameters = self.resources.context;
        assert!(
            lookup_table.is_compatible_with_ciphertext_domain(
                parameters.poly_length(),
                parameters.input_modulus_value(),
                parameters.accumulator_ntru().cipher_modulus_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let lwe_dimension = parameters.external_lwe_dimension();
        assert_eq!(
            input.dimension(),
            lwe_dimension.get(),
            "PBS input dimension mismatch"
        );
        assert_eq!(
            output.dimension(),
            lwe_dimension.get(),
            "PBS output dimension mismatch"
        );

        self.resources
            .blind_rotate(input, lookup_table.polynomial(), 1);
        self.return_accumulator_at_to(0, output);
    }

    /// Applies all interleaved tables into reusable output allocations.
    ///
    /// Shares one blind rotation and Q→q conversion, then batches LWE key switches.
    ///
    /// Inherits [`ProgrammableBootstrapInterleaved::apply_interleaved_lookup_table_to`]'s input encoding,
    /// key, noise and output-scale requirements.
    ///
    /// # Panics
    ///
    /// Panics before output writes on incompatible LUT encoding/moduli/length
    /// or ciphertext dimensions. A wrong output count is also rejected.
    pub fn apply_interleaved_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &InterleavedLookupTable<T>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        let parameters = self.resources.context;
        assert!(
            lookup_table.is_compatible_with_ciphertext_domain(
                parameters.poly_length(),
                parameters.input_modulus_value(),
                parameters.accumulator_ntru().cipher_modulus_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let lwe_dimension = parameters.external_lwe_dimension();
        assert_eq!(
            input.dimension(),
            lwe_dimension.get(),
            "PBS input dimension mismatch"
        );
        assert_eq!(
            outputs.len(),
            lookup_table.output_count(),
            "PBSManyLUT output slice length mismatch"
        );
        assert!(
            outputs
                .iter()
                .all(|output| output.dimension() == lwe_dimension.get()),
            "PBSManyLUT output ciphertext dimension mismatch"
        );

        self.batch_return.discard_batch();
        self.resources.blind_rotate(
            input,
            lookup_table.polynomial(),
            lookup_table.padded_output_count(),
        );
        self.return_accumulator_prefix_to(outputs);
    }

    /// CBS consumes `current` directly; ordinary PBS returns its phase coefficient.
    fn return_accumulator_at_to(&mut self, index: usize, output: Lwe<&mut [T]>) {
        self.lwe_return.return_at_to(
            self.resources.blind_rotation.current.as_view(),
            index,
            output,
            &mut self.scalar_return,
        );
    }

    /// Share Q→q across the interleaved prefix. The batch kernel also handles
    /// singleton outputs directly, without a tile copy.
    fn return_accumulator_prefix_to(&mut self, outputs: &mut [LweCiphertext<T>]) {
        self.lwe_return.return_prefix_to(
            self.resources.blind_rotation.current.as_view(),
            outputs,
            &mut self.batch_return,
        );
    }
}

impl<T, Table, LM> ProgrammableBootstrap<T> for Evaluator<'_, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    #[inline]
    fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &LookupTable<T>,
        output: Lwe<&mut [T]>,
    ) {
        Self::apply_lookup_table_to(self, input, lookup_table, output);
    }
}

impl<T, Table, LM> ProgrammableBootstrapInterleaved<T> for Evaluator<'_, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    #[inline]
    fn apply_interleaved_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &InterleavedLookupTable<T>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        Self::apply_interleaved_lookup_table_to(self, input, lookup_table, outputs);
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Creates an evaluator with reusable NTT and coefficient workspaces.
    pub fn evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<Evaluator<'a, T, Table, LM>, TfheEvaluationError> {
        Evaluator::try_new(self, server_key)
    }
}
