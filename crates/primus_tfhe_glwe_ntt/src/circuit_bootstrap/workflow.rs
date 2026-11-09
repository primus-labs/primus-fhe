//! Default CBS workflow with one owned input/BR/EP resource set.

use primus_glwe::GlweCiphertext;
use primus_integer::FheUint;
use primus_lattice::ggsw::NttGgsw;
use primus_ntt::MonomialNttTable;
use primus_reduce::RingContext;
use primus_tfhe::CircuitBootstrapLookupTable;

use crate::{
    CircuitBootstrapServerKey, Lwe, TfheContext, TfheEvaluationError,
    bootstrap::BootstrapResources, circuit_bootstrap::CircuitBootstrapEvaluator,
};

/// A configured CBS program and its reusable input/BR/projection resources.
///
/// Created by [`TfheContext::circuit_bootstrap_evaluator_with_lookup_table`].
/// Borrows the Context and complete server key; owns exactly the buffers used by
/// CBS, without output-return scratch, key copies or a second transform table.
/// Calls inherit [`CircuitBootstrapEvaluator`]'s encoding, secret, transform and
/// noise requirements. Independent workers need separate evaluators.
pub struct CbsEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    operation: CircuitBootstrapEvaluator<'a, T, Table>,
    resources: BootstrapResources<'a, T, Table>,
}

impl<'a, T, Table> CbsEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Allocates one zeroed NttGgsw in this program's output layout.
    #[must_use]
    pub fn allocate_output(&self) -> NttGgsw<Vec<T>> {
        self.operation.allocate_output()
    }

    /// Allocates a gadget output and evaluates F(m).
    /// Inherits [`Self::circuit_bootstrap_to`]'s contracts.
    #[must_use]
    pub fn circuit_bootstrap(&mut self, input: Lwe<&[T]>) -> NttGgsw<Vec<T>> {
        self.operation.circuit_bootstrap(input, &mut self.resources)
    }

    /// Writes gadget-scaled F(m), reusing all resources without allocating.
    /// Inherits [`CircuitBootstrapEvaluator::circuit_bootstrap_to`]'s input,
    /// noise, representation and exact-output-length contracts.
    pub fn circuit_bootstrap_to(&mut self, input: Lwe<&[T]>, mut output: NttGgsw<&mut [T]>) {
        self.operation
            .circuit_bootstrap_to(input, &mut output, &mut self.resources);
    }

    /// Selects a coefficient-ring candidate with a bit control.
    /// Inherits [`CircuitBootstrapEvaluator::cmux_to`]'s layout, encoding,
    /// secret, representation and noise contracts; candidates may use an
    /// independent ring message modulus.
    pub fn cmux_to(
        &mut self,
        control: NttGgsw<&[T]>,
        lhs: GlweCiphertext<&[T]>,
        rhs: GlweCiphertext<&[T]>,
        mut output: GlweCiphertext<&mut [T]>,
    ) {
        self.operation
            .cmux_to(&control, &lhs, &rhs, &mut output, &mut self.resources);
    }

    /// Multiplies a coefficient-ring ciphertext by a canonical integer control.
    /// Inherits [`CircuitBootstrapEvaluator::external_product_to`]'s contracts.
    pub fn external_product_to(
        &mut self,
        control: NttGgsw<&[T]>,
        input: GlweCiphertext<&[T]>,
        mut output: GlweCiphertext<&mut [T]>,
    ) {
        self.operation
            .external_product_to(&control, &input, &mut output, &mut self.resources);
    }

    /// Moves out operation state and resources for serial composition with PBS
    /// or another prepared operation. Does not copy or allocate buffers.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CircuitBootstrapEvaluator<'a, T, Table>,
        BootstrapResources<'a, T, Table>,
    ) {
        (self.operation, self.resources)
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    LM: RingContext<T>,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Compiles the gadget identity F(m)=m using configured CBS input/gadgets.
    /// Identity is a bit control only when the full input domain contains only bits.
    pub fn compile_cbs_identity(
        &self,
    ) -> Result<CircuitBootstrapLookupTable<T>, TfheEvaluationError> {
        let parameters = self
            .cbs_parameters()
            .ok_or(TfheEvaluationError::MissingCircuitBootstrapParameters)?;
        Ok(parameters.compile_lookup_table()?)
    }

    /// Compiles F on the complete configured padded or MSB Boolean input domain.
    /// F(m) must be canonical at ring Q; CMux requires a bit throughout the domain.
    /// Inherits [`crate::CbsParameters::compile_lookup_table_fn`]'s contracts.
    pub fn compile_cbs_fn<F: Fn(usize) -> T>(
        &self,
        function: F,
    ) -> Result<CircuitBootstrapLookupTable<T>, TfheEvaluationError> {
        let parameters = self
            .cbs_parameters()
            .ok_or(TfheEvaluationError::MissingCircuitBootstrapParameters)?;
        Ok(parameters.compile_lookup_table_fn(function)?)
    }

    /// Compiles the complete configured input-domain slice.
    /// Inherits [`Self::compile_cbs_fn`]'s contracts and rejects missing/extra entries.
    pub fn compile_cbs_slice(
        &self,
        values: &[T],
    ) -> Result<CircuitBootstrapLookupTable<T>, TfheEvaluationError> {
        let parameters = self
            .cbs_parameters()
            .ok_or(TfheEvaluationError::MissingCircuitBootstrapParameters)?;
        Ok(parameters.compile_lookup_table_slice(values)?)
    }

    /// Prepares configured identity CBS with one owned resource set.
    /// No return scratch is allocated. For a custom function, compile a program
    /// and use [`Self::circuit_bootstrap_evaluator_with_lookup_table`].
    /// Inherits that factory's key, representation and noise requirements.
    pub fn circuit_bootstrap_evaluator<'a>(
        &'a self,
        server_key: &'a CircuitBootstrapServerKey<T>,
    ) -> Result<CbsEvaluator<'a, T, Table>, TfheEvaluationError> {
        self.circuit_bootstrap_evaluator_with_lookup_table(server_key, self.compile_cbs_identity()?)
    }

    /// Moves a public CBS program into the default workflow without cloning it.
    /// Checks its input encoding, gadget basis and ring against the retained CBS
    /// configuration, and binds the complete server key's input/BR resources.
    /// Explicit message/basis combinations remain available through
    /// [`CircuitBootstrapEvaluator`]'s per-call resource interfaces.
    ///
    /// # Correctness
    /// The complete server key must pair the actual external and accumulator
    /// secrets in this Context's transform representation. Parameter checks do
    /// not establish identities or a noise budget; inherit
    /// [`CircuitBootstrapEvaluator::circuit_bootstrap_to`]'s numerical requirements.
    pub fn circuit_bootstrap_evaluator_with_lookup_table<'a>(
        &'a self,
        server_key: &'a CircuitBootstrapServerKey<T>,
        lookup_table: CircuitBootstrapLookupTable<T>,
    ) -> Result<CbsEvaluator<'a, T, Table>, TfheEvaluationError> {
        let parameters = self
            .cbs_parameters()
            .ok_or(TfheEvaluationError::MissingCircuitBootstrapParameters)?;
        if lookup_table.input_plaintext_modulus()
            != parameters.br_control_codec().plaintext_modulus()
            || lookup_table.input_encoding() != parameters.input_encoding()
        {
            return Err(TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable);
        }
        let circuit_key = server_key.circuit_bootstrap_key();
        let circuit = super::key::CircuitBootstrapBinding::try_new(
            self.parameters().evaluation(),
            parameters.gadget(),
            circuit_key,
            &lookup_table,
        )?;
        let resources = server_key.bootstrap_resources(self)?;
        let operation = CircuitBootstrapEvaluator::from_binding(
            self.evaluation_context(),
            circuit,
            lookup_table,
        );
        Ok(CbsEvaluator {
            operation,
            resources,
        })
    }
}
