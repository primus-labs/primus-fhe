//! Default CBS workflow with one owned input/BR/EP resource set.

use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_ntru::{FourierNgswCiphertext, NtruCiphertext};
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
    T: TorusFftValue,
    Table: FftTable,
{
    operation: CircuitBootstrapEvaluator<'a, T, Table>,
    resources: BootstrapResources<'a, T, Table>,
}

impl<'a, T, Table> CbsEvaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Allocates one zeroed FourierNgswCiphertext in this program's output layout.
    #[must_use]
    pub fn allocate_output(&self) -> FourierNgswCiphertext<Vec<Complex64>> {
        self.operation.allocate_output()
    }

    /// Allocates a gadget output and evaluates F(m).
    /// Inherits [`Self::circuit_bootstrap_to`]'s contracts.
    #[must_use]
    pub fn circuit_bootstrap(&mut self, input: Lwe<&[T]>) -> FourierNgswCiphertext<Vec<Complex64>> {
        self.operation.circuit_bootstrap(input, &mut self.resources)
    }

    /// Writes gadget-scaled F(m), reusing all resources without allocating.
    /// Inherits [`CircuitBootstrapEvaluator::circuit_bootstrap_to`]'s input,
    /// noise, representation and exact-output-length contracts.
    pub fn circuit_bootstrap_to(
        &mut self,
        input: Lwe<&[T]>,
        mut output: FourierNgswCiphertext<&mut [Complex64]>,
    ) {
        self.operation
            .circuit_bootstrap_to(input, &mut output, &mut self.resources);
    }

    /// Selects a coefficient-ring candidate with a bit control.
    /// Inherits [`CircuitBootstrapEvaluator::cmux_to`]'s layout, encoding,
    /// secret, representation and noise contracts; candidates may use an
    /// independent ring message modulus.
    pub fn cmux_to(
        &mut self,
        control: FourierNgswCiphertext<&[Complex64]>,
        lhs: NtruCiphertext<&[T]>,
        rhs: NtruCiphertext<&[T]>,
        mut output: NtruCiphertext<&mut [T]>,
    ) {
        self.operation
            .cmux_to(&control, &lhs, &rhs, &mut output, &mut self.resources);
    }

    /// Multiplies a coefficient-ring ciphertext by a canonical integer control.
    /// Inherits [`CircuitBootstrapEvaluator::external_product_to`]'s contracts.
    pub fn external_product_to(
        &mut self,
        control: FourierNgswCiphertext<&[Complex64]>,
        input: NtruCiphertext<&[T]>,
        mut output: NtruCiphertext<&mut [T]>,
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
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
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

    /// Compiles F on the complete configured unsigned Rounded input domain.
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
    /// Checks the circuit key's ring and configured precision/projection/gadgets,
    /// the program's input encoding and basis, and the server key's input/BR
    /// binding before allocating online resources.
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
        if lookup_table.input_plaintext_modulus() != parameters.input_codec().plaintext_modulus() {
            return Err(TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable);
        }
        let circuit_key = server_key.circuit_bootstrap_key();
        circuit_key.check_parameters(self)?;
        if lookup_table.input_encoding() != primus_tfhe::CbsInputEncoding::Padded
            || !lookup_table.is_compatible(
                self.parameters().poly_length(),
                self.parameters().external_lwe().cipher_modulus_value(),
                parameters.gadget().output_basis(),
            )
        {
            return Err(TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable);
        }
        let resources = server_key.bootstrap_resources(self)?;
        let operation = CircuitBootstrapEvaluator::from_lookup_table(
            self.evaluation_context(),
            circuit_key,
            lookup_table,
        );
        Ok(CbsEvaluator {
            operation,
            resources,
        })
    }
}
