use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::{DcrtTable, NttTable};
use primus_reduce::FieldContext;

use super::{CrtGlweExpandCoeffKey, CrtGlweTraceWorkspace, assert_expansion_layout};
use crate::workspace_pool::WorkspacePool;
use crate::{CrtGlevParameters, CrtGlweCiphertext, RnsDomainError};

/// CRT serial coefficient expansion, bound to one key, gadget parameters, table and owned scratch.
///
/// Construct once and reuse. Numerical checks do not establish secret identity
/// or agreement on the table's NTT representation; callers maintain both.
/// Ciphertexts must contain canonical residues in the bound ordered Q basis.
pub struct CrtGlweExpandCoeffEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    key: &'a CrtGlweExpandCoeffKey<T>,
    parameters: &'a CrtGlevParameters<T, M>,
    table: &'a DcrtTable<Table>,
    workspace: CrtGlweTraceWorkspace<T>,
}

impl<'a, T, M, Table> CrtGlweExpandCoeffEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Creates a new [`CrtGlweExpandCoeffEvaluator`] for a compatible key, gadget parameters and table.
    ///
    /// # Panics
    /// Panics if [`Self::try_new`] rejects the binding.
    #[must_use]
    pub fn new(
        key: &'a CrtGlweExpandCoeffKey<T>,
        parameters: &'a CrtGlevParameters<T, M>,
        table: &'a DcrtTable<Table>,
    ) -> Self {
        Self::try_new(key, parameters, table)
            .unwrap_or_else(|error| panic!("invalid CRT coefficient expansion binding: {error}"))
    }

    /// Checks layout, ordered Q, radix and retained levels before allocating scratch.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] if the key, gadget parameters and table are numerically incompatible.
    pub fn try_new(
        key: &'a CrtGlweExpandCoeffKey<T>,
        parameters: &'a CrtGlevParameters<T, M>,
        table: &'a DcrtTable<Table>,
    ) -> Result<Self, RnsDomainError<T>> {
        key.metadata.validate(parameters, table)?;
        let workspace = CrtGlweTraceWorkspace::from_parameters(parameters);
        Ok(Self {
            key,
            parameters,
            table,
            workspace,
        })
    }

    /// Writes output `j` as an encryption of input coefficient `m[j]`.
    /// Expands all `N` coefficients without an extra factor N.
    /// See Algorithm 1 of <https://eprint.iacr.org/2024/266>.
    ///
    /// Outputs are overwritten; internal scratch is reused without caller clearing.
    ///
    /// # Panics
    /// Panics unless there are exactly `N` outputs, or if an input/output
    /// ciphertext has an incorrect complete length. Checks precede all writes.
    ///
    /// # Correctness
    /// Every ciphertext must match the bound RNS GLWE layout and CRT
    /// representation, and the input must use the key's secret.
    pub fn expand_coefficients_to<A: Data<Elem = T>, B: DataMut<Elem = T>>(
        &mut self,
        input: &CrtGlweCiphertext<A>,
        output: &mut [CrtGlweCiphertext<B>],
    ) {
        assert_eq!(
            output.len(),
            self.parameters.poly_length().get(),
            "full coefficient expansion requires N outputs"
        );
        assert_expansion_layout(input.as_ref().len(), output, self.parameters.rns_glwe_len());
        self.key.expand_kernel_to(
            input.as_view(),
            output,
            self.parameters,
            self.table,
            &mut self.workspace,
        );
    }

    /// Extracts residue classes modulo a power-of-two output count `d`.
    /// Output `j` targets `sum_k m[j+k*d] * X^(k*d)`, without an extra factor d.
    /// Higher message coefficients are retained, as required by Relect's block factor.
    ///
    /// Outputs are overwritten; internal scratch is reused without caller clearing.
    ///
    /// # Panics
    /// Panics if the output count is zero, not a power of two or greater than `N`,
    /// or if an input/output ciphertext has an incorrect complete length.
    /// Checks precede all writes.
    ///
    /// # Correctness
    /// Every ciphertext must match the bound RNS GLWE layout and CRT
    /// representation, and the input must use the key's secret.
    /// Plaintext coefficients beyond the requested prefix must be zero to obtain
    /// constant-polynomial outputs; otherwise they remain at higher powers of X.
    pub fn expand_partial_coefficients_to<A: Data<Elem = T>, B: DataMut<Elem = T>>(
        &mut self,
        input: &CrtGlweCiphertext<A>,
        output: &mut [CrtGlweCiphertext<B>],
    ) {
        let n = self.parameters.poly_length().get();
        assert!(
            output.len().is_power_of_two() && output.len() <= n,
            "coefficient expansion output count must be a power of two in 1..=N"
        );
        assert_expansion_layout(input.as_ref().len(), output, self.parameters.rns_glwe_len());
        self.key.expand_kernel_to(
            input.as_view(),
            output,
            self.parameters,
            self.table,
            &mut self.workspace,
        );
    }

    /// Expands a publicly known plaintext support prefix of any length `1..=N`.
    ///
    /// Output `j` targets the constant message `m[j]`, without an extra count
    /// factor. Normalize by `B = count.next_power_of_two()`, then prune the
    /// final level: unpaired leaves are doubled instead of key-switched.
    /// Exactly `count-1` automorphisms are evaluated. Outputs are overwritten;
    /// prepared scratch is reused and the ring length is unchanged. Doubling an
    /// unpaired leaf doubles its existing phase error as well as its message.
    ///
    /// # Correctness
    /// The input plaintext must have degree strictly less than the output count.
    /// This encrypted support condition cannot be checked here; ciphertext and
    /// error tails need not be zero. Relect's block-factor accumulator generally
    /// violates this precondition and must use partial residue-class expansion.
    /// All ciphertexts use the bound complete layout, secret and CRT representation.
    /// Canonical residues and sufficient evaluation-noise margin remain caller contracts.
    ///
    /// # Panics
    /// Panics for a zero count, count greater than N, or an incorrect complete
    /// input/output ciphertext length. These checks precede all writes.
    pub fn expand_supported_coefficients_to<A: Data<Elem = T>, B: DataMut<Elem = T>>(
        &mut self,
        input: &CrtGlweCiphertext<A>,
        output: &mut [CrtGlweCiphertext<B>],
    ) {
        assert!(
            !output.is_empty() && output.len() <= self.parameters.poly_length().get(),
            "supported coefficient expansion count must be in 1..=N",
        );
        assert_expansion_layout(input.as_ref().len(), output, self.parameters.rns_glwe_len());
        self.key.expand_kernel_to(
            input.as_view(),
            output,
            self.parameters,
            self.table,
            &mut self.workspace,
        );
    }
}

/// CRT parallel coefficient expansion, bound to one key, gadget parameters, table and owned scratch.
///
/// Construct once and reuse. Numerical checks do not establish secret identity
/// or agreement on the table's NTT representation; callers maintain both.
/// Ciphertexts must contain canonical residues in the bound ordered Q basis.
pub struct CrtGlweExpandCoeffParallelEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    key: &'a CrtGlweExpandCoeffKey<T>,
    parameters: &'a CrtGlevParameters<T, M>,
    table: &'a DcrtTable<Table>,
    workspace: WorkspacePool<CrtGlweTraceWorkspace<T>>,
}

impl<'a, T, M, Table> CrtGlweExpandCoeffParallelEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T> + Sync,
    Table: NttTable<ValueT = T>,
{
    /// Creates a new [`CrtGlweExpandCoeffParallelEvaluator`] for a compatible key, gadget parameters and table.
    ///
    /// `worker_count` is the maximum number of concurrent scratch-bearing jobs.
    /// Each level is divided into at most that many chunks. The caller's Rayon
    /// pool may have fewer or more threads; no additional thread pool is created.
    /// Initialize the caller's pool outside evaluation to exclude thread startup.
    ///
    /// # Panics
    /// Panics if [`Self::try_new`] rejects the binding or `worker_count` is zero.
    #[must_use]
    pub fn new(
        key: &'a CrtGlweExpandCoeffKey<T>,
        parameters: &'a CrtGlevParameters<T, M>,
        table: &'a DcrtTable<Table>,
        worker_count: usize,
    ) -> Self {
        Self::try_new(key, parameters, table, worker_count)
            .unwrap_or_else(|error| panic!("invalid CRT coefficient expansion binding: {error}"))
    }

    /// Checks layout, ordered Q, radix and retained levels before allocating scratch.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] if the key, gadget parameters and table are numerically incompatible.
    ///
    /// # Panics
    /// Panics if `worker_count` is zero.
    pub fn try_new(
        key: &'a CrtGlweExpandCoeffKey<T>,
        parameters: &'a CrtGlevParameters<T, M>,
        table: &'a DcrtTable<Table>,
        worker_count: usize,
    ) -> Result<Self, RnsDomainError<T>> {
        key.metadata.validate(parameters, table)?;
        assert!(
            worker_count > 0,
            "coefficient expansion needs at least one worker workspace"
        );
        let workspaces = (0..worker_count)
            .map(|_| CrtGlweTraceWorkspace::from_parameters(parameters))
            .collect();
        let workspace = WorkspacePool::new(workspaces);
        Ok(Self {
            key,
            parameters,
            table,
            workspace,
        })
    }

    /// Writes output `j` as an encryption of input coefficient `m[j]`.
    /// Expands all `N` coefficients without an extra factor N.
    /// See Algorithm 1 of <https://eprint.iacr.org/2024/266>.
    ///
    /// Outputs are overwritten; internal scratch is reused without caller clearing.
    /// Worker guards return scratch to the pool on success or unwind. An evaluation
    /// borrows this evaluator exclusively, so calls cannot compete for its pool.
    /// The prepared workspace count bounds concurrent jobs, independently of the
    /// caller's Rayon thread count.
    ///
    /// # Panics
    /// Panics unless there are exactly `N` outputs, or if an input/output
    /// ciphertext has an incorrect complete length. Checks precede all writes.
    ///
    /// # Correctness
    /// Every ciphertext must match the bound RNS GLWE layout and CRT
    /// representation, and the input must use the key's secret.
    pub fn expand_coefficients_to<A: Data<Elem = T>, B: DataMut<Elem = T> + Send>(
        &mut self,
        input: &CrtGlweCiphertext<A>,
        output: &mut [CrtGlweCiphertext<B>],
    ) {
        assert_eq!(
            output.len(),
            self.parameters.poly_length().get(),
            "full coefficient expansion requires N outputs"
        );
        assert_expansion_layout(input.as_ref().len(), output, self.parameters.rns_glwe_len());
        self.key.expand_parallel_kernel_to(
            input.as_view(),
            output,
            self.parameters,
            self.table,
            &self.workspace,
        );
    }

    /// Extracts residue classes modulo a power-of-two output count `d`.
    /// Output `j` targets `sum_k m[j+k*d] * X^(k*d)`, without an extra factor d.
    /// Higher message coefficients are retained, as required by Relect's block factor.
    ///
    /// Outputs are overwritten; internal scratch is reused without caller clearing.
    /// Worker guards return scratch to the pool on success or unwind. An evaluation
    /// borrows this evaluator exclusively, so calls cannot compete for its pool.
    /// The prepared workspace count bounds concurrent jobs, independently of the
    /// caller's Rayon thread count.
    ///
    /// # Panics
    /// Panics if the output count is zero, not a power of two or greater than `N`,
    /// or if an input/output ciphertext has an incorrect complete length.
    /// Checks precede all writes.
    ///
    /// # Correctness
    /// Every ciphertext must match the bound RNS GLWE layout and CRT
    /// representation, and the input must use the key's secret.
    /// Plaintext coefficients beyond the requested prefix must be zero to obtain
    /// constant-polynomial outputs; otherwise they remain at higher powers of X.
    pub fn expand_partial_coefficients_to<A: Data<Elem = T>, B: DataMut<Elem = T> + Send>(
        &mut self,
        input: &CrtGlweCiphertext<A>,
        output: &mut [CrtGlweCiphertext<B>],
    ) {
        let n = self.parameters.poly_length().get();
        assert!(
            output.len().is_power_of_two() && output.len() <= n,
            "coefficient expansion output count must be a power of two in 1..=N"
        );
        assert_expansion_layout(input.as_ref().len(), output, self.parameters.rns_glwe_len());
        self.key.expand_parallel_kernel_to(
            input.as_view(),
            output,
            self.parameters,
            self.table,
            &self.workspace,
        );
    }

    /// Expands a publicly known plaintext support prefix of any length `1..=N`.
    ///
    /// Output `j` targets the constant message `m[j]`, without an extra count
    /// factor. Normalize by `B = count.next_power_of_two()`, then prune the
    /// final level: unpaired leaves are doubled instead of key-switched.
    /// Exactly `count-1` automorphisms are evaluated. Outputs are overwritten;
    /// prepared scratch is reused and the ring length is unchanged. Doubling an
    /// unpaired leaf doubles its existing phase error as well as its message.
    ///
    /// # Correctness
    /// The input plaintext must have degree strictly less than the output count.
    /// This encrypted support condition cannot be checked here; ciphertext and
    /// error tails need not be zero. Relect's block-factor accumulator generally
    /// violates this precondition and must use partial residue-class expansion.
    /// All ciphertexts use the bound complete layout, secret and CRT representation.
    /// Canonical residues and sufficient evaluation-noise margin remain caller contracts.
    ///
    /// # Panics
    /// Panics for a zero count, count greater than N, or an incorrect complete
    /// input/output ciphertext length. These checks precede all writes.
    pub fn expand_supported_coefficients_to<A: Data<Elem = T>, B: DataMut<Elem = T> + Send>(
        &mut self,
        input: &CrtGlweCiphertext<A>,
        output: &mut [CrtGlweCiphertext<B>],
    ) {
        assert!(
            !output.is_empty() && output.len() <= self.parameters.poly_length().get(),
            "supported coefficient expansion count must be in 1..=N",
        );
        assert_expansion_layout(input.as_ref().len(), output, self.parameters.rns_glwe_len());
        self.key.expand_parallel_kernel_to(
            input.as_view(),
            output,
            self.parameters,
            self.table,
            &self.workspace,
        );
    }
}
