use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use super::{CrtGlweExpandCoeffKey, CrtGlweTraceWorkspace};
use crate::workspace_pool::WorkspacePool;
use crate::{CrtGlweCiphertext, DcrtGadgetDomain, RnsDomainError};

/// CRT serial coefficient expansion, bound to one key, numerical domain and owned scratch.
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
    domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    workspace: CrtGlweTraceWorkspace<T>,
}

impl<'a, T, M, Table> CrtGlweExpandCoeffEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Creates a new [`CrtGlweExpandCoeffEvaluator`] for a compatible key and domain.
    ///
    /// # Panics
    /// Panics if [`Self::try_new`] rejects the binding.
    #[must_use]
    pub fn new(
        key: &'a CrtGlweExpandCoeffKey<T>,
        domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    ) -> Self {
        Self::try_new(key, domain)
            .unwrap_or_else(|error| panic!("invalid CRT coefficient expansion binding: {error}"))
    }

    /// Checks layout, ordered Q, radix and retained levels before allocating scratch.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] if the key and domain are numerically incompatible.
    pub fn try_new(
        key: &'a CrtGlweExpandCoeffKey<T>,
        domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    ) -> Result<Self, RnsDomainError<T>> {
        key.metadata.validate(domain)?;
        let workspace = CrtGlweTraceWorkspace::from_parameters(domain.parameters());
        Ok(Self {
            key,
            domain,
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
    /// Panics unless there are exactly `N` outputs.
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
            self.domain.parameters().poly_length().get(),
            "full coefficient expansion requires N outputs"
        );
        self.key
            .expand_kernel_to(input.as_view(), output, self.domain, &mut self.workspace);
    }

    /// Expands a power-of-two prefix of coefficients, normalized by its count.
    /// The output count determines the number of expansion levels.
    ///
    /// Outputs are overwritten; internal scratch is reused without caller clearing.
    ///
    /// # Panics
    /// Panics if the output count is zero, not a power of two or greater than `N`.
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
        let n = self.domain.parameters().poly_length().get();
        assert!(
            output.len().is_power_of_two() && output.len() <= n,
            "coefficient expansion output count must be a power of two in 1..=N"
        );
        self.key
            .expand_kernel_to(input.as_view(), output, self.domain, &mut self.workspace);
    }
}

/// CRT parallel coefficient expansion, bound to one key, numerical domain and owned scratch.
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
    domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    workspace: WorkspacePool<CrtGlweTraceWorkspace<T>>,
}

impl<'a, T, M, Table> CrtGlweExpandCoeffParallelEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T> + Sync,
    Table: NttTable<ValueT = T>,
{
    /// Creates a new [`CrtGlweExpandCoeffParallelEvaluator`] for a compatible key and domain.
    ///
    /// `worker_count` must cover the maximum simultaneous Rayon workers used by
    /// an evaluation. For a custom pool, pass its `current_num_threads()`.
    /// Initialize the Rayon pool outside evaluation to exclude thread startup.
    ///
    /// # Panics
    /// Panics if [`Self::try_new`] rejects the binding or `worker_count` is zero.
    #[must_use]
    pub fn new(
        key: &'a CrtGlweExpandCoeffKey<T>,
        domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
        worker_count: usize,
    ) -> Self {
        Self::try_new(key, domain, worker_count)
            .unwrap_or_else(|error| panic!("invalid CRT coefficient expansion binding: {error}"))
    }

    /// Checks layout, ordered Q, radix and retained levels before allocating scratch.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] if the key and domain are numerically incompatible.
    ///
    /// # Panics
    /// Panics if `worker_count` is zero.
    pub fn try_new(
        key: &'a CrtGlweExpandCoeffKey<T>,
        domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
        worker_count: usize,
    ) -> Result<Self, RnsDomainError<T>> {
        key.metadata.validate(domain)?;
        assert!(
            worker_count > 0,
            "coefficient expansion needs at least one worker workspace"
        );
        let workspaces = (0..worker_count)
            .map(|_| CrtGlweTraceWorkspace::from_parameters(domain.parameters()))
            .collect();
        let workspace = WorkspacePool::new(workspaces);
        Ok(Self {
            key,
            domain,
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
    ///
    /// # Panics
    /// Panics unless there are exactly `N` outputs.
    /// An undersized worker pool can panic after partially writing the outputs;
    /// construct with enough workspaces for the Rayon pool used by the call.
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
            self.domain.parameters().poly_length().get(),
            "full coefficient expansion requires N outputs"
        );
        self.key
            .expand_parallel_kernel_to(input.as_view(), output, self.domain, &self.workspace);
    }

    /// Expands a power-of-two prefix of coefficients, normalized by its count.
    /// The output count determines the number of expansion levels.
    ///
    /// Outputs are overwritten; internal scratch is reused without caller clearing.
    /// Worker guards return scratch to the pool on success or unwind. An evaluation
    /// borrows this evaluator exclusively, so calls cannot compete for its pool.
    ///
    /// # Panics
    /// Panics if the output count is zero, not a power of two or greater than `N`.
    /// An undersized worker pool can panic after partially writing the outputs;
    /// construct with enough workspaces for the Rayon pool used by the call.
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
        let n = self.domain.parameters().poly_length().get();
        assert!(
            output.len().is_power_of_two() && output.len() <= n,
            "coefficient expansion output count must be a power of two in 1..=N"
        );
        self.key
            .expand_parallel_kernel_to(input.as_view(), output, self.domain, &self.workspace);
    }
}
