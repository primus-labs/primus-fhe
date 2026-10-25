//! Bound coefficient-domain returns and valid-prefix state for streamed inputs.

use primus_integer::FheUint;
use primus_lattice::lwe::Lwe;
use primus_lwe::LweCiphertext;
use primus_reduce::RingContext;
use primus_shape::PolyLength;

use super::{
    NtruLweKeySwitchingBatchWorkspace, NtruLweKeySwitchingKey, NtruLweKeySwitchingWorkspace,
};
use crate::NtruCiphertext;

/// Coefficient-domain NTRU→LWE returns, independent of blind rotation and NTT/FFT scratch.
///
/// Borrows the Q→q, f→s key and binds q without allocating. Callers prepare
/// only the scalar and/or batch workspace their operations need, independently
/// of standalone one-hot CBS or an ordinary PBS evaluator. Single returns,
/// shared-input selections and independent streams keep their conversion schedules.
/// All online methods allocate nothing.
/// Source secret identity, coefficient representation and noise are caller contracts.
/// Batch methods borrow a slice of preallocated LWEs and validate every output
/// before writing. A short final tile contains fewer complete LWEs, not a partial
/// ciphertext; outputs beyond the supplied slice are not touched.
pub struct LweReturnEvaluator<'a, T: FheUint, LM: RingContext<T>> {
    key: &'a NtruLweKeySwitchingKey<T>,
    modulus: LM,
}

impl<'a, T: FheUint, LM: RingContext<T>> LweReturnEvaluator<'a, T, LM> {
    /// Binds a return key to q without allocating scratch.
    ///
    /// # Panics
    /// Panics if q differs from the key's target modulus.
    #[must_use]
    pub fn new(key: &'a NtruLweKeySwitchingKey<T>, modulus: LM) -> Self {
        assert_eq!(
            modulus.explicit_value(),
            key.basis().modulus(),
            "target LWE modulus mismatch"
        );
        Self { key, modulus }
    }

    /// Allocates the single N+1-element intermediate LWE used by scalar returns.
    ///
    /// # Panics
    /// Panics if the key's polynomial length is outside [`PolyLength`]'s range.
    #[must_use]
    pub fn new_scalar_workspace(&self) -> NtruLweKeySwitchingWorkspace<T> {
        NtruLweKeySwitchingWorkspace::new(PolyLength::new(self.key.poly_length()))
    }

    /// Allocates bounded return tiles and shared-input conversion scratch.
    /// No scalar workspace is included; the batch path handles singleton tiles too.
    ///
    /// # Panics
    /// Panics if the key's polynomial length is outside [`PolyLength`]'s range
    /// or tile storage length overflows.
    #[must_use]
    pub fn new_batch_workspace(&self) -> LweReturnBatchWorkspace<T> {
        LweReturnBatchWorkspace {
            batch: NtruLweKeySwitchingBatchWorkspace::new(
                PolyLength::new(self.key.poly_length()),
                self.key.output_dimension(),
            ),
            prepared: None,
        }
    }

    /// Returns phase coefficient `index` at q under the independent LWE secret.
    ///
    /// With `c' = round(q*c/Q) mod q`, the intermediate mask is
    /// `a[i] = -c'[index-i]` for `i <= index`, otherwise `c'[N+index-i]`;
    /// `b = 0`. Its phase `b-<a,f>` equals `(f*c')[index]`.
    /// Rounding is nearest with ties upward, including endpoint wrap to zero.
    /// Q→q precedes extraction signs; reversing the order can change results at
    /// ties. Output and scratch are overwritten without reset or allocation.
    ///
    /// # Correctness
    /// Input is a coefficient-domain ciphertext under f with canonical residues
    /// at the key's generation-time Q. The bound modulus supplies q. The phase
    /// approximates `(q/Q)*(f*c)[index]` modulo q: coefficient rounding is weighted
    /// by f, followed by secret-weighted decomposition error and key-entry noise.
    /// These errors and any previous NTRU/FFT error need a joint decoding budget.
    /// This operation does not decode or re-encode plaintexts.
    ///
    /// # Panics
    /// Rejects invalid input/output/workspace lengths or index before writes.
    pub fn return_at_to(
        &self,
        input: NtruCiphertext<&[T]>,
        index: usize,
        output: Lwe<&mut [T]>,
        workspace: &mut NtruLweKeySwitchingWorkspace<T>,
    ) {
        let n = self.key.poly_length();
        assert_eq!(input.as_ref().len(), n, "NTRU input length mismatch");
        assert!(index < n, "NTRU extraction index is out of range");
        assert_eq!(
            output.as_ref().len(),
            self.key.output_dimension().ciphertext_len(),
            "target LWE ciphertext length mismatch"
        );
        assert_eq!(
            workspace.poly_length(),
            n,
            "NTRU to LWE workspace length mismatch"
        );
        self.key.key_switch_coefficient(
            input,
            index,
            output,
            self.modulus,
            workspace.extracted.as_mut_view(),
        );
    }

    /// Returns phase coefficients `0..outputs.len()` from one shared NTRU input.
    /// Uses [`Self::return_many_at_to`] with ascending prefix indices.
    ///
    /// # Correctness
    /// Inherits [`Self::return_many_at_to`]'s key, canonical
    /// coefficient and noise requirements. Shared source noise remains correlated.
    ///
    /// # Panics
    /// Rejects an active stream or invalid input/output lengths or prefix indices
    /// or workspace dimensions before output/scratch writes.
    pub fn return_prefix_to(
        &self,
        input: NtruCiphertext<&[T]>,
        outputs: &mut [LweCiphertext<T>],
        workspace: &mut LweReturnBatchWorkspace<T>,
    ) {
        self.return_many_at_to(input, 0..outputs.len(), outputs, workspace);
    }

    /// Returns selected phase coefficients from one shared NTRU input.
    ///
    /// Preserves index order and repeats. Larger requests reuse one Q→q conversion
    /// across bounded key-switch tiles; an empty request writes nothing and a
    /// singleton uses the scalar path. The cloned iterator validates the entire
    /// request before writes, and must produce the same sequence as the original.
    ///
    /// # Correctness
    /// Inherits [`Self::return_at_to`]'s canonical coefficient, secret and noise
    /// requirements. Shared source noise remains correlated across outputs;
    /// batching adds no rounding or decomposition step.
    ///
    /// # Panics
    /// Rejects an active stream, invalid input/output/workspace lengths, mismatched
    /// index/output counts or out-of-range indices before output/scratch writes.
    /// An iterator that panics or changes its sequence when cloned may leave
    /// partial writes after validation.
    pub fn return_many_at_to(
        &self,
        input: NtruCiphertext<&[T]>,
        indices: impl ExactSizeIterator<Item = usize> + Clone,
        outputs: &mut [LweCiphertext<T>],
        workspace: &mut LweReturnBatchWorkspace<T>,
    ) {
        assert!(
            !workspace.is_batch_active(),
            "finish or discard the pending NTRU return batch first"
        );
        self.key
            .check_extraction(input.as_view(), indices.clone(), outputs.len());
        self.key.check_batch_outputs(outputs, &workspace.batch);
        self.key
            .switch_shared_input(input, indices, outputs, self.modulus, &mut workspace.batch);
    }

    /// Converts/extracts one phase coefficient and appends it to the current prefix.
    /// No source borrow survives; the NTRU may be overwritten immediately afterward.
    ///
    /// # Correctness
    /// Inherits [`Self::return_at_to`]'s canonical
    /// coefficient, source secret and noise requirements. Conversion precedes signs.
    /// Every append and submission in one stream must use this same return key
    /// (or a key for the same actual secrets and Q/q); workspace shape does not
    /// establish secret or modulus identity.
    ///
    /// # Panics
    /// Rejects an inactive/full batch, invalid input length/index or workspace
    /// polynomial length before writes.
    /// A rejected append does not advance the valid prefix.
    pub fn append_at(
        &self,
        input: NtruCiphertext<&[T]>,
        index: usize,
        workspace: &mut LweReturnBatchWorkspace<T>,
    ) {
        let count = workspace
            .prepared
            .expect("begin an NTRU return batch before appending");
        assert!(
            count < workspace.batch_capacity(),
            "NTRU return batch exceeds workspace capacity"
        );
        let n = self.key.poly_length();
        assert_eq!(input.as_ref().len(), n, "NTRU input length mismatch");
        assert!(index < n, "NTRU extraction index is out of range");
        assert_eq!(
            workspace.batch.poly_length(),
            n,
            "NTRU to LWE workspace length mismatch"
        );
        self.key.modulus_switch_extract_coefficient(
            input,
            index,
            workspace.batch.extracted_slot_mut(count),
            self.modulus,
        );
        workspace.prepared = Some(count + 1);
    }

    /// Returns the entire appended prefix in order, then ends the stream.
    /// Outputs must match its count exactly, including empty and short final tiles.
    /// Successful submission invalidates the prefix, preventing fresh/stale reads.
    ///
    /// # Correctness
    /// The intermediate LWEs must have been prepared by [`Self::append_at`] under
    /// this binding's actual secrets and Q/q, with [`Self::return_at_to`]'s noise
    /// budget. Workspace shape and prefix state do not establish key identity.
    ///
    /// # Panics
    /// Rejects an inactive batch, mismatched count or incompatible workspace/output
    /// dimensions before output/scratch writes. Failed validation retains the prefix for retry
    /// or discard.
    pub fn return_batch_to(
        &self,
        outputs: &mut [LweCiphertext<T>],
        workspace: &mut LweReturnBatchWorkspace<T>,
    ) {
        let count = workspace
            .prepared
            .expect("begin an NTRU return batch before submitting");
        assert_eq!(
            outputs.len(),
            count,
            "NTRU return output count differs from the prepared prefix"
        );
        self.key.check_batch_outputs(outputs, &workspace.batch);
        self.key
            .switch_extracted_tile(outputs, self.modulus, &mut workspace.batch);
        workspace.discard_batch();
    }
}

/// Reusable batch-return storage and the current stream's valid prefix.
///
/// Created by [`LweReturnEvaluator::new_batch_workspace`]. Owns one Q→q
/// polynomial plus bounded extracted/output LWE tiles, with no scalar buffer or
/// key borrow. Only `0..prepared` belongs to the current stream; old slot contents
/// never become valid merely by restarting. Compatible storage can be reused with
/// another binding after finishing or discarding the previous stream.
/// Scalar returns use independent storage and may run while this stream is active.
pub struct LweReturnBatchWorkspace<T: FheUint> {
    batch: NtruLweKeySwitchingBatchWorkspace<T>,
    // None is idle; Some(k) is an active stream, even when k is zero.
    prepared: Option<usize>,
}

impl<T: FheUint> LweReturnBatchWorkspace<T> {
    /// Returns whether a stream is active, including an empty active batch.
    #[must_use]
    pub fn is_batch_active(&self) -> bool {
        self.prepared.is_some()
    }

    /// Maximum number of extracted LWEs retained in one streamed tile.
    #[must_use]
    pub fn batch_capacity(&self) -> usize {
        self.batch.batch_capacity()
    }

    /// Starts an empty stream, discarding any previous prefix without clearing buffers.
    /// Source and BR/FFT buffers remain independently usable between appends.
    pub fn begin_batch(&mut self) {
        self.prepared = Some(0);
    }

    /// Cancels a stream without clearing buffers; does nothing when idle.
    /// Dropping this workspace also drops pending samples.
    pub fn discard_batch(&mut self) {
        self.prepared = None;
    }
}
