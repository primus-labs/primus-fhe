//! Native role-key storage and local context provenance.
use std::sync::Arc;

use primus_modulus::BarrettModulus;
use primus_ntt::NttAutomorphismPermutation;

use crate::BfvContext;

use super::{
    BfvEvaluationKeyError,
    backend::NativeEvaluationBasis,
    error::{validate_level, validate_ordered_moduli, validate_ring_length},
};

/// One native BFV key's actual Q level, decomposition and public columns.
/// Radix metadata and Hybrid P tables are shared immutable owners; the actual
/// Q NTT tables remain borrowed from the context. Ordinary keys retain that
/// local generating context and cannot be prepared under a foreign owner.
pub(super) struct NativeEvaluationKey {
    pub(super) context: Arc<()>,
    pub(super) level: usize,
    pub(super) t: u64,
    pub(super) n: usize,
    pub(super) basis: NativeEvaluationBasis,
    pub(super) columns: Vec<u64>,
}

impl NativeEvaluationKey {
    pub(super) fn key_poly_len(&self) -> usize {
        match &self.basis {
            NativeEvaluationBasis::Radix(p) => p.size().rns_glwe_size().rns_poly_len(),
            NativeEvaluationBasis::Hybrid(p) => p.qp_poly_len(),
        }
    }
    pub(super) fn key_len(&self) -> usize {
        match &self.basis {
            NativeEvaluationBasis::Radix(p) => p.size().rns_glev_len(),
            NativeEvaluationBasis::Hybrid(p) => p.key_len(),
        }
    }

    pub(super) fn key_moduli(&self) -> &[BarrettModulus<u64>] {
        self.basis.key_base().moduli()
    }

    pub(super) fn key_moduli_values(&self) -> &[u64] {
        self.basis.key_base().moduli_values()
    }

    pub(super) fn weights(&self, index: usize) -> &[u64] {
        match &self.basis {
            NativeEvaluationBasis::Radix(p) => p.key_weights(index),
            NativeEvaluationBasis::Hybrid(p) => p.key_weights(index),
        }
    }
    pub(super) fn empty(&self) -> Self {
        Self {
            context: Arc::clone(&self.context),
            level: self.level,
            t: self.t,
            n: self.n,
            basis: self.basis.clone(),
            columns: vec![0; self.key_len()],
        }
    }
    pub(super) fn validate(&self, context: &BfvContext) -> Result<(), BfvEvaluationKeyError> {
        if !Arc::ptr_eq(&self.context, context.identity()) {
            // A foreign owner never becomes compatible by matching numbers.
            // Retain detailed numerical diagnostics only on this error path.
            validate_level(context, self.level)?;
            validate_ring_length(self.n, context.parameters().poly_length().get())?;
            let codec = context.codec(self.level);
            if self.t != codec.t() {
                return Err(BfvEvaluationKeyError::PlainModulus {
                    expected: self.t,
                    actual: codec.t(),
                });
            }
            validate_ordered_moduli(self.basis.q_base().moduli_values(), codec.moduli_values())?;
            return Err(BfvEvaluationKeyError::ContextMismatch);
        }
        Ok(())
    }
}

/// Public role columns encrypting gadget multiples of s² under s.
///
/// Radix columns are unscaled in Q. Hybrid QP columns include P in their
/// partition weights; native ModDown removes P without a BFV message scale.
/// Construction reveals correlated evaluation keys; their security assumption
/// is additional to the fresh-ciphertext RLWE assumption.
pub struct BfvRelinearizationKey {
    pub(super) key: NativeEvaluationKey,
}

impl BfvRelinearizationKey {
    /// Returns the level for which these columns were generated.
    #[must_use]
    pub(crate) fn level(&self) -> usize {
        self.key.level
    }

    // Cold finite-family admission reads actual immutable metadata; it does not
    // recreate Hybrid NTT owners or infer a sampler/secret relation from it.
    pub(crate) fn matches_leveled_backend(
        &self,
        backend: crate::planning::BfvLeveledKeyBackend,
        auxiliary_p: &[u64],
    ) -> bool {
        match (backend, &self.key.basis) {
            (
                crate::planning::BfvLeveledKeyBackend::Radix16,
                NativeEvaluationBasis::Radix(metadata),
            ) => metadata.basis().log_basis().get() == 16 && metadata.basis().drop_bits() < 16,
            (
                crate::planning::BfvLeveledKeyBackend::HybridAlpha1,
                NativeEvaluationBasis::Hybrid(parameters),
            ) => {
                let rns = parameters.hybrid_rns();
                rns.partition_moduli_count() == 1
                    && rns.partitioning().full_q_moduli_count()
                        == rns.q_base().moduli_count() + self.key.level
                    && rns.p_base().moduli_values() == auxiliary_p
            }
            _ => false,
        }
    }
}

/// Public role columns encrypting a source secret under the target secret.
/// Hybrid columns use the separate key modulus QP, as described on
/// [`BfvRelinearizationKey`].
pub struct BfvKeySwitchingKey {
    pub(super) key: NativeEvaluationKey,
}

impl BfvKeySwitchingKey {
    /// Returns the exact prepared level at which this key is consumed.
    #[must_use]
    pub fn level(&self) -> usize {
        self.key.level
    }
}

/// Public role columns encrypting σ(s) under s for one odd automorphism.
/// Hybrid columns use the separate key modulus QP.
pub struct BfvAutomorphismKey {
    pub(super) key: NativeEvaluationKey,
    pub(super) exponent: usize,
    pub(super) permutation: NttAutomorphismPermutation,
}

impl BfvAutomorphismKey {
    /// Returns the exact prepared level at which this key is consumed.
    #[must_use]
    pub fn level(&self) -> usize {
        self.key.level
    }

    /// Returns the odd substitution exponent in `X -> X^exponent`.
    #[must_use]
    pub fn exponent(&self) -> usize {
        self.exponent
    }
}
