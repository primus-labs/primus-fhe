//! Native role-key columns and local context provenance.
use std::sync::Arc;

#[cfg(test)]
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_ntt::NttAutomorphismPermutation;

#[cfg(test)]
use crate::BgvCiphertext;
use crate::BgvContext;

use super::{
    BgvEvaluationKeyError,
    backend::{KeyBase, NativeEvaluationBasis},
    error::{
        validate_level, validate_ordered_moduli, validate_plaintext_modulus, validate_ring_length,
    },
};

/// Radix metadata and Hybrid P tables are shared immutable owners. Role keys
/// retain the generating context identity and the exact p used by their phases.
pub(super) struct NativeEvaluationKey {
    pub(super) context: Arc<()>,
    pub(super) n: usize,
    pub(super) level: usize,
    pub(super) p: u64,
    pub(super) basis: NativeEvaluationBasis,
    pub(super) columns: Vec<u64>,
}

impl NativeEvaluationKey {
    pub(super) fn key_base(&self) -> &KeyBase {
        self.basis.key_base()
    }

    pub(super) fn key_poly_len(&self) -> usize {
        match &self.basis {
            NativeEvaluationBasis::Radix(parameters) => {
                parameters.size().rns_glwe_size().rns_poly_len()
            }
            NativeEvaluationBasis::Hybrid(parameters) => parameters.qp_poly_len(),
        }
    }

    #[cfg(test)]
    pub(super) fn digit_count(&self) -> usize {
        match &self.basis {
            NativeEvaluationBasis::Radix(parameters) => parameters.basis().level_count().get(),
            NativeEvaluationBasis::Hybrid(parameters) => parameters.partition_count(),
        }
    }

    pub(super) fn key_len(&self) -> usize {
        match &self.basis {
            NativeEvaluationBasis::Radix(parameters) => parameters.size().rns_glev_len(),
            NativeEvaluationBasis::Hybrid(parameters) => parameters.key_len(),
        }
    }

    pub(super) fn is_hybrid(&self) -> bool {
        matches!(self.basis, NativeEvaluationBasis::Hybrid(_))
    }

    pub(super) fn weights(&self, index: usize) -> &[u64] {
        match &self.basis {
            NativeEvaluationBasis::Radix(parameters) => parameters.key_weights(index),
            NativeEvaluationBasis::Hybrid(parameters) => parameters.key_weights(index),
        }
    }

    pub(super) fn validate(&self, context: &BgvContext) -> Result<(), BgvEvaluationKeyError> {
        if Arc::ptr_eq(&self.context, context.identity()) {
            return Ok(());
        }
        // Foreign owners never become compatible by matching numbers. Keep
        // detailed diagnostics for the mismatched geometry.
        validate_level(context, self.level)?;
        validate_ring_length(self.n, context.parameters().poly_length().get())?;
        validate_plaintext_modulus(self.p, context.parameters().plain_modulus().value())?;
        validate_ordered_moduli(
            self.basis.q_base().moduli_values(),
            context.base_q(self.level).moduli_values(),
        )?;
        Err(BgvEvaluationKeyError::ContextMismatch)
    }

    pub(super) fn with_columns(&self, columns: Vec<u64>) -> Self {
        Self {
            context: Arc::clone(&self.context),
            n: self.n,
            level: self.level,
            p: self.p,
            basis: self.basis.clone(),
            columns,
        }
    }

    #[cfg(test)]
    pub(super) fn radix_basis(&self) -> &BigUintApproxSignedBasis<u64> {
        match &self.basis {
            NativeEvaluationBasis::Radix(parameters) => parameters.basis(),
            _ => panic!("radix oracle requires radix key"),
        }
    }

    #[cfg(test)]
    pub(super) fn ciphertexts(&self) -> impl ExactSizeIterator<Item = BgvCiphertext<&[u64]>> {
        let len = self.columns.len() / self.digit_count();
        self.columns.chunks_exact(len).map(BgvCiphertext::from_raw)
    }
}

/// Public native columns switching s² back to s. Radix encrypts p-scaled
/// gadget weights; Hybrid encrypts P times the actual CRT-projector weights.
/// Construction reveals correlated evaluation keys; their security assumption
/// is additional to the fresh-ciphertext RLWE assumption.
pub struct BgvRelinearizationKey {
    pub(super) key: NativeEvaluationKey,
}

impl BgvRelinearizationKey {
    /// Returns the level for which these columns were generated.
    #[must_use]
    pub fn level(&self) -> usize {
        self.key.level
    }
}

/// Public native columns encrypting source-secret weights under a target secret.
/// The selected radix/Hybrid representation determines its Q or QP key domain.
pub struct BgvKeySwitchingKey {
    pub(super) key: NativeEvaluationKey,
}

impl BgvKeySwitchingKey {
    /// Returns the exact prepared level at which this key is consumed.
    #[must_use]
    pub fn level(&self) -> usize {
        self.key.level
    }
}

/// Public native columns switching σ(s) back to s for one odd automorphism.
pub struct BgvAutomorphismKey {
    pub(super) key: NativeEvaluationKey,
    pub(super) exponent: usize,
    pub(super) permutation: NttAutomorphismPermutation,
}

impl BgvAutomorphismKey {
    /// Returns the native level (the number of removed tail primes).
    #[must_use]
    pub fn level(&self) -> usize {
        self.key.level
    }

    /// Returns the odd exponent in `X -> X^exponent`.
    #[must_use]
    pub fn exponent(&self) -> usize {
        self.exponent
    }
}
