//! Shared numerical preparation for rank-one signed-radix evaluation keys.
//!
//! This owner binds the ring length, ordered Q base, complete column geometry
//! and CRT weights. It does not establish secret, NTT or noise provenance.

use crate::{GlweDimension, GlweSize, GlweSizeError, RnsGadgetSize, RnsGlweSize};
use primus_decompose::{
    ApproxSignedBasisError, DecompositionConfig, big_integer::BigUintApproxSignedBasis,
};
use primus_modulus::BarrettModulus;
use primus_rns::{RNSBase, Residues};
use primus_shape::PolyLength;

type Base = RNSBase<u64, BarrettModulus<u64>>;

/// Invalid radix, decomposition or complete column geometry.
#[derive(Debug, thiserror::Error)]
pub enum NativeRadixError {
    /// The radix or retained digit count is incompatible with Q.
    #[error(transparent)]
    Decomposition(#[from] ApproxSignedBasisError),
    /// Complete storage geometry overflows.
    #[error(transparent)]
    Layout(#[from] GlweSizeError),
    /// Signed digit lifting needs the radix strictly below every Q prime.
    #[error("gadget radix {radix} is not below ciphertext modulus {modulus}")]
    Radix {
        /// Selected radix.
        radix: u64,
        /// Incompatible Q prime.
        modulus: u64,
    },
}

/// Immutable decomposition, rank-one column shape and CRT weights at one Q level.
///
/// Share it through an `Arc` when several role keys use the same numerical
/// configuration. Key ciphertexts and their randomness remain independent.
pub struct NativeRadixParameters {
    poly_length: PolyLength,
    base_q: Base,
    config: DecompositionConfig,
    size: RnsGadgetSize,
    basis: BigUintApproxSignedBasis<u64>,
    weights: Vec<u64>,
}

impl NativeRadixParameters {
    /// Prepares signed-radix columns over the complete ordered active Q base.
    /// # Errors
    /// Rejects invalid decomposition, radix/Q lifting or overflowing geometry.
    pub fn try_new(
        poly_length: PolyLength,
        base_q: &Base,
        config: DecompositionConfig,
    ) -> Result<Self, NativeRadixError> {
        let basis = BigUintApproxSignedBasis::try_new(
            base_q.moduli_product(),
            config.log_basis,
            config.level_count,
        )?;
        for q in base_q.moduli() {
            if basis.basis_value() >= q.value() {
                return Err(NativeRadixError::Radix {
                    radix: basis.basis_value(),
                    modulus: q.value(),
                });
            }
        }
        let size = RnsGadgetSize::try_new(
            RnsGlweSize::try_new(
                GlweSize::try_new(GlweDimension::new(1), poly_length)?,
                base_q.moduli_count(),
            )?,
            basis.level_count(),
        )?;
        let mut weights = vec![0; basis.level_count().get() * base_q.moduli_count()];
        for (scalar, output) in basis
            .scalar_iter()
            .zip(weights.chunks_exact_mut(base_q.moduli_count()))
        {
            base_q.decompose_to(primus_integer::BigUint(scalar), Residues(output));
        }
        Ok(Self {
            poly_length,
            base_q: base_q.clone(),
            config,
            size,
            basis,
            weights,
        })
    }
    /// Ring length used by this numerical preparation.
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.poly_length
    }
    /// Complete ordered active Q base; its immutable CRT allocation is shared.
    #[must_use]
    pub fn base_q(&self) -> &Base {
        &self.base_q
    }
    /// Original decomposition request, including automatic digit-count selection.
    #[must_use]
    pub fn config(&self) -> DecompositionConfig {
        self.config
    }
    /// Checked complete rank-one gadget shape.
    #[must_use]
    pub fn size(&self) -> RnsGadgetSize {
        self.size
    }
    /// Prepared signed-radix decomposition.
    #[must_use]
    pub fn basis(&self) -> &BigUintApproxSignedBasis<u64> {
        &self.basis
    }
    /// CRT residues of one column's gadget scalar.
    /// # Panics
    /// Panics when the column index exceeds the prepared digit count.
    #[must_use]
    pub fn key_weights(&self, index: usize) -> &[u64] {
        let count = self.base_q.moduli_count();
        &self.weights[index * count..(index + 1) * count]
    }
}
