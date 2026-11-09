//! Public masks, frozen first-round sums and native relin key finalization.
use crate::BgvContext;

use super::super::{BgvEvaluationKeyConfig, BgvRelinearizationKey, generate::scale_with_p_to};
use super::{
    key_plan::KeyPlan,
    messages::{
        BgvCollectiveAggregate, BgvCollectiveContribution, BgvCollectiveError, Binding, Round,
    },
};

mod pending;

pub use pending::BgvCollectiveRelinearizationState;

/// Two-round collective relinearization with every cross term of `(sum s_i)^2`.
pub struct BgvCollectiveRelinearization<'c> {
    plan: KeyPlan<'c>,
    round_one_binding: Binding<'c>,
}
/// Frozen public first-round sums. No secret/ephemeral is retained.
pub struct BgvCollectiveRoundOne<'p> {
    binding: &'p Binding<'p>,
    values: Vec<u64>,
    count: usize,
}
impl BgvCollectiveRoundOne<'_> {
    /// Backend-owned canonical public payload for authenticated round broadcast.
    #[must_use]
    pub fn as_residues(&self) -> &[u64] {
        &self.values
    }
    /// Number of first-round contributions; protocol enforces full roster.
    #[must_use]
    pub fn contribution_count(&self) -> usize {
        self.count
    }
}
impl<'c> BgvCollectiveRelinearization<'c> {
    /// Prepares one exact role/level and independent uniform A_j.
    /// # Errors
    /// Rejects sampling, level or decomposition before randomness.
    pub fn try_new(
        context: &'c BgvContext,
        level: usize,
        config: impl Into<BgvEvaluationKeyConfig>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Self, BgvCollectiveError> {
        Ok(Self::from_plan(KeyPlan::new(context, level, config, rng)?))
    }
    /// Imports public masks for this exact relinearization setup.
    /// # Correctness
    /// Authenticated metadata binds context, level, role and uniform common coins.
    /// # Errors
    /// Rejects unsupported parameters or incomplete/noncanonical masks.
    pub fn try_from_common_masks(
        context: &'c BgvContext,
        level: usize,
        config: impl Into<BgvEvaluationKeyConfig>,
        masks: Vec<u64>,
    ) -> Result<Self, BgvCollectiveError> {
        Ok(Self::from_plan(KeyPlan::from_masks(
            context, level, config, masks,
        )?))
    }

    fn from_plan(plan: KeyPlan<'c>) -> Self {
        let round_one_binding = Binding::new(
            plan.binding.context,
            plan.template.key_len(),
            plan.template.key_base(),
        );
        Self {
            plan,
            round_one_binding,
        }
    }
    /// Borrows the public common-mask message.
    #[must_use]
    pub fn common_masks(&self) -> &[u64] {
        &self.plan.masks
    }
    /// Imports one authenticated first-round contribution.
    /// # Errors
    /// Rejects wrong full length or noncanonical residues.
    pub fn try_import_round_one(
        &self,
        values: Vec<u64>,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.round_one_binding.try_import(values, Round::First)
    }
    /// Allocates empty first-round public sums.
    #[must_use]
    pub fn round_one_aggregate(&self) -> BgvCollectiveAggregate<'_> {
        self.round_one_binding.aggregate(Round::First)
    }
    /// Freezes the complete first-round public sum for subsequent responses.
    /// # Errors
    /// Rejects aborted, empty or mismatched sums. Caller authenticates the complete roster.
    pub fn freeze_round_one(
        &self,
        aggregate: BgvCollectiveAggregate<'_>,
    ) -> Result<BgvCollectiveRoundOne<'_>, BgvCollectiveError> {
        let (values, count) = self.round_one_binding.finish(aggregate, Round::First)?;
        Ok(BgvCollectiveRoundOne {
            binding: &self.round_one_binding,
            values,
            count,
        })
    }
    /// Imports an authenticated complete first-round broadcast.
    /// # Errors
    /// Rejects an empty count, wrong full length or noncanonical residues. The
    /// count alone proves no roster membership; that proof belongs to the caller.
    pub fn try_import_frozen_round_one(
        &self,
        values: Vec<u64>,
        count: usize,
    ) -> Result<BgvCollectiveRoundOne<'_>, BgvCollectiveError> {
        if count == 0 {
            return Err(BgvCollectiveError::Empty);
        }
        self.round_one_binding.validate(&values)?;
        Ok(BgvCollectiveRoundOne {
            binding: &self.round_one_binding,
            values,
            count,
        })
    }
    /// Allocates a second-round sum bound to this exact frozen first round.
    /// # Errors
    /// Rejects a first-round result belonging to another setup.
    pub fn round_two_aggregate<'p>(
        &'p self,
        frozen: &'p BgvCollectiveRoundOne<'_>,
    ) -> Result<BgvCollectiveAggregate<'p>, BgvCollectiveError> {
        self.check_frozen(frozen)?;
        Ok(self.plan.binding.aggregate(Round::Second(&frozen.values)))
    }
    /// Imports a second-round response bound to the authenticated frozen round.
    /// # Errors
    /// Rejects another setup, wrong full length or noncanonical residues.
    pub fn try_import_round_two<'p>(
        &'p self,
        frozen: &'p BgvCollectiveRoundOne<'_>,
        values: Vec<u64>,
    ) -> Result<BgvCollectiveContribution<'p>, BgvCollectiveError> {
        self.check_frozen(frozen)?;
        self.plan
            .binding
            .try_import(values, Round::Second(&frozen.values))
    }
    /// Produces native columns from complete rounds in the selected key domain.
    /// Radix scales `(Z,H1)` by p; Hybrid uses `(Z,H1)` in QP directly.
    /// # Errors
    /// Rejects aborted, empty or mismatched rounds. Both authenticated round rosters must be
    /// complete and identical; contributions' identity remains caller-owned.
    pub fn finalize(
        &self,
        frozen: &BgvCollectiveRoundOne<'_>,
        aggregate: BgvCollectiveAggregate<'_>,
    ) -> Result<BgvRelinearizationKey, BgvCollectiveError> {
        self.check_frozen(frozen)?;
        let (second, count) = self
            .plan
            .binding
            .finish(aggregate, Round::Second(&frozen.values))?;
        if count != frozen.count {
            return Err(BgvCollectiveError::Binding);
        }
        let key = &self.plan.template;
        let len = key.key_poly_len();
        let mut columns = vec![0; key.key_len()];
        for ((column, z), first) in columns
            .chunks_exact_mut(2 * len)
            .zip(second.chunks_exact(len))
            .zip(frozen.values.chunks_exact(2 * len))
        {
            let (c0, c1) = column.split_at_mut(len);
            if key.is_hybrid() {
                c0.copy_from_slice(z);
                c1.copy_from_slice(&first[len..]);
            } else {
                scale_with_p_to(key.p, key.n, key.key_base(), z, c0);
                scale_with_p_to(key.p, key.n, key.key_base(), &first[len..], c1);
            }
        }
        Ok(BgvRelinearizationKey {
            key: key.with_columns(columns),
        })
    }

    fn check_frozen(&self, frozen: &BgvCollectiveRoundOne<'_>) -> Result<(), BgvCollectiveError> {
        if std::ptr::eq(frozen.binding, &self.round_one_binding) {
            Ok(())
        } else {
            Err(BgvCollectiveError::Binding)
        }
    }
}
