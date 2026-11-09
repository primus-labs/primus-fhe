//! Canonical public bodies and sums bound to an exact local plan and round.
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, SecretKeyDistr};
use primus_poly::DcrtPolynomial;
use primus_reduce::ReduceAdd;

use crate::{BgvClient, BgvContext};

use super::super::{BgvEvaluationKeyError, backend::KeyBase};

/// Invalid collective context, message or arithmetic setup.
#[derive(Debug, thiserror::Error)]
pub enum BgvCollectiveError {
    /// The initial collective family requires exact CBD1 shares and CBD21 errors.
    #[error("collective BGV requires SparseTernary (CBD1) and CBD21")]
    Distribution,
    /// A message, client, aggregate or frozen round belongs to another instance.
    #[error("collective BGV setup/context/round binding mismatch")]
    Binding,
    /// The complete payload has a wrong length.
    #[error("collective BGV payload length mismatch: expected {expected}, got {actual}")]
    Length {
        /// Expected number of residues.
        expected: usize,
        /// Supplied number of residues.
        actual: usize,
    },
    /// A payload residue is outside its ordered modulus.
    #[error("collective BGV payload contains a noncanonical residue")]
    Residue,
    /// Finalization of an empty sum is forbidden.
    #[error("collective BGV aggregate is empty")]
    Empty,
    /// An interrupted or rejected streaming import permanently spent this sum.
    #[error("collective BGV aggregate was aborted")]
    Aborted,
    /// A plaintext is not N canonical field coefficients.
    #[error("collective BGV plaintext must have N canonical coefficients")]
    Plaintext,
    /// Evaluation-key geometry or decomposition is invalid.
    #[error(transparent)]
    Evaluation(#[from] BgvEvaluationKeyError),
}

// Nonzero-sized and borrowed: equality is exact owner identity, not a hash or
// equal numeric parameters. Import authenticates no remote identity by itself.
pub(super) struct Binding<'c> {
    pub(super) context: &'c BgvContext,
    pub(super) words: usize,
    base: KeyBase,
}

impl<'c> Binding<'c> {
    pub(super) fn top(context: &'c BgvContext) -> Result<Self, BgvCollectiveError> {
        validate_distribution(context)?;
        Ok(Self::new(
            context,
            context.rns_poly_len(0),
            context.base_q(0),
        ))
    }

    // The caller prepared the complete basis and word count before binding.
    pub(super) fn new(context: &'c BgvContext, words: usize, base: &KeyBase) -> Self {
        Self {
            context,
            words,
            base: base.clone(),
        }
    }

    pub(super) fn validate(&self, values: &[u64]) -> Result<(), BgvCollectiveError> {
        validate_values(
            self.context.parameters().poly_length().get(),
            &self.base,
            values,
            self.words,
        )
    }

    pub(super) fn client(&self, client: &BgvClient<'_>) -> Result<(), BgvCollectiveError> {
        if !std::ptr::eq(self.context, client.context) {
            return Err(BgvCollectiveError::Binding);
        }
        if client.secret_key().distr() != SecretKeyDistr::SparseTernary {
            return Err(BgvCollectiveError::Distribution);
        }
        Ok(())
    }

    pub(super) fn secret(&self, share: &DcrtGlweSecretKey<u64>) -> Result<(), BgvCollectiveError> {
        share
            .validate_parameters(
                self.context.parameters().size(),
                self.context.parameters().base_q().moduli(),
            )
            .map_err(|_| BgvCollectiveError::Binding)?;
        if share.distr() != SecretKeyDistr::SparseTernary {
            return Err(BgvCollectiveError::Distribution);
        }
        Ok(())
    }

    pub(super) fn try_import<'p>(
        &'p self,
        values: Vec<u64>,
        round: Round<'p>,
    ) -> Result<BgvCollectiveContribution<'p>, BgvCollectiveError> {
        self.validate(&values)?;
        Ok(self.contribution(values, round))
    }

    // Native kernels have already established canonical residues and shape.
    pub(super) fn contribution<'p>(
        &'p self,
        values: Vec<u64>,
        round: Round<'p>,
    ) -> BgvCollectiveContribution<'p> {
        debug_assert_eq!(values.len(), self.words);
        BgvCollectiveContribution {
            binding: self,
            values,
            round,
        }
    }

    pub(super) fn aggregate<'p>(&'p self, round: Round<'p>) -> BgvCollectiveAggregate<'p> {
        BgvCollectiveAggregate {
            binding: self,
            values: vec![0; self.words],
            round,
            count: 0,
            failed: false,
        }
    }

    pub(super) fn finish(
        &self,
        aggregate: BgvCollectiveAggregate<'_>,
        round: Round<'_>,
    ) -> Result<(Vec<u64>, usize), BgvCollectiveError> {
        if aggregate.failed {
            return Err(BgvCollectiveError::Aborted);
        }
        if !std::ptr::eq(self, aggregate.binding) || aggregate.round != round {
            return Err(BgvCollectiveError::Binding);
        }
        if aggregate.count == 0 {
            return Err(BgvCollectiveError::Empty);
        }
        Ok((aggregate.values, aggregate.count))
    }
}

pub(super) fn validate_values(
    n: usize,
    base: &KeyBase,
    values: &[u64],
    words: usize,
) -> Result<(), BgvCollectiveError> {
    if values.len() != words {
        return Err(BgvCollectiveError::Length {
            expected: words,
            actual: values.len(),
        });
    }
    if values
        .chunks_exact(n)
        .zip(base.moduli_values().iter().cycle())
        .any(|(limb, &q)| limb.iter().any(|&v| v >= q))
    {
        return Err(BgvCollectiveError::Residue);
    }
    Ok(())
}

pub(super) fn validate_distribution(context: &BgvContext) -> Result<(), BgvCollectiveError> {
    let sampling = context.parameters().encryption_parameters();
    if sampling.secret_key_distr() != SecretKeyDistr::SparseTernary
        || sampling.noise_distribution().distribution()
            != (ErrorDistribution::CenteredBinomial { eta: 21 })
    {
        return Err(BgvCollectiveError::Distribution);
    }
    Ok(())
}

/// Only a second-round payload borrows a frozen first round.
#[derive(Clone, Copy)]
pub(super) enum Round<'p> {
    Body,
    First,
    Second(&'p [u64]),
}

impl PartialEq for Round<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Body, Self::Body) | (Self::First, Self::First) => true,
            (Self::Second(lhs), Self::Second(rhs)) => std::ptr::eq(*lhs, *rhs),
            _ => false,
        }
    }
}

/// Opaque public mathematical contribution bound to its exact setup instance.
/// Exported residues omit identities: authenticate metadata before importing.
/// There is no secret, private ephemeral or evaluation-column accessor.
pub struct BgvCollectiveContribution<'p> {
    binding: &'p Binding<'p>,
    values: Vec<u64>,
    round: Round<'p>,
}

impl BgvCollectiveContribution<'_> {
    /// Canonical public payload. Its length/order are owned by this backend.
    #[must_use]
    pub fn as_residues(&self) -> &[u64] {
        &self.values
    }

    /// Transfers the public body to the caller without copying its residues.
    ///
    /// The returned words carry no local binding. The enclosing protocol
    /// authenticates their role, party and round before import.
    #[must_use]
    pub fn into_residues(self) -> Vec<u64> {
        self.values
    }
}

/// A public sum for one exact setup and round.
/// `add` checks instance/round binding, not party identity or roster completeness.
pub struct BgvCollectiveAggregate<'p> {
    binding: &'p Binding<'p>,
    values: Vec<u64>,
    round: Round<'p>,
    count: usize,
    failed: bool,
}

impl BgvCollectiveAggregate<'_> {
    /// Adds a validated contribution without allocating or retaining its owner.
    /// # Errors
    /// Rejects an aborted sum, other instances, rounds or frozen results before writes.
    pub fn add(
        &mut self,
        contribution: &BgvCollectiveContribution<'_>,
    ) -> Result<(), BgvCollectiveError> {
        if self.failed {
            return Err(BgvCollectiveError::Aborted);
        }
        if !std::ptr::eq(self.binding, contribution.binding) || self.round != contribution.round {
            return Err(BgvCollectiveError::Binding);
        }
        let n = self.binding.context.parameters().poly_length().get();
        let moduli = self.binding.base.moduli();
        let len = n * moduli.len();
        for (output, input) in self
            .values
            .chunks_exact_mut(len)
            .zip(contribution.values.chunks_exact(len))
        {
            DcrtPolynomial(output).add_assign(&DcrtPolynomial(input), n, moduli);
        }
        self.count = self
            .count
            .checked_add(1)
            .expect("collective count overflow");
        Ok(())
    }

    /// Checks and adds one complete imported body from a residue iterator.
    ///
    /// Uses this aggregate's actual ordered basis; protocol authentication and
    /// sender uniqueness must have been checked before calling. Each residue
    /// is checked immediately before its addition, without a temporary body.
    /// An error or iterator panic permanently aborts the aggregate, including
    /// every subsequent add and finalization. Earlier additions may have been
    /// written when a later residue is rejected.
    ///
    /// # Errors
    /// Rejects a short/long iterator or any value outside its exact modulus.
    /// A long iterator is stopped at the first extra value; its reported
    /// `actual` length is therefore a lower bound.
    pub fn add_imported(
        &mut self,
        values: impl IntoIterator<Item = u64>,
    ) -> Result<(), BgvCollectiveError> {
        if self.failed {
            return Err(BgvCollectiveError::Aborted);
        }
        self.failed = true;
        let mut values = values.into_iter();
        let n = self.binding.context.parameters().poly_length().get();
        let moduli = self.binding.base.moduli();
        let expected = self.values.len();
        let mut actual = 0;
        for (output, &q) in self.values.chunks_exact_mut(n).zip(moduli.iter().cycle()) {
            for out in output {
                let value = values
                    .next()
                    .ok_or(BgvCollectiveError::Length { expected, actual })?;
                actual += 1;
                if value >= q.value() {
                    return Err(BgvCollectiveError::Residue);
                }
                *out = q.reduce_add(*out, value);
            }
        }
        if values.next().is_some() {
            return Err(BgvCollectiveError::Length {
                expected,
                actual: expected + 1,
            });
        }
        self.count = self
            .count
            .checked_add(1)
            .expect("collective count overflow");
        self.failed = false;
        Ok(())
    }

    /// Number of mathematical contributions added; duplicates are a protocol check.
    #[must_use]
    pub fn contribution_count(&self) -> usize {
        self.count
    }
}
