mod state;

pub use state::BfvCollectiveRelinearizationState;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use primus_glwe_rns::DcrtGlweSecretKey;
use primus_poly::DcrtPolynomial;
use zeroize::Zeroizing;

use crate::{
    BfvContext,
    evaluation_key::{BfvEvaluationKeyConfig, material::NativeEvaluationKey},
    keys::BfvRelinearizationKey,
};

use super::{
    BfvCollectiveAggregate, BfvCollectiveContribution, BfvCollectiveError, BfvFreshLookupKey,
    contribution::Binding, evaluation_setup::EvaluationSetup, share::owner,
};

/// Two-round S²-to-S setup for ordinary BFV relinearization.
/// See [`BfvCollectiveSquare`] for the shared setup and first-round operations.
pub type BfvCollectiveRelinearization<'a> = BfvCollectiveSquare<'a, false>;

/// Independently sampled two-round S²-to-S setup for one raw lookup request.
/// Its common masks, errors and ephemerals must be independent of the lookup
/// inputs and every other ceremony, including indirect seed dependencies.
/// See [`BfvCollectiveSquare`] for the shared setup and first-round operations.
pub type BfvCollectiveLookup<'a> = BfvCollectiveSquare<'a, true>;

/// Shared two-round S²-to-S arithmetic for a statically selected key role.
/// Use [`BfvCollectiveRelinearization`] or [`BfvCollectiveLookup`] to choose the role.
pub struct BfvCollectiveSquare<'a, const RAW_LOOKUP: bool> {
    setup: EvaluationSetup<'a>,
    frozen: AtomicBool,
}
impl<'a, const RAW_LOOKUP: bool> BfvCollectiveSquare<'a, RAW_LOOKUP> {
    /// Prepares independent common masks at the exact native gadget level.
    pub fn try_new<R: rand::Rng + rand::CryptoRng>(
        context: &'a BfvContext,
        level: usize,
        config: impl Into<BfvEvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<Self, BfvCollectiveError> {
        Ok(Self {
            setup: EvaluationSetup::new(context, level, config, rng)?,
            frozen: AtomicBool::new(false),
        })
    }
    /// Imports canonical common masks. Authentication, role binding and
    /// independence of the imported material are the protocol's responsibility.
    pub fn try_from_common_mask(
        context: &'a BfvContext,
        level: usize,
        config: impl Into<BfvEvaluationKeyConfig>,
        masks: Vec<u64>,
    ) -> Result<Self, BfvCollectiveError> {
        Ok(Self {
            setup: EvaluationSetup::from_mask(context, level, config, masks)?,
            frozen: AtomicBool::new(false),
        })
    }
    /// The setup's public common masks in opaque backend order.
    #[must_use]
    pub fn common_mask(&self) -> &[u64] {
        &self.setup.masks
    }
    /// Expected canonical transport residue count for one first-round pair.
    #[must_use]
    pub fn contribution_len(&self) -> usize {
        2 * self.setup.masks.len()
    }
    /// Samples CBD1 u_i and independent CBD21 errors. Returns public
    /// `(g*s_i-A*u_i+e0, A*s_i+e1)` plus an erasing, noncloneable private state.
    pub fn start<'p, R: rand::Rng + rand::CryptoRng>(
        &'p self,
        share: &'p DcrtGlweSecretKey<u64>,
        rng: &mut R,
    ) -> Result<
        (
            BfvCollectiveContribution<'p>,
            BfvCollectiveRelinearizationState<'p, 'a>,
        ),
        BfvCollectiveError,
    > {
        owner(share, self.setup.context)?;
        let context = self.setup.context;
        let len = self.setup.native.key_poly_len();
        let n = self.setup.native.n;
        let moduli = self.setup.native.key_moduli();
        let secret = self.setup.native.secret(self.setup.context, share)?;
        let mut ephemeral = Zeroizing::new(vec![0; len]);
        let minus_one: Vec<_> = self
            .setup
            .native
            .key_moduli_values()
            .iter()
            .map(|&q| q - 1)
            .collect();
        primus_distr::sample_crt_sparse_ternary_values_to(&mut ephemeral, n, &minus_one, rng);
        self.setup
            .native
            .basis
            .transform_to_ntt(context, &mut ephemeral);
        let mut values = vec![0; self.contribution_len()];
        for (index, (mask, pair)) in self
            .setup
            .masks
            .chunks_exact(len)
            .zip(values.chunks_exact_mut(2 * len))
            .enumerate()
        {
            let (h0, h1) = pair.split_at_mut(len);
            self.setup.native.noise_to(context, h0, rng);
            self.setup.native.noise_to(context, h1, rng);
            let mut h0 = DcrtPolynomial(h0);
            h0.sub_mul_assign(
                &DcrtPolynomial(mask),
                &DcrtPolynomial(ephemeral.as_slice()),
                n,
                moduli,
            );
            h0.add_mul_scalar_assign(
                &DcrtPolynomial(secret.as_slice()),
                self.setup.native.weights(index),
                n,
                moduli,
            );
            DcrtPolynomial(h1).add_mul_assign(
                &DcrtPolynomial(mask),
                &DcrtPolynomial(secret.as_slice()),
                n,
                moduli,
            );
        }
        Ok((
            BfvCollectiveContribution {
                binding: &self.setup.binding,
                residues: values,
            },
            BfvCollectiveRelinearizationState::new(&self.setup, share, ephemeral),
        ))
    }
    /// Checks a transported first-round pair payload.
    pub fn try_import_contribution(
        &self,
        values: Vec<u64>,
    ) -> Result<BfvCollectiveContribution<'_>, BfvCollectiveError> {
        self.setup
            .import_len(&self.setup.binding, 2 * self.setup.masks.len(), values)
    }
    /// Allocates the first-round sum for one complete authenticated roster.
    pub fn aggregate(
        &self,
        expected: usize,
    ) -> Result<BfvCollectiveAggregate<'_>, BfvCollectiveError> {
        self.setup
            .aggregate_len(&self.setup.binding, 2 * self.setup.masks.len(), expected)
    }
    /// Consumes the complete round-one sum. A local lookup setup accepts only
    /// one complete freeze, so replay cannot issue another lookup key.
    pub fn freeze_round1(
        &self,
        aggregate: BfvCollectiveAggregate<'_>,
    ) -> Result<BfvCollectiveSquareRound1<'_, 'a, RAW_LOOKUP>, BfvCollectiveError> {
        let expected = aggregate.expected;
        let residues = aggregate.finish(&self.setup.binding)?;
        if RAW_LOOKUP && self.frozen.swap(true, Ordering::Relaxed) {
            return Err(BfvCollectiveError::ConsumedLookupSetup);
        }
        Ok(BfvCollectiveSquareRound1 {
            setup: &self.setup,
            residues,
            binding: Binding::new(),
            expected,
        })
    }
}

/// Frozen ordinary BFV relinearization first-round sums.
/// See [`BfvCollectiveSquareRound1`] for the shared second-round operations.
pub type BfvCollectiveRelinearizationRound1<'p, 'c> = BfvCollectiveSquareRound1<'p, 'c, false>;

/// Frozen fresh lookup first-round sums, consumed by finalization.
/// See [`BfvCollectiveSquareRound1`] for the shared second-round operations.
pub type BfvCollectiveLookupRound1<'p, 'c> = BfvCollectiveSquareRound1<'p, 'c, true>;

/// Frozen public H0/H1 sums bound to the actual setup instance and key role.
pub struct BfvCollectiveSquareRound1<'p, 'c, const RAW_LOOKUP: bool> {
    setup: &'p EvaluationSetup<'c>,
    residues: Vec<u64>,
    binding: Binding,
    expected: usize,
}
impl<const RAW_LOOKUP: bool> BfvCollectiveSquareRound1<'_, '_, RAW_LOOKUP> {
    /// Expected canonical transport residue count for one second-round body.
    #[must_use]
    pub fn contribution_len(&self) -> usize {
        self.setup.masks.len()
    }
    /// Checks and binds a transported second-round z payload.
    pub fn try_import_contribution(
        &self,
        values: Vec<u64>,
    ) -> Result<BfvCollectiveContribution<'_>, BfvCollectiveError> {
        self.setup
            .import_len(&self.binding, self.setup.masks.len(), values)
    }
    /// Allocates the second-round sum for the same authenticated roster size.
    /// The caller must check that its identities match the frozen first round.
    pub fn aggregate(
        &self,
        expected: usize,
    ) -> Result<BfvCollectiveAggregate<'_>, BfvCollectiveError> {
        if expected != self.expected {
            return Err(BfvCollectiveError::Count);
        }
        self.setup
            .aggregate_len(&self.binding, self.setup.masks.len(), expected)
    }
    fn finalize_native(
        &self,
        aggregate: BfvCollectiveAggregate<'_>,
    ) -> Result<NativeEvaluationKey, BfvCollectiveError> {
        let bodies = aggregate.finish(&self.binding)?;
        let len = self.setup.native.key_poly_len();
        let masks = self.residues.chunks_exact(2 * len).map(|pair| &pair[len..]);
        Ok(self.setup.assemble_key(&bodies, masks))
    }
}

impl BfvCollectiveRelinearizationRound1<'_, '_> {
    /// Consumes the complete second-round aggregate into an ordinary scaled-input relin key.
    pub fn finalize(
        &self,
        aggregate: BfvCollectiveAggregate<'_>,
    ) -> Result<BfvRelinearizationKey, BfvCollectiveError> {
        Ok(BfvRelinearizationKey {
            key: self.finalize_native(aggregate)?,
        })
    }
}

impl<'c> BfvCollectiveLookupRound1<'_, 'c> {
    /// Consumes this frozen round into a one-use raw lookup key, even on failure.
    /// The collector builds the complete second-round aggregate bound to this
    /// round from the authenticated roster. The closure keeps that borrow
    /// within finalization.
    pub fn finalize_lookup<E: From<BfvCollectiveError>>(
        self,
        collect: impl for<'r> FnOnce(&'r Self) -> Result<BfvCollectiveAggregate<'r>, E>,
    ) -> Result<BfvFreshLookupKey<'c>, E> {
        Ok(BfvFreshLookupKey {
            key: Arc::new(self.finalize_native(collect(&self)?)?),
            context: self.setup.context,
        })
    }

    /// Consumes this round and issues one handle per first-round roster member.
    /// The immutable columns are assembled once and shared by all handles.
    /// Each handle is consumed by one local evaluation of the same authenticated
    /// lookup request. The protocol binds handles to the actual receivers and
    /// ensures identical request provenance. Use [`Self::finalize_lookup`] when
    /// this process only represents a single receiver.
    pub fn finalize_lookup_for_roster<E: From<BfvCollectiveError>>(
        self,
        collect: impl for<'r> FnOnce(&'r Self) -> Result<BfvCollectiveAggregate<'r>, E>,
    ) -> Result<Vec<BfvFreshLookupKey<'c>>, E> {
        let expected = self.expected;
        let key = self.finalize_lookup(collect)?;
        Ok((0..expected)
            .map(|_| BfvFreshLookupKey {
                key: Arc::clone(&key.key),
                context: key.context,
            })
            .collect())
    }
}
