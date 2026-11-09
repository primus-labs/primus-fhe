use primus_glwe_rns::DcrtGlweSecretKey;
use primus_ntt::NttAutomorphismPermutation;
use primus_poly::DcrtPolynomial;
use zeroize::Zeroizing;

use crate::{
    BfvContext,
    evaluation_key::{BfvEvaluationKeyConfig, BfvEvaluationKeyError},
    keys::{BfvAutomorphismKey, BfvKeySwitchingKey},
};

use super::{
    BfvCollectiveAggregate, BfvCollectiveContribution, BfvCollectiveError,
    evaluation_setup::EvaluationSetup, share::owner,
};

impl EvaluationSetup<'_> {
    fn linear<R: rand::Rng + rand::CryptoRng>(
        &self,
        source: &[u64],
        target: &[u64],
        rng: &mut R,
    ) -> BfvCollectiveContribution<'_> {
        let len = self.native.key_poly_len();
        let n = self.native.n;
        let moduli = self.native.key_moduli();
        let mut output = vec![0; self.masks.len()];
        for (index, (mask, body)) in self
            .masks
            .chunks_exact(len)
            .zip(output.chunks_exact_mut(len))
            .enumerate()
        {
            self.native.noise_to(self.context, body, rng);
            let mut poly = DcrtPolynomial(body);
            poly.sub_mul_assign(&DcrtPolynomial(mask), &DcrtPolynomial(target), n, moduli);
            poly.add_mul_scalar_assign(
                &DcrtPolynomial(source),
                self.native.weights(index),
                n,
                moduli,
            );
        }
        // Every column was produced by canonical native modular operations.
        BfvCollectiveContribution {
            binding: &self.binding,
            residues: output,
        }
    }
}

/// Collective unscaled source-to-target switching in one actual NTT context.
/// Source and target shares may differ; their secret IDs remain a protocol
/// contract and are supplied separately to [`Self::contribute`].
pub struct BfvCollectiveSwitchingKey<'a> {
    setup: EvaluationSetup<'a>,
}
impl<'a> BfvCollectiveSwitchingKey<'a> {
    /// Prepares independent masks in the source/target shares' common context.
    pub fn try_new<R: rand::Rng + rand::CryptoRng>(
        context: &'a BfvContext,
        level: usize,
        config: impl Into<BfvEvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<Self, BfvCollectiveError> {
        Ok(Self {
            setup: EvaluationSetup::new(context, level, config, rng)?,
        })
    }
    /// Imports canonical common masks; sender authentication/uniformity are external.
    pub fn try_from_common_mask(
        context: &'a BfvContext,
        level: usize,
        config: impl Into<BfvEvaluationKeyConfig>,
        masks: Vec<u64>,
    ) -> Result<Self, BfvCollectiveError> {
        Ok(Self {
            setup: EvaluationSetup::from_mask(context, level, config, masks)?,
        })
    }
    /// Public common masks in backend-defined payload order.
    #[must_use]
    pub fn common_mask(&self) -> &[u64] {
        &self.setup.masks
    }
    /// Expected canonical transport residue count for one body contribution.
    #[must_use]
    pub fn contribution_len(&self) -> usize {
        self.setup.masks.len()
    }
    /// Creates one contribution from this owner's source and target shares only.
    pub fn contribute<R: rand::Rng + rand::CryptoRng>(
        &self,
        source: &DcrtGlweSecretKey<u64>,
        target: &DcrtGlweSecretKey<u64>,
        rng: &mut R,
    ) -> Result<BfvCollectiveContribution<'_>, BfvCollectiveError> {
        owner(source, self.setup.context)?;
        owner(target, self.setup.context)?;
        let source = self.setup.native.secret(self.setup.context, source)?;
        let target = self.setup.native.secret(self.setup.context, target)?;
        Ok(self.setup.linear(&source, &target, rng))
    }
    /// Checks and binds a transported body payload.
    pub fn try_import_contribution(
        &self,
        values: Vec<u64>,
    ) -> Result<BfvCollectiveContribution<'_>, BfvCollectiveError> {
        self.setup.import(values)
    }
    /// Allocates a fixed-count public body sum.
    pub fn aggregate(
        &self,
        expected: usize,
    ) -> Result<BfvCollectiveAggregate<'_>, BfvCollectiveError> {
        self.setup.aggregate(expected)
    }
    /// Finalizes into the existing ordinary switching key.
    pub fn finalize(
        &self,
        aggregate: BfvCollectiveAggregate<'_>,
    ) -> Result<BfvKeySwitchingKey, BfvCollectiveError> {
        Ok(BfvKeySwitchingKey {
            key: self.setup.finalize_linear(aggregate)?,
        })
    }
}

/// Collective unscaled automorphism setup for a fixed odd exponent.
pub struct BfvCollectiveAutomorphismKey<'a> {
    setup: EvaluationSetup<'a>,
    exponent: usize,
    permutation: NttAutomorphismPermutation,
}
impl<'a> BfvCollectiveAutomorphismKey<'a> {
    /// Checks exponent and prepares the fixed-level public masks.
    pub fn try_new<R: rand::Rng + rand::CryptoRng>(
        context: &'a BfvContext,
        level: usize,
        exponent: usize,
        config: impl Into<BfvEvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<Self, BfvCollectiveError> {
        let n = context.parameters().poly_length().get();
        if exponent >= 2 * n || exponent & 1 == 0 {
            return Err(BfvEvaluationKeyError::Exponent {
                exponent,
                twice_n: 2 * n,
            }
            .into());
        }
        Ok(Self {
            setup: EvaluationSetup::new(context, level, config, rng)?,
            exponent,
            permutation: NttAutomorphismPermutation::new(
                exponent,
                context.parameters().poly_length(),
            ),
        })
    }
    /// Imports checked common masks for this fixed automorphism.
    pub fn try_from_common_mask(
        context: &'a BfvContext,
        level: usize,
        exponent: usize,
        config: impl Into<BfvEvaluationKeyConfig>,
        masks: Vec<u64>,
    ) -> Result<Self, BfvCollectiveError> {
        let n = context.parameters().poly_length().get();
        if exponent >= 2 * n || exponent & 1 == 0 {
            return Err(BfvEvaluationKeyError::Exponent {
                exponent,
                twice_n: 2 * n,
            }
            .into());
        }
        Ok(Self {
            setup: EvaluationSetup::from_mask(context, level, config, masks)?,
            exponent,
            permutation: NttAutomorphismPermutation::new(
                exponent,
                context.parameters().poly_length(),
            ),
        })
    }
    /// Public common masks, without final key columns.
    #[must_use]
    pub fn common_mask(&self) -> &[u64] {
        &self.setup.masks
    }
    /// Expected canonical transport residue count for one body contribution.
    #[must_use]
    pub fn contribution_len(&self) -> usize {
        self.setup.masks.len()
    }
    /// Samples one owner's automorphed-source contribution under its own share.
    pub fn contribute<R: rand::Rng + rand::CryptoRng>(
        &self,
        share: &DcrtGlweSecretKey<u64>,
        rng: &mut R,
    ) -> Result<BfvCollectiveContribution<'_>, BfvCollectiveError> {
        owner(share, self.setup.context)?;
        let n = self.setup.context.parameters().poly_length().get();
        let secret = self.setup.native.secret(self.setup.context, share)?;
        let mut transformed = Zeroizing::new(vec![0; self.setup.native.key_poly_len()]);
        for (input, output) in secret.chunks_exact(n).zip(transformed.chunks_exact_mut(n)) {
            self.permutation.apply_to(input, output);
        }
        Ok(self.setup.linear(&transformed, &secret, rng))
    }
    /// Checks and binds a transported body payload.
    pub fn try_import_contribution(
        &self,
        values: Vec<u64>,
    ) -> Result<BfvCollectiveContribution<'_>, BfvCollectiveError> {
        self.setup.import(values)
    }
    /// Allocates a fixed-count public body sum.
    pub fn aggregate(
        &self,
        expected: usize,
    ) -> Result<BfvCollectiveAggregate<'_>, BfvCollectiveError> {
        self.setup.aggregate(expected)
    }
    /// Produces the ordinary automorphism key with the checked exponent.
    pub fn finalize(
        &self,
        aggregate: BfvCollectiveAggregate<'_>,
    ) -> Result<BfvAutomorphismKey, BfvCollectiveError> {
        Ok(BfvAutomorphismKey {
            key: self.setup.finalize_linear(aggregate)?,
            exponent: self.exponent,
            permutation: NttAutomorphismPermutation::new(
                self.exponent,
                self.setup.context.parameters().poly_length(),
            ),
        })
    }
}
