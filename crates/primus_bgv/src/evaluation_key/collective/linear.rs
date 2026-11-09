//! Collective identity switching and automorphism role keys.
use primus_glwe_rns::DcrtGlweSecretKey;
use primus_ntt::NttAutomorphismPermutation;
use primus_poly::DcrtPolynomial;
use zeroize::Zeroizing;

use crate::BgvContext;

use super::super::{
    BgvAutomorphismKey, BgvEvaluationKeyConfig, BgvEvaluationKeyError, BgvKeySwitchingKey,
    generate::{scale_with_p, scale_with_p_to},
    material::NativeEvaluationKey,
};
use super::{
    key_plan::KeyPlan,
    messages::{BgvCollectiveAggregate, BgvCollectiveContribution, BgvCollectiveError, Round},
};

impl KeyPlan<'_> {
    fn contribute(
        &self,
        source: &DcrtGlweSecretKey<u64>,
        target: &DcrtGlweSecretKey<u64>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.binding.secret(source)?;
        self.binding.secret(target)?;
        let context = self.binding.context;
        let source = self.template.secret(context, source)?;
        let target = self.template.secret(context, target)?;
        Ok(self.linear(&source, &target, rng))
    }
    fn linear(
        &self,
        source: &[u64],
        target: &[u64],
        rng: &mut impl rand::CryptoRng,
    ) -> BgvCollectiveContribution<'_> {
        let context = self.binding.context;
        let key = &self.template;
        let len = key.key_poly_len();
        let n = key.n;
        let base = key.key_base();
        let mut values = vec![0; self.binding.words];
        for (digit, (body, mask)) in values
            .chunks_exact_mut(len)
            .zip(self.masks.chunks_exact(len))
            .enumerate()
        {
            key.noise(context, body, rng);
            let mut body = DcrtPolynomial(body);
            body.add_mul_scalar_assign(
                &DcrtPolynomial(source),
                key.weights(digit),
                n,
                base.moduli(),
            );
            body.sub_mul_assign(
                &DcrtPolynomial(mask),
                &DcrtPolynomial(target),
                n,
                base.moduli(),
            );
        }
        if !key.is_hybrid() {
            scale_with_p(key.p, n, base, &mut values);
        }
        // Every column was produced by canonical native modular operations.
        self.binding.contribution(values, Round::Body)
    }
    fn finish(
        &self,
        aggregate: BgvCollectiveAggregate<'_>,
    ) -> Result<NativeEvaluationKey, BgvCollectiveError> {
        let (bodies, _) = self.binding.finish(aggregate, Round::Body)?;
        let key = &self.template;
        let len = key.key_poly_len();
        let mut columns = vec![0; key.key_len()];
        for ((column, body), mask) in columns
            .chunks_exact_mut(2 * len)
            .zip(bodies.chunks_exact(len))
            .zip(self.masks.chunks_exact(len))
        {
            let (c0, c1) = column.split_at_mut(len);
            c0.copy_from_slice(body);
            if key.is_hybrid() {
                c1.copy_from_slice(mask);
            } else {
                scale_with_p_to(key.p, key.n, key.key_base(), mask, c1);
            }
        }
        Ok(key.with_columns(columns))
    }
}

/// Concrete collective identity switch from source shares to target shares.
/// Actual source/target identities are bound by the authenticated protocol.
pub struct BgvCollectiveSwitchingKey<'c> {
    plan: KeyPlan<'c>,
}

impl<'c> BgvCollectiveSwitchingKey<'c> {
    /// Prepares the actual radix weights and independent public masks at one level.
    /// # Errors
    /// Rejects unsupported sampling, level, geometry or decomposition.
    pub fn try_new(
        context: &'c BgvContext,
        level: usize,
        config: impl Into<BgvEvaluationKeyConfig>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Self, BgvCollectiveError> {
        Ok(Self {
            plan: KeyPlan::new(context, level, config, rng)?,
        })
    }

    /// Imports canonical public masks using backend-defined complete storage.
    /// # Correctness
    /// Caller authenticates role/source/target/context and the uniform-mask setup.
    /// # Errors
    /// Rejects unsupported parameters, wrong length or noncanonical residues.
    pub fn try_from_common_masks(
        context: &'c BgvContext,
        level: usize,
        config: impl Into<BgvEvaluationKeyConfig>,
        masks: Vec<u64>,
    ) -> Result<Self, BgvCollectiveError> {
        Ok(Self {
            plan: KeyPlan::from_masks(context, level, config, masks)?,
        })
    }

    /// Borrows the opaque public common-mask payload.
    #[must_use]
    pub fn common_masks(&self) -> &[u64] {
        &self.plan.masks
    }

    /// Produces p-scaled switching bodies from only this party's two shares.
    /// # Errors
    /// Rejects incompatible native shares before sampling.
    pub fn contribute(
        &self,
        source: &DcrtGlweSecretKey<u64>,
        target: &DcrtGlweSecretKey<u64>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.plan.contribute(source, target, rng)
    }

    /// Imports an authenticated opaque body payload.
    /// # Errors
    /// Rejects incorrect full length or noncanonical residues.
    pub fn try_import(
        &self,
        values: Vec<u64>,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.plan.binding.try_import(values, Round::Body)
    }

    /// Allocates a public switching-body sum.
    #[must_use]
    pub fn aggregate(&self) -> BgvCollectiveAggregate<'_> {
        self.plan.binding.aggregate(Round::Body)
    }

    /// Consumes a nonempty complete sum into the existing native role key.
    /// # Errors
    /// Rejects an aborted, empty or differently bound sum; protocol checks the roster.
    pub fn finalize(
        &self,
        aggregate: BgvCollectiveAggregate<'_>,
    ) -> Result<BgvKeySwitchingKey, BgvCollectiveError> {
        Ok(BgvKeySwitchingKey {
            key: self.plan.finish(aggregate)?,
        })
    }
}

/// Concrete collective σ(S)-to-S switch for one odd exponent.
pub struct BgvCollectiveAutomorphismKey<'c> {
    plan: KeyPlan<'c>,
    permutation: NttAutomorphismPermutation,
    exponent: usize,
}
impl<'c> BgvCollectiveAutomorphismKey<'c> {
    /// Prepares actual radix weights/public masks for the requested automorphism.
    /// # Errors
    /// Rejects an invalid odd exponent or unsupported sampling/level/decomposition.
    pub fn try_new(
        context: &'c BgvContext,
        level: usize,
        exponent: usize,
        config: impl Into<BgvEvaluationKeyConfig>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Self, BgvCollectiveError> {
        validate_exponent(context, exponent)?;
        Ok(Self {
            plan: KeyPlan::new(context, level, config, rng)?,
            permutation: NttAutomorphismPermutation::new(
                exponent,
                context.parameters().poly_length(),
            ),
            exponent,
        })
    }
    /// Imports authenticated canonical public common masks.
    /// # Correctness
    /// Caller binds exponent, source/target identity, context and uniform-mask setup.
    /// # Errors
    /// Rejects invalid parameters or incomplete/noncanonical masks.
    pub fn try_from_common_masks(
        context: &'c BgvContext,
        level: usize,
        exponent: usize,
        config: impl Into<BgvEvaluationKeyConfig>,
        masks: Vec<u64>,
    ) -> Result<Self, BgvCollectiveError> {
        validate_exponent(context, exponent)?;
        Ok(Self {
            plan: KeyPlan::from_masks(context, level, config, masks)?,
            permutation: NttAutomorphismPermutation::new(
                exponent,
                context.parameters().poly_length(),
            ),
            exponent,
        })
    }
    /// Public common-mask payload; decomposition storage stays private.
    #[must_use]
    pub fn common_masks(&self) -> &[u64] {
        &self.plan.masks
    }
    /// Produces this owner's automorphism-switch body contribution.
    /// # Errors
    /// Rejects incompatible native share geometry, ordered Q or declared support before sampling.
    pub fn contribute(
        &self,
        share: &DcrtGlweSecretKey<u64>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.plan.binding.secret(share)?;
        let context = self.plan.binding.context;
        let n = context.parameters().poly_length().get();
        let secret = self.plan.template.secret(context, share)?;
        let mut transformed = Zeroizing::new(vec![0; self.plan.template.key_poly_len()]);
        for (input, output) in secret.chunks_exact(n).zip(transformed.chunks_exact_mut(n)) {
            self.permutation.apply_to(input, output);
        }
        Ok(self.plan.linear(&transformed, &secret, rng))
    }
    /// Imports an authenticated public contribution.
    /// # Errors
    /// Rejects wrong length or noncanonical residues.
    pub fn try_import(
        &self,
        values: Vec<u64>,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.plan.binding.try_import(values, Round::Body)
    }
    /// Allocates an empty sum of automorphism-switch bodies.
    #[must_use]
    pub fn aggregate(&self) -> BgvCollectiveAggregate<'_> {
        self.plan.binding.aggregate(Round::Body)
    }
    /// Consumes the complete sum into the native automorphism role key.
    /// # Errors
    /// Rejects an aborted, empty or mismatched sum; protocol checks the roster.
    pub fn finalize(
        &self,
        aggregate: BgvCollectiveAggregate<'_>,
    ) -> Result<BgvAutomorphismKey, BgvCollectiveError> {
        Ok(BgvAutomorphismKey {
            key: self.plan.finish(aggregate)?,
            exponent: self.exponent,
            permutation: self.permutation.clone(),
        })
    }
}
fn validate_exponent(context: &BgvContext, exponent: usize) -> Result<(), BgvCollectiveError> {
    let twice_n = 2 * context.parameters().poly_length().get();
    if exponent >= twice_n || exponent & 1 == 0 {
        return Err(BgvEvaluationKeyError::Exponent { exponent, twice_n }.into());
    }
    Ok(())
}
