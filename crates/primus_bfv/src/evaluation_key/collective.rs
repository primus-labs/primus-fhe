//! Per-owner collective key generation. Public masks and contributions are
//! mathematical messages; authentication, roster uniqueness and session IDs
//! belong to the calling protocol. No production operation constructs Σs_i.
//!
//! Individual imported shares must actually follow CBD1 for the stated
//! distribution contract; a secret's distribution metadata cannot prove this.
//! Setup masks are public uniform common randomness, independent of private
//! errors. Checked import validates canonical geometry, not provenance.

use super::*;
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use std::ptr;

/// A malformed collective message, incompatible owner or incomplete aggregate.
#[derive(Debug, thiserror::Error)]
pub enum BfvCollectiveError {
    /// Evaluation-key parameters are invalid.
    #[error(transparent)]
    Evaluation(#[from] BfvEvaluationKeyError),
    /// This first collective construction requires exact CBD1/CBD21 sampling.
    #[error("collective BFV requires CBD1 secrets and CBD21 errors")]
    Distribution,
    /// The owner/message was bound to another actual context or setup instance.
    #[error("collective BFV setup or context mismatch")]
    Binding,
    /// A payload has an incomplete length or noncanonical residue.
    #[error("invalid collective BFV canonical payload")]
    Payload,
    /// The expected nonzero number of contributions has not been received.
    #[error("incomplete or overfull collective BFV aggregate")]
    Count,
    /// An embedded target must have exactly half the destination ring length.
    #[error("invalid collective BFV own-share embedding")]
    Embedding,
}

// A nonzero-sized stable object is used for local instance identity. Receivers
// rebind wire payloads through their own plan; identities are never serialized.
struct Binding {
    _round: u8,
}

/// An opaque public mathematical contribution bound to one local setup/round.
/// Exporting it does not reveal private native key column storage.
pub struct BfvCollectiveContribution<'a> {
    binding: &'a Binding,
    residues: Vec<u64>,
}
impl BfvCollectiveContribution<'_> {
    /// Canonical modulus-major message payload, for authenticated transport.
    #[must_use]
    pub fn as_residues(&self) -> &[u64] {
        &self.residues
    }
}

/// A public sum of messages. The protocol must enforce unique authenticated
/// owners; this arithmetic owner enforces only binding and the declared count.
pub struct BfvCollectiveAggregate<'a> {
    binding: &'a Binding,
    moduli: Vec<BarrettModulus<u64>>,
    n: usize,
    expected: usize,
    count: usize,
    residues: Vec<u64>,
}
impl BfvCollectiveAggregate<'_> {
    /// Adds one already checked same-setup contribution, rejecting before writes.
    pub fn add(
        &mut self,
        message: &BfvCollectiveContribution<'_>,
    ) -> Result<(), BfvCollectiveError> {
        if !ptr::eq(self.binding, message.binding) {
            return Err(BfvCollectiveError::Binding);
        }
        if self.count == self.expected {
            return Err(BfvCollectiveError::Count);
        }
        for (out, input) in self
            .residues
            .chunks_exact_mut(self.n * self.moduli.len())
            .zip(message.residues.chunks_exact(self.n * self.moduli.len()))
        {
            DcrtPolynomial(out).add_assign(&DcrtPolynomial(input), self.n, &self.moduli);
        }
        self.count += 1;
        Ok(())
    }
    fn finish(self, binding: &Binding) -> Result<Vec<u64>, BfvCollectiveError> {
        if !ptr::eq(self.binding, binding) {
            return Err(BfvCollectiveError::Binding);
        }
        if self.expected == 0 || self.count != self.expected {
            return Err(BfvCollectiveError::Count);
        }
        Ok(self.residues)
    }
}
fn aggregate<'a>(
    binding: &'a Binding,
    context: &'a BfvContext,
    level: usize,
    len: usize,
    expected: usize,
) -> Result<BfvCollectiveAggregate<'a>, BfvCollectiveError> {
    aggregate_basis(
        binding,
        context.parameters().poly_length().get(),
        context.codec(level).moduli_values(),
        len,
        expected,
    )
}
fn aggregate_basis<'a>(
    binding: &'a Binding,
    n: usize,
    moduli: &[u64],
    len: usize,
    expected: usize,
) -> Result<BfvCollectiveAggregate<'a>, BfvCollectiveError> {
    if expected == 0 {
        return Err(BfvCollectiveError::Count);
    }
    Ok(BfvCollectiveAggregate {
        binding,
        moduli: moduli.iter().copied().map(BarrettModulus::new).collect(),
        n,
        expected,
        count: 0,
        residues: vec![0; len],
    })
}
fn import<'a>(
    binding: &'a Binding,
    context: &BfvContext,
    level: usize,
    len: usize,
    residues: Vec<u64>,
) -> Result<BfvCollectiveContribution<'a>, BfvCollectiveError> {
    canonical(context, level, &residues, len)?;
    Ok(BfvCollectiveContribution { binding, residues })
}
fn canonical(
    context: &BfvContext,
    level: usize,
    values: &[u64],
    len: usize,
) -> Result<(), BfvCollectiveError> {
    validate_level(context, level)?;
    canonical_basis(
        context.parameters().poly_length().get(),
        context.codec(level).moduli_values(),
        values,
        len,
    )
}
fn canonical_basis(
    n: usize,
    moduli: &[u64],
    values: &[u64],
    len: usize,
) -> Result<(), BfvCollectiveError> {
    if values.len() != len || !len.is_multiple_of(n * moduli.len()) {
        return Err(BfvCollectiveError::Payload);
    }
    for poly in values.chunks_exact(n * moduli.len()) {
        for (limb, &q) in poly.chunks_exact(n).zip(moduli) {
            if limb.iter().any(|&x| x >= q) {
                return Err(BfvCollectiveError::Payload);
            }
        }
    }
    Ok(())
}
fn distribution(context: &BfvContext) -> Result<(), BfvCollectiveError> {
    let sampling = context.parameters().encryption_parameters();
    if sampling.secret_key_distr() != SecretKeyDistr::SparseTernary
        || sampling.noise_distribution().distribution()
            != (ErrorDistribution::CenteredBinomial { eta: 21 })
    {
        return Err(BfvCollectiveError::Distribution);
    }
    Ok(())
}
fn owner(client: &BfvClient<'_>, context: &BfvContext) -> Result<(), BfvCollectiveError> {
    if !ptr::eq(client.context, context) {
        return Err(BfvCollectiveError::Binding);
    }
    if client.secret_key().distr() != SecretKeyDistr::SparseTernary {
        return Err(BfvCollectiveError::Distribution);
    }
    Ok(())
}
fn secret<'a>(client: &'a BfvClient<'_>, len: usize) -> &'a [u64] {
    let DcrtPolynomial(values) = client
        .secret_key()
        .iter_dcrt_poly()
        .next()
        .expect("rank-one secret");
    &values[..len]
}
fn add_polynomials(context: &BfvContext, level: usize, output: &mut [u64], input: &[u64]) {
    let len = context.rns_poly_len(level);
    let n = context.parameters().poly_length().get();
    for (output, input) in output.chunks_exact_mut(len).zip(input.chunks_exact(len)) {
        DcrtPolynomial(output).add_assign(
            &DcrtPolynomial(input),
            n,
            context.codec(level).base_q().moduli(),
        );
    }
}
fn noise<R: rand::Rng + rand::CryptoRng>(
    context: &BfvContext,
    level: usize,
    rng: &mut R,
) -> Vec<u64> {
    let mut output = vec![0; context.rns_poly_len(level)];
    context
        .parameters()
        .encryption_parameters()
        .sample_noise_to(&mut output, context.codec(level).moduli_values(), rng);
    transform(context, &mut output, false);
    output
}
fn transform(context: &BfvContext, output: &mut [u64], inverse: bool) {
    let n = context.parameters().poly_length().get();
    for (table, limb) in context.table().iter().zip(output.chunks_exact_mut(n)) {
        if inverse {
            table.inverse_transform_slice(limb);
        } else {
            table.transform_slice(limb);
        }
    }
}
fn masks<R: rand::Rng + rand::CryptoRng>(
    context: &BfvContext,
    level: usize,
    columns: usize,
    rng: &mut R,
) -> Vec<u64> {
    let mut output = vec![0; columns * context.rns_poly_len(level)];
    for poly in output.chunks_exact_mut(context.rns_poly_len(level)) {
        primus_distr::sample_crt_uniform_values_to(
            poly,
            context.parameters().poly_length().get(),
            &context
                .parameters()
                .encryption_parameters()
                .cipher_moduli_uniform_distr()[..context.codec(level).moduli_count()],
            rng,
        );
    }
    output
}

/// Common-mask collective level-zero BFV public-key setup.
/// Each party contributes `-A*s_i+e_i`; finalize inserts A exactly once.
pub struct BfvCollectivePublicKey<'a> {
    context: &'a BfvContext,
    mask: Vec<u64>,
    binding: Binding,
}
impl<'a> BfvCollectivePublicKey<'a> {
    /// Samples public uniform A after checking the exact first-version law.
    pub fn try_new<R: rand::Rng + rand::CryptoRng>(
        context: &'a BfvContext,
        rng: &mut R,
    ) -> Result<Self, BfvCollectiveError> {
        distribution(context)?;
        Self::try_from_common_mask(context, masks(context, 0, 1, rng))
    }
    /// Binds an authenticated, canonical public mask to this actual context.
    /// The protocol establishes uniformity and the intended common-mask identity.
    pub fn try_from_common_mask(
        context: &'a BfvContext,
        mask: Vec<u64>,
    ) -> Result<Self, BfvCollectiveError> {
        distribution(context)?;
        canonical(context, 0, &mask, context.rns_poly_len(0))?;
        Ok(Self {
            context,
            mask,
            binding: Binding { _round: 0 },
        })
    }
    /// Public common A payload; no private native key columns are exposed.
    #[must_use]
    pub fn common_mask(&self) -> &[u64] {
        &self.mask
    }
    /// Expected canonical transport residue count for one body contribution.
    #[must_use]
    pub fn contribution_len(&self) -> usize {
        self.mask.len()
    }
    /// Samples only this party's body contribution using its individual share.
    pub fn contribute<R: rand::Rng + rand::CryptoRng>(
        &self,
        client: &BfvClient<'_>,
        rng: &mut R,
    ) -> Result<BfvCollectiveContribution<'_>, BfvCollectiveError> {
        owner(client, self.context)?;
        let mut body = noise(self.context, 0, rng);
        let len = body.len();
        DcrtPolynomial(body.as_mut_slice()).sub_mul_assign(
            &DcrtPolynomial(&self.mask),
            &DcrtPolynomial(secret(client, len)),
            self.context.parameters().poly_length().get(),
            self.context.codec(0).base_q().moduli(),
        );
        self.try_import_contribution(body)
    }
    /// Checks a transported body before rebinding it to this setup instance.
    pub fn try_import_contribution(
        &self,
        residues: Vec<u64>,
    ) -> Result<BfvCollectiveContribution<'_>, BfvCollectiveError> {
        import(&self.binding, self.context, 0, self.mask.len(), residues)
    }
    /// Allocates a public accumulator for a fixed nonempty authenticated roster.
    pub fn aggregate(
        &self,
        expected: usize,
    ) -> Result<BfvCollectiveAggregate<'_>, BfvCollectiveError> {
        aggregate(&self.binding, self.context, 0, self.mask.len(), expected)
    }
    /// Consumes a complete body sum and constructs the ordinary public key.
    pub fn finalize(
        &self,
        aggregate: BfvCollectiveAggregate<'_>,
    ) -> Result<crate::BfvPublicKey, BfvCollectiveError> {
        let mut body = aggregate.finish(&self.binding)?;
        body.extend_from_slice(&self.mask);
        Ok(crate::BfvPublicKey::from_collective(self.context, body))
    }
}

struct EvaluationSetup<'a> {
    context: &'a BfvContext,
    native: NativeEvaluationKey,
    masks: Vec<u64>,
    binding: Binding,
}
impl<'a> EvaluationSetup<'a> {
    fn new<R: rand::Rng + rand::CryptoRng>(
        context: &'a BfvContext,
        level: usize,
        config: impl Into<EvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<Self, BfvCollectiveError> {
        distribution(context)?;
        let native = NativeEvaluationKey::prepare_metadata(context, level, config)?;
        let mut masks = vec![0; native.key_len() / 2];
        let uniforms: Vec<_> = native
            .key_moduli_values(context)
            .iter()
            .map(|&q| rand::distr::Uniform::new(0, q).expect("validated modulus"))
            .collect();
        for poly in masks.chunks_exact_mut(native.key_poly_len()) {
            primus_distr::sample_crt_uniform_values_to(poly, native.n, &uniforms, rng);
        }
        Ok(Self {
            context,
            native,
            masks,
            binding: Binding { _round: 0 },
        })
    }
    fn from_mask(
        context: &'a BfvContext,
        level: usize,
        config: impl Into<EvaluationKeyConfig>,
        masks: Vec<u64>,
    ) -> Result<Self, BfvCollectiveError> {
        distribution(context)?;
        let native = NativeEvaluationKey::prepare_metadata(context, level, config)?;
        canonical_basis(
            native.n,
            native.key_moduli_values(context),
            &masks,
            native.key_len() / 2,
        )?;
        Ok(Self {
            context,
            native,
            masks,
            binding: Binding { _round: 0 },
        })
    }
    fn import(
        &self,
        values: Vec<u64>,
    ) -> Result<BfvCollectiveContribution<'_>, BfvCollectiveError> {
        self.import_len(&self.binding, self.masks.len(), values)
    }
    fn import_len<'p>(
        &self,
        binding: &'p Binding,
        len: usize,
        values: Vec<u64>,
    ) -> Result<BfvCollectiveContribution<'p>, BfvCollectiveError> {
        canonical_basis(
            self.native.n,
            self.native.key_moduli_values(self.context),
            &values,
            len,
        )?;
        Ok(BfvCollectiveContribution {
            binding,
            residues: values,
        })
    }
    fn aggregate(&self, expected: usize) -> Result<BfvCollectiveAggregate<'_>, BfvCollectiveError> {
        self.aggregate_len(&self.binding, self.masks.len(), expected)
    }
    fn aggregate_len<'p>(
        &self,
        binding: &'p Binding,
        len: usize,
        expected: usize,
    ) -> Result<BfvCollectiveAggregate<'p>, BfvCollectiveError> {
        aggregate_basis(
            binding,
            self.native.n,
            self.native.key_moduli_values(self.context),
            len,
            expected,
        )
    }
    fn linear<R: rand::Rng + rand::CryptoRng>(
        &self,
        source: &[u64],
        target: &[u64],
        rng: &mut R,
    ) -> Vec<u64> {
        let len = self.native.key_poly_len();
        let n = self.native.n;
        let moduli = self.native.key_moduli(self.context);
        let mut output = Vec::with_capacity(self.masks.len());
        for (index, mask) in self.masks.chunks_exact(len).enumerate() {
            let mut body = self.native.noise(self.context, rng);
            let mut poly = DcrtPolynomial(body.as_mut_slice());
            poly.sub_mul_assign(&DcrtPolynomial(mask), &DcrtPolynomial(target), n, moduli);
            poly.add_mul_scalar_assign(
                &DcrtPolynomial(source),
                self.native.weights(index),
                n,
                moduli,
            );
            output.extend(body);
        }
        output
    }
    fn empty_key(&self) -> NativeEvaluationKey {
        self.native.empty()
    }
    fn key(&self, bodies: Vec<u64>, masks: &[u64]) -> NativeEvaluationKey {
        let mut key = self.empty_key();
        let len = self.native.key_poly_len();
        for ((out, body), mask) in key
            .columns
            .chunks_exact_mut(2 * len)
            .zip(bodies.chunks_exact(len))
            .zip(masks.chunks_exact(len))
        {
            out[..len].copy_from_slice(body);
            out[len..].copy_from_slice(mask);
        }
        key
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
        config: impl Into<EvaluationKeyConfig>,
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
        config: impl Into<EvaluationKeyConfig>,
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
        source: &BfvClient<'_>,
        target: &BfvClient<'_>,
        rng: &mut R,
    ) -> Result<BfvCollectiveContribution<'_>, BfvCollectiveError> {
        owner(source, self.setup.context)?;
        owner(target, self.setup.context)?;
        let source = self.setup.native.secret(source)?;
        let target = self.setup.native.secret(target)?;
        self.setup.import(self.setup.linear(&source, &target, rng))
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
            key: self
                .setup
                .key(aggregate.finish(&self.setup.binding)?, &self.setup.masks),
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
        config: impl Into<EvaluationKeyConfig>,
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
        config: impl Into<EvaluationKeyConfig>,
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
        client: &BfvClient<'_>,
        rng: &mut R,
    ) -> Result<BfvCollectiveContribution<'_>, BfvCollectiveError> {
        owner(client, self.setup.context)?;
        let n = self.setup.context.parameters().poly_length().get();
        let secret = self.setup.native.secret(client)?;
        let mut transformed = Zeroizing::new(vec![0; self.setup.native.key_poly_len()]);
        for (input, output) in secret.chunks_exact(n).zip(transformed.chunks_exact_mut(n)) {
            self.permutation.apply_to(input, output);
        }
        self.setup
            .import(self.setup.linear(&transformed, &secret, rng))
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
            key: self
                .setup
                .key(aggregate.finish(&self.setup.binding)?, &self.setup.masks),
            exponent: self.exponent,
            permutation: NttAutomorphismPermutation::new(
                self.exponent,
                self.setup.context.parameters().poly_length(),
            ),
        })
    }
}

/// Concrete two-round S²-to-S setup with cross terms. Ordinary BFV and fresh
/// unscaled lookup use separate instances and independent randomness.
pub struct BfvCollectiveRelinearization<'a> {
    setup: EvaluationSetup<'a>,
}
impl<'a> BfvCollectiveRelinearization<'a> {
    /// Prepares independent common masks at the exact native gadget level.
    pub fn try_new<R: rand::Rng + rand::CryptoRng>(
        context: &'a BfvContext,
        level: usize,
        config: impl Into<EvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<Self, BfvCollectiveError> {
        Ok(Self {
            setup: EvaluationSetup::new(context, level, config, rng)?,
        })
    }
    /// Imports canonical authenticated common masks for this setup.
    pub fn try_from_common_mask(
        context: &'a BfvContext,
        level: usize,
        config: impl Into<EvaluationKeyConfig>,
        masks: Vec<u64>,
    ) -> Result<Self, BfvCollectiveError> {
        Ok(Self {
            setup: EvaluationSetup::from_mask(context, level, config, masks)?,
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
        client: &'p BfvClient<'a>,
        rng: &mut R,
    ) -> Result<
        (
            BfvCollectiveContribution<'p>,
            BfvCollectiveRelinearizationState<'p, 'a>,
        ),
        BfvCollectiveError,
    > {
        owner(client, self.setup.context)?;
        let context = self.setup.context;
        let len = self.setup.native.key_poly_len();
        let n = self.setup.native.n;
        let moduli = self.setup.native.key_moduli(context);
        let secret = self.setup.native.secret(client)?;
        let mut ephemeral = Zeroizing::new(vec![0; len]);
        let minus_one: Vec<_> = self
            .setup
            .native
            .key_moduli_values(context)
            .iter()
            .map(|&q| q - 1)
            .collect();
        primus_distr::sample_crt_sparse_ternary_values_to(&mut ephemeral, n, &minus_one, rng);
        self.setup.native.transform(context, &mut ephemeral, false);
        let mut values = Vec::with_capacity(2 * self.setup.masks.len());
        for (index, mask) in self.setup.masks.chunks_exact(len).enumerate() {
            let mut h0 = self.setup.native.noise(context, rng);
            let mut h1 = self.setup.native.noise(context, rng);
            DcrtPolynomial(h0.as_mut_slice()).sub_mul_assign(
                &DcrtPolynomial(mask),
                &DcrtPolynomial(ephemeral.as_slice()),
                n,
                moduli,
            );
            DcrtPolynomial(h0.as_mut_slice()).add_mul_scalar_assign(
                &DcrtPolynomial(secret.as_slice()),
                self.setup.native.weights(index),
                n,
                moduli,
            );
            DcrtPolynomial(h1.as_mut_slice()).add_mul_assign(
                &DcrtPolynomial(mask),
                &DcrtPolynomial(secret.as_slice()),
                n,
                moduli,
            );
            values.extend(h0);
            values.extend(h1);
        }
        Ok((
            BfvCollectiveContribution {
                binding: &self.setup.binding,
                residues: values,
            },
            BfvCollectiveRelinearizationState {
                setup: &self.setup,
                client,
                ephemeral,
            },
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
    /// Consumes the complete round-one sum; no partial roster can enter round two.
    pub fn freeze_round1(
        &self,
        aggregate: BfvCollectiveAggregate<'_>,
    ) -> Result<BfvCollectiveRelinearizationRound1<'_, 'a>, BfvCollectiveError> {
        let expected = aggregate.expected;
        Ok(BfvCollectiveRelinearizationRound1 {
            setup: &self.setup,
            residues: aggregate.finish(&self.setup.binding)?,
            binding: Binding { _round: 1 },
            expected,
        })
    }
}

/// One party's private single-use two-round state. Ephemeral storage is erased
/// on success, errors and unwind; it has no Clone/Debug/serialization interface.
pub struct BfvCollectiveRelinearizationState<'p, 'c> {
    setup: &'p EvaluationSetup<'c>,
    client: &'p BfvClient<'c>,
    ephemeral: Zeroizing<Vec<u64>>,
}
impl BfvCollectiveRelinearizationState<'_, '_> {
    /// Consumes this private state before producing `s_i*H0+(u_i-s_i)*H1+e2`.
    /// A rejected aggregate or RNG failure does not restore the state.
    pub fn round2<'r, R: rand::Rng + rand::CryptoRng>(
        mut self,
        round1: &'r BfvCollectiveRelinearizationRound1<'_, '_>,
        rng: &mut R,
    ) -> Result<BfvCollectiveContribution<'r>, BfvCollectiveError> {
        if !ptr::eq(self.setup, round1.setup) {
            return Err(BfvCollectiveError::Binding);
        }
        let context = self.setup.context;
        let len = self.setup.native.key_poly_len();
        let n = self.setup.native.n;
        let moduli = self.setup.native.key_moduli(context);
        let secret = self.setup.native.secret(self.client)?;
        DcrtPolynomial(self.ephemeral.as_mut_slice()).sub_assign(
            &DcrtPolynomial(secret.as_slice()),
            n,
            moduli,
        );
        let mut values = Vec::with_capacity(self.setup.masks.len());
        for pair in round1.residues.chunks_exact(2 * len) {
            let mut z = self.setup.native.noise(context, rng);
            DcrtPolynomial(z.as_mut_slice()).add_mul_assign(
                &DcrtPolynomial(secret.as_slice()),
                &DcrtPolynomial(&pair[..len]),
                n,
                moduli,
            );
            DcrtPolynomial(z.as_mut_slice()).add_mul_assign(
                &DcrtPolynomial(self.ephemeral.as_slice()),
                &DcrtPolynomial(&pair[len..]),
                n,
                moduli,
            );
            values.extend(z);
        }
        Ok(BfvCollectiveContribution {
            binding: &round1.binding,
            residues: values,
        })
    }
}

/// Frozen public H0/H1 sums bound to the actual first-round setup instance.
pub struct BfvCollectiveRelinearizationRound1<'p, 'c> {
    setup: &'p EvaluationSetup<'c>,
    residues: Vec<u64>,
    binding: Binding,
    expected: usize,
}
impl<'c> BfvCollectiveRelinearizationRound1<'_, 'c> {
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
        let mut key = self.setup.empty_key();
        for ((output, body), pair) in key
            .columns
            .chunks_exact_mut(2 * len)
            .zip(bodies.chunks_exact(len))
            .zip(self.residues.chunks_exact(2 * len))
        {
            output[..len].copy_from_slice(body);
            output[len..].copy_from_slice(&pair[len..]);
        }
        Ok(key)
    }
    /// Consumes the complete second-round aggregate into an ordinary scaled-input relin key.
    pub fn finalize(
        &self,
        aggregate: BfvCollectiveAggregate<'_>,
    ) -> Result<BfvRelinearizationKey, BfvCollectiveError> {
        Ok(BfvRelinearizationKey {
            key: self.finalize_native(aggregate)?,
        })
    }
    /// Finalizes a separately sampled setup into a consuming fresh raw lookup key.
    /// Its errors/ephemeral must be independent of all raw tensor inputs.
    pub fn finalize_lookup(
        &self,
        aggregate: BfvCollectiveAggregate<'_>,
    ) -> Result<BfvFreshLookupKey<'c>, BfvCollectiveError> {
        Ok(BfvFreshLookupKey {
            key: self.finalize_native(aggregate)?,
            context: self.setup.context,
        })
    }
}

/// Independent unscaled S²-to-S key for one mixed lookup. Unlike the ordinary
/// BFV role, this key consumes raw tensors without scale-and-round.
pub struct BfvFreshLookupKey<'a> {
    key: NativeEvaluationKey,
    context: &'a BfvContext,
}
/// Prepared consuming lookup owner, retaining the key and reusable scratch.
pub struct BfvFreshLookup<'a> {
    context: &'a BfvContext,
    key: NativeEvaluationKey,
    coefficient: Vec<u64>,
    workspace: NativeProductWorkspace<'a>,
}
/// Checked raw mixed-tensor sum `[t0,t1,t2]` in one actual context/level.
/// It is deliberately distinct from the ordinary scaled BFV quadratic type.
pub struct BfvRawQuadraticAggregate<'a> {
    context: &'a BfvContext,
    level: usize,
    residues: Vec<u64>,
}
impl<'a> BfvRawQuadraticAggregate<'a> {
    /// Checks canonical complete raw degree-two components. The protocol must
    /// construct the intended mixed tensors and aggregate every owner once.
    pub fn try_new(
        context: &'a BfvContext,
        level: usize,
        residues: Vec<u64>,
    ) -> Result<Self, BfvCollectiveError> {
        validate_level(context, level)?;
        canonical(context, level, &residues, 3 * context.rns_poly_len(level))?;
        Ok(Self {
            context,
            level,
            residues,
        })
    }
    /// Adds another checked raw tensor sum from this actual context and level.
    pub fn add(&mut self, input: Self) -> Result<(), BfvCollectiveError> {
        if !ptr::eq(self.context, input.context) || self.level != input.level {
            return Err(BfvCollectiveError::Binding);
        }
        add_polynomials(
            self.context,
            self.level,
            &mut self.residues,
            &input.residues,
        );
        Ok(())
    }
}
impl<'a> BfvFreshLookupKey<'a> {
    /// Returns the actual numerical context owned by this fresh key's setup.
    /// This establishes neither a protocol key identity nor input provenance.
    #[must_use]
    pub fn context(&self) -> &'a BfvContext {
        self.context
    }

    /// Returns the native prefix level at which this unscaled key is consumed.
    #[must_use]
    pub fn level(&self) -> usize {
        self.key.level
    }

    /// Takes ownership of the fresh key and prepares scratch in its bound context.
    /// Finalization has already established the numerical binding; there is no
    /// external context or mutable key metadata to revalidate here.
    ///
    /// # Correctness
    /// The enclosing protocol must use independently sampled fresh setup whose
    /// errors/ephemeral do not enter raw tensor inputs, including through seeds
    /// or transcripts. Preparation does not certify this provenance or noise.
    #[must_use]
    pub fn prepare(self) -> BfvFreshLookup<'a> {
        let context = self.context;
        debug_assert!(self.key.validate(context).is_ok());
        let len = context.rns_poly_len(self.key.level);
        let workspace = NativeProductWorkspace::try_new(context, &self.key)
            .expect("validated native lookup key resources");
        BfvFreshLookup {
            context,
            key: self.key,
            coefficient: vec![0; len],
            workspace,
        }
    }
}
impl BfvFreshLookup<'_> {
    /// Consumes both this key owner and the complete raw aggregate, applying one
    /// unscaled relin and no BFV scale-and-round. Prepared arithmetic allocates
    /// nothing; binding/output errors consume the owner too.
    ///
    /// # Correctness
    /// The raw tensors use the key's actual selection secret. Selector inputs
    /// must be independent of this key's errors/ephemeral (including indirect
    /// seed/transcript dependencies). The caller separately proves total noise.
    pub fn apply_to<B: DataMut<Elem = u64>>(
        mut self,
        input: BfvRawQuadraticAggregate<'_>,
        output: &mut BfvCiphertext<B>,
    ) -> Result<(), BfvCollectiveError> {
        if !ptr::eq(self.context, input.context) || self.key.level != input.level {
            return Err(BfvCollectiveError::Binding);
        }
        let len = self.coefficient.len();
        if output.as_ref().len() != 2 * len {
            return Err(BfvCollectiveError::Payload);
        }
        native_product_to(
            self.context,
            &self.key,
            &mut self.coefficient,
            &mut self.workspace,
            &input.residues[2 * len..],
            None,
            output,
        );
        add_polynomials(
            self.context,
            self.key.level,
            output.as_mut(),
            &input.residues[..2 * len],
        );
        Ok(())
    }
}

impl<'a> BfvClient<'a> {
    /// Writes only this individual share's native `c1*s_i` (not c0), without
    /// decoding, flooding or allocation. The protocol owns privacy and reuse.
    pub fn partial_phase_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &self,
        input: &BfvCiphertext<A>,
        level: usize,
        output: &mut DcrtPolynomial<B>,
    ) -> Result<(), BfvCollectiveError> {
        validate_level(self.context, level)?;
        let len = self.context.rns_poly_len(level);
        canonical(self.context, level, input.as_ref(), 2 * len)?;
        if output.as_ref().len() != len {
            return Err(BfvCollectiveError::Payload);
        }
        output.as_mut().copy_from_slice(&input.as_ref()[len..]);
        output.mul_assign(
            &DcrtPolynomial(secret(self, len)),
            self.context.parameters().poly_length().get(),
            self.context.codec(level).base_q().moduli(),
        );
        Ok(())
    }
    /// Embeds this owner's exact CBD1 N/2 secret as `s_i(X²)` in the destination
    /// N ring. INTT temporary secrets are erased. Every limb is checked against
    /// the same signed {-1,0,1} coefficients before importing/transformation.
    pub fn try_embed_secret<'b>(
        &self,
        destination: &'b BfvContext,
    ) -> Result<BfvClient<'b>, BfvCollectiveError> {
        distribution(destination)?;
        let n = self.context.parameters().poly_length().get();
        if destination.parameters().poly_length().get() != 2 * n
            || destination.parameters().codec().t() != self.context.parameters().codec().t()
        {
            return Err(BfvCollectiveError::Embedding);
        }
        let mut coefficients = Zeroizing::new(secret(self, self.context.rns_poly_len(0)).to_vec());
        transform(self.context, &mut coefficients, true);
        let mut embedded = Zeroizing::new(vec![0i64; 2 * n]);
        for (index, &value) in coefficients[..n].iter().enumerate() {
            embedded[2 * index] = if value == 0 {
                0
            } else if value == 1 {
                1
            } else if value == self.context.codec(0).moduli_values()[0] - 1 {
                -1
            } else {
                return Err(BfvCollectiveError::Embedding);
            };
        }
        for (limb, &q) in coefficients
            .chunks_exact(n)
            .zip(self.context.codec(0).moduli_values())
        {
            if limb.iter().enumerate().any(|(i, &x)| {
                x != match embedded[2 * i] {
                    -1 => q - 1,
                    0 => 0,
                    _ => 1,
                }
            }) {
                return Err(BfvCollectiveError::Embedding);
            }
        }
        let coefficient_key = GlweSecretKey::new(
            embedded.to_vec(),
            destination.parameters().size().glwe_size(),
            SecretKeyDistr::SparseTernary,
        );
        let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, destination.table());
        BfvClient::try_from_secret_key(destination, key).map_err(|_| BfvCollectiveError::Embedding)
    }
}

#[cfg(test)]
mod tests;
