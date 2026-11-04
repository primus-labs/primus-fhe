//! Collective arithmetic. Authentication, roster completeness and single-use
//! protocol policy belong to the caller; no method receives every private share.

use super::{
    BgvAutomorphismKey, BgvEvaluationKeyError, BgvKeySwitchingKey, BgvRelinearizationKey,
    NativeEvaluationKey,
};
use crate::{BgvCiphertext, BgvClient, BgvContext, BgvPublicKey};
use primus_data::{Data, DataMut};
use primus_decompose::DecompositionConfig;
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_ntt::{NttAutomorphismPermutation, NttTable};
use primus_poly::{DcrtPolynomial, Polynomial};
use primus_reduce::{ReduceAdd, ReduceMul};
use primus_rns::Residues;
use zeroize::Zeroizing;

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
    /// A plaintext is not N canonical field coefficients.
    #[error("collective BGV plaintext must have N canonical coefficients")]
    Plaintext,
    /// Evaluation-key geometry or decomposition is invalid.
    #[error(transparent)]
    Evaluation(#[from] BgvEvaluationKeyError),
}

// Nonzero-sized and borrowed: equality is exact owner identity, not a hash or
// equal numeric parameters. Import authenticates no remote identity by itself.
struct Binding<'c> {
    context: &'c BgvContext,
    level: usize,
    words: usize,
}

impl<'c> Binding<'c> {
    fn new(
        context: &'c BgvContext,
        level: usize,
        polynomials: usize,
    ) -> Result<Self, BgvCollectiveError> {
        validate_distribution(context)?;
        super::validate_level(context, level)?;
        Ok(Self {
            context,
            level,
            words: context
                .rns_poly_len(level)
                .checked_mul(polynomials)
                .expect("collective payload length overflow"),
        })
    }

    fn validate(&self, values: &[u64], words: usize) -> Result<(), BgvCollectiveError> {
        if values.len() != words {
            return Err(BgvCollectiveError::Length {
                expected: words,
                actual: values.len(),
            });
        }
        let n = self.context.parameters().poly_length().get();
        let moduli = self.context.base_q(self.level).moduli_values();
        if values
            .chunks_exact(n)
            .enumerate()
            .any(|(i, limb)| limb.iter().any(|&v| v >= moduli[i % moduli.len()]))
        {
            return Err(BgvCollectiveError::Residue);
        }
        Ok(())
    }

    fn client(&self, client: &BgvClient<'_>) -> Result<(), BgvCollectiveError> {
        if !std::ptr::eq(self.context, client.context) {
            return Err(BgvCollectiveError::Binding);
        }
        if client.secret_key().distr() != SecretKeyDistr::SparseTernary {
            return Err(BgvCollectiveError::Distribution);
        }
        Ok(())
    }

    fn message<'p>(
        &'p self,
        values: Vec<u64>,
        round: u8,
        frozen: Option<&'p [u64]>,
    ) -> Result<BgvCollectiveContribution<'p>, BgvCollectiveError> {
        self.validate(&values, self.words)?;
        Ok(BgvCollectiveContribution {
            binding: self,
            values,
            round,
            frozen,
        })
    }

    fn aggregate<'p>(&'p self, round: u8, frozen: Option<&'p [u64]>) -> BgvCollectiveAggregate<'p> {
        BgvCollectiveAggregate {
            binding: self,
            values: vec![0; self.words],
            round,
            frozen,
            count: 0,
        }
    }
}

fn validate_distribution(context: &BgvContext) -> Result<(), BgvCollectiveError> {
    let sampling = context.parameters().encryption_parameters();
    if sampling.secret_key_distr() != SecretKeyDistr::SparseTernary
        || sampling.noise_distribution().distribution()
            != (ErrorDistribution::CenteredBinomial { eta: 21 })
    {
        return Err(BgvCollectiveError::Distribution);
    }
    Ok(())
}

/// Opaque public mathematical contribution bound to its exact setup instance.
/// Exported residues omit identities: authenticate metadata before importing.
/// There is no secret, private ephemeral or evaluation-column accessor.
pub struct BgvCollectiveContribution<'p> {
    binding: &'p Binding<'p>,
    values: Vec<u64>,
    round: u8,
    frozen: Option<&'p [u64]>,
}

impl BgvCollectiveContribution<'_> {
    /// Canonical public payload. Its length/order are owned by this backend.
    #[must_use]
    pub fn as_residues(&self) -> &[u64] {
        &self.values
    }
}

/// A public sum for one exact setup and round.
/// `add` checks instance/round binding, not party identity or roster completeness.
pub struct BgvCollectiveAggregate<'p> {
    binding: &'p Binding<'p>,
    values: Vec<u64>,
    round: u8,
    frozen: Option<&'p [u64]>,
    count: usize,
}

impl BgvCollectiveAggregate<'_> {
    /// Adds a validated contribution without allocating or retaining its owner.
    /// # Errors
    /// Rejects other setup instances, rounds or frozen round-one results before writes.
    pub fn add(
        &mut self,
        contribution: &BgvCollectiveContribution<'_>,
    ) -> Result<(), BgvCollectiveError> {
        if !std::ptr::eq(self.binding, contribution.binding)
            || self.round != contribution.round
            || !same_frozen(self.frozen, contribution.frozen)
        {
            return Err(BgvCollectiveError::Binding);
        }
        let context = self.binding.context;
        let n = context.parameters().poly_length().get();
        let moduli = context.base_q(self.binding.level).moduli();
        for (i, (output, input)) in self
            .values
            .chunks_exact_mut(n)
            .zip(contribution.values.chunks_exact(n))
            .enumerate()
        {
            let q = moduli[i % moduli.len()];
            for (out, &value) in output.iter_mut().zip(input) {
                *out = q.reduce_add(*out, value);
            }
        }
        self.count = self
            .count
            .checked_add(1)
            .expect("collective count overflow");
        Ok(())
    }

    /// Number of mathematical contributions added; duplicates are a protocol check.
    #[must_use]
    pub fn contribution_count(&self) -> usize {
        self.count
    }
}

fn same_frozen(a: Option<&[u64]>, b: Option<&[u64]>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => std::ptr::eq(a, b),
        _ => false,
    }
}

fn check_sum(
    binding: &Binding<'_>,
    aggregate: &BgvCollectiveAggregate<'_>,
    round: u8,
    frozen: Option<&[u64]>,
) -> Result<(), BgvCollectiveError> {
    if !std::ptr::eq(binding, aggregate.binding)
        || aggregate.round != round
        || !same_frozen(aggregate.frozen, frozen)
    {
        return Err(BgvCollectiveError::Binding);
    }
    if aggregate.count == 0 {
        return Err(BgvCollectiveError::Empty);
    }
    Ok(())
}

fn noise(context: &BgvContext, level: usize, output: &mut [u64], rng: &mut impl rand::CryptoRng) {
    context
        .parameters()
        .encryption_parameters()
        .sample_noise_to(output, context.base_q(level).moduli_values(), rng);
    transform(context, output);
}

fn transform(context: &BgvContext, output: &mut [u64]) {
    for (table, limb) in context
        .table()
        .iter()
        .zip(output.chunks_exact_mut(context.parameters().poly_length().get()))
    {
        table.transform_slice(limb);
    }
}

fn uniform(context: &BgvContext, level: usize, output: &mut [u64], rng: &mut impl rand::CryptoRng) {
    let count = context.base_q(level).moduli_count();
    primus_distr::sample_crt_uniform_values_to(
        output,
        context.parameters().poly_length().get(),
        &context
            .parameters()
            .encryption_parameters()
            .cipher_moduli_uniform_distr()[..count],
        rng,
    );
}

fn secret<'a>(client: &'a BgvClient<'_>, level: usize) -> &'a [u64] {
    &client
        .secret_key()
        .iter_dcrt_poly()
        .next()
        .expect("rank-one secret")
        .0[..client.context.rns_poly_len(level)]
}

fn scale_p(context: &BgvContext, level: usize, values: &mut [u64]) {
    let n = context.parameters().poly_length().get();
    let moduli = context.base_q(level).moduli();
    for (i, limb) in values.chunks_exact_mut(n).enumerate() {
        let q = moduli[i % moduli.len()];
        for value in limb {
            *value = q.reduce_mul(*value, context.parameters().plain_modulus().value());
        }
    }
}

/// Common-mask public-key setup with native phase `p*sum(e_i)`.
/// The mask is inserted once, while only bodies are added.
pub struct BgvCollectivePublicKey<'c> {
    binding: Binding<'c>,
    mask: Vec<u64>,
}

impl<'c> BgvCollectivePublicKey<'c> {
    /// Samples public uniform NTT mask A using caller-owned randomness.
    /// # Errors
    /// Rejects a context outside the exact CBD1/CBD21 family before sampling.
    pub fn try_new(
        context: &'c BgvContext,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Self, BgvCollectiveError> {
        let binding = Binding::new(context, 0, 1)?;
        let mut mask = vec![0; binding.words];
        uniform(context, 0, &mut mask, rng);
        Ok(Self { binding, mask })
    }

    /// Imports the public mask after exact length/canonical-residue checks.
    /// # Correctness
    /// Authenticated setup binds this exact context/NTT convention and a uniform A.
    /// # Errors
    /// Rejects the sampling family, shape or noncanonical residues.
    pub fn try_from_common_mask(
        context: &'c BgvContext,
        mask: Vec<u64>,
    ) -> Result<Self, BgvCollectiveError> {
        let binding = Binding::new(context, 0, 1)?;
        binding.validate(&mask, binding.words)?;
        Ok(Self { binding, mask })
    }

    /// Borrows the public NTT mask, without exposing evaluation-key storage.
    #[must_use]
    pub fn common_mask(&self) -> &[u64] {
        &self.mask
    }

    /// Produces `-A*s_i+p*e_i` from one owner's share.
    /// # Errors
    /// Rejects a client belonging to another exact context before sampling.
    pub fn contribute<'p>(
        &'p self,
        client: &BgvClient<'_>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<BgvCollectiveContribution<'p>, BgvCollectiveError> {
        self.binding.client(client)?;
        let context = self.binding.context;
        let mut body = vec![0; self.binding.words];
        crate::client::sample_scaled_noise(context, 0, &mut body, rng);
        transform(context, &mut body);
        DcrtPolynomial(body.as_mut_slice()).sub_mul_assign(
            &DcrtPolynomial(self.mask.as_slice()),
            &DcrtPolynomial(secret(client, 0)),
            context.parameters().poly_length().get(),
            context.base_q(0).moduli(),
        );
        self.binding.message(body, 0, None)
    }

    /// Imports a public body after protocol identity/metadata validation.
    /// # Errors
    /// Rejects wrong complete length or noncanonical residues.
    pub fn try_import(
        &self,
        body: Vec<u64>,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.binding.message(body, 0, None)
    }

    /// Allocates one empty public body sum.
    #[must_use]
    pub fn aggregate(&self) -> BgvCollectiveAggregate<'_> {
        self.binding.aggregate(0, None)
    }

    /// Consumes a nonempty, protocol-complete body sum into an existing native key.
    /// # Errors
    /// Rejects another setup or an empty sum. Roster completeness is caller-owned.
    pub fn finalize(
        &self,
        aggregate: BgvCollectiveAggregate<'_>,
    ) -> Result<BgvPublicKey, BgvCollectiveError> {
        check_sum(&self.binding, &aggregate, 0, None)?;
        let mut values = aggregate.values;
        values.extend_from_slice(&self.mask);
        Ok(BgvPublicKey::from_collective(
            self.binding.context,
            BgvCiphertext::new(values),
        ))
    }
}

/// One centered additive-input domain with an independent public common A.
/// The caller consumes its per-party input authorization before `contribute`.
pub struct BgvSeededInput<'c> {
    binding: Binding<'c>,
    mask: Vec<u64>,
}

impl<'c> BgvSeededInput<'c> {
    /// Samples a fresh uniform public NTT mask from caller-owned random words.
    ///
    /// The prepared integer distributions use unbiased rejection sampling.
    /// Public mask values may be published; this does not publish the random
    /// generator's internal seed/state or authorize reuse as a public-key mask.
    /// # Errors
    /// Rejects an unsupported sampling family before allocating or sampling.
    pub fn try_new(
        context: &'c BgvContext,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Self, BgvCollectiveError> {
        let binding = Binding::new(context, 0, 1)?;
        let mut mask = vec![0; binding.words];
        uniform(context, 0, &mut mask, rng);
        Ok(Self { binding, mask })
    }

    /// Imports the public uniform common mask in this exact NTT convention.
    /// # Correctness
    /// Authenticated setup must establish a fresh, independent uniform A. A
    /// public short seed and deterministic expansion do not establish that
    /// statistical distribution; neither does a canonical-storage check.
    /// # Errors
    /// Rejects wrong family, full length or canonical range.
    pub fn try_from_common_mask(
        context: &'c BgvContext,
        common_mask: Vec<u64>,
    ) -> Result<Self, BgvCollectiveError> {
        let binding = Binding::new(context, 0, 1)?;
        binding.validate(&common_mask, binding.words)?;
        Ok(Self {
            binding,
            mask: common_mask,
        })
    }

    /// Borrows the domain's public NTT mask.
    #[must_use]
    pub fn common_mask(&self) -> &[u64] {
        &self.mask
    }

    /// Borrows the actual numerical context that owns this input's NTT tables.
    #[must_use]
    pub const fn context(&self) -> &'c BgvContext {
        self.binding.context
    }

    /// Produces `B_i=-A*s_i+center(m_i)+p*e_i` from this owner's share.
    /// # Errors
    /// Rejects other contexts or invalid plaintext before sampling/writes.
    pub fn contribute<'p, A: Data<Elem = u64>>(
        &'p self,
        client: &BgvClient<'_>,
        input: &Polynomial<A>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<BgvCollectiveContribution<'p>, BgvCollectiveError> {
        self.binding.client(client)?;
        let context = self.binding.context;
        let parameters = context.parameters();
        if input.as_ref().len() != parameters.poly_length().get()
            || input
                .as_ref()
                .iter()
                .any(|&x| x >= parameters.plain_modulus().value())
        {
            return Err(BgvCollectiveError::Plaintext);
        }
        let mut body = vec![0; self.binding.words];
        crate::client::sample_scaled_noise(context, 0, &mut body, rng);
        crate::client::add_plaintext(context, input.as_ref(), &mut body, true);
        transform(context, &mut body);
        DcrtPolynomial(body.as_mut_slice()).sub_mul_assign(
            &DcrtPolynomial(self.mask.as_slice()),
            &DcrtPolynomial(secret(client, 0)),
            parameters.poly_length().get(),
            context.base_q(0).moduli(),
        );
        self.binding.message(body, 0, None)
    }

    /// Imports a body only after its authenticated domain/party check.
    /// # Errors
    /// Rejects incomplete or noncanonical payloads.
    pub fn try_import(
        &self,
        body: Vec<u64>,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.binding.message(body, 0, None)
    }

    /// Allocates an empty sum containing no common mask yet.
    #[must_use]
    pub fn aggregate(&self) -> BgvCollectiveAggregate<'_> {
        self.binding.aggregate(0, None)
    }

    /// Inserts A once and consumes the nonempty body aggregate.
    /// # Errors
    /// Rejects an empty or differently bound sum. Caller checks complete roster.
    pub fn finalize(
        &self,
        aggregate: BgvCollectiveAggregate<'_>,
    ) -> Result<BgvCiphertext<Vec<u64>>, BgvCollectiveError> {
        check_sum(&self.binding, &aggregate, 0, None)?;
        let mut values = aggregate.values;
        values.extend_from_slice(&self.mask);
        Ok(BgvCiphertext::new(values))
    }
}

struct LinearPlan<'c> {
    binding: Binding<'c>,
    template: NativeEvaluationKey,
    masks: Vec<u64>,
}

impl<'c> LinearPlan<'c> {
    fn new(
        context: &'c BgvContext,
        level: usize,
        config: DecompositionConfig,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Self, BgvCollectiveError> {
        validate_distribution(context)?;
        let template = NativeEvaluationKey::prepare_metadata(context, level, config)?;
        let binding = Binding::new(context, level, template.basis.level_count().get())?;
        let mut masks = vec![0; binding.words];
        for mask in masks.chunks_exact_mut(context.rns_poly_len(level)) {
            uniform(context, level, mask, rng)
        }
        Ok(Self {
            binding,
            template,
            masks,
        })
    }

    fn from_masks(
        context: &'c BgvContext,
        level: usize,
        config: DecompositionConfig,
        masks: Vec<u64>,
    ) -> Result<Self, BgvCollectiveError> {
        validate_distribution(context)?;
        let template = NativeEvaluationKey::prepare_metadata(context, level, config)?;
        let binding = Binding::new(context, level, template.basis.level_count().get())?;
        binding.validate(&masks, binding.words)?;
        Ok(Self {
            binding,
            template,
            masks,
        })
    }

    fn contribute(
        &self,
        source: &BgvClient<'_>,
        target: &BgvClient<'_>,
        permutation: Option<&NttAutomorphismPermutation>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.binding.client(source)?;
        self.binding.client(target)?;
        let context = self.binding.context;
        let level = self.binding.level;
        let len = context.rns_poly_len(level);
        let n = context.parameters().poly_length().get();
        let base = context.base_q(level);
        let mut transformed = Zeroizing::new(vec![0; len]);
        if let Some(permutation) = permutation {
            for (input, output) in secret(source, level)
                .chunks_exact(n)
                .zip(transformed.chunks_exact_mut(n))
            {
                permutation.apply_to(input, output)
            }
        } else {
            transformed.copy_from_slice(secret(source, level))
        }
        let mut values = vec![0; self.binding.words];
        let mut weights = vec![0; base.moduli_count()];
        for ((body, mask), scalar) in values
            .chunks_exact_mut(len)
            .zip(self.masks.chunks_exact(len))
            .zip(self.template.basis.scalar_iter())
        {
            noise(context, level, body, rng);
            base.decompose_to(primus_integer::BigUint(scalar), Residues(&mut weights));
            let mut body = DcrtPolynomial(body);
            body.add_mul_scalar_assign(
                &DcrtPolynomial(transformed.as_slice()),
                &weights,
                n,
                base.moduli(),
            );
            body.sub_mul_assign(
                &DcrtPolynomial(mask),
                &DcrtPolynomial(secret(target, level)),
                n,
                base.moduli(),
            );
        }
        scale_p(context, level, &mut values);
        self.binding.message(values, 0, None)
    }

    fn finish(
        &self,
        aggregate: BgvCollectiveAggregate<'_>,
    ) -> Result<NativeEvaluationKey, BgvCollectiveError> {
        check_sum(&self.binding, &aggregate, 0, None)?;
        let context = self.binding.context;
        let len = context.rns_poly_len(self.binding.level);
        let mut columns = vec![0; 2 * self.binding.words];
        for ((column, body), mask) in columns
            .chunks_exact_mut(2 * len)
            .zip(aggregate.values.chunks_exact(len))
            .zip(self.masks.chunks_exact(len))
        {
            let (c0, c1) = column.split_at_mut(len);
            c0.copy_from_slice(body);
            c1.copy_from_slice(mask);
            scale_p(context, self.binding.level, c1)
        }
        Ok(copy_template(&self.template, columns))
    }
}

fn copy_template(template: &NativeEvaluationKey, columns: Vec<u64>) -> NativeEvaluationKey {
    NativeEvaluationKey {
        level: template.level,
        p: template.p,
        moduli: template.moduli.clone(),
        size: template.size,
        basis: template.basis.clone(),
        columns,
    }
}

/// Concrete collective identity switch from source shares to target shares.
/// Actual source/target identities are bound by the authenticated protocol.
pub struct BgvCollectiveSwitchingKey<'c> {
    plan: LinearPlan<'c>,
}

impl<'c> BgvCollectiveSwitchingKey<'c> {
    /// Prepares the actual radix weights and independent public masks at one level.
    /// # Errors
    /// Rejects unsupported sampling, level, geometry or decomposition.
    pub fn try_new(
        context: &'c BgvContext,
        level: usize,
        config: DecompositionConfig,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Self, BgvCollectiveError> {
        Ok(Self {
            plan: LinearPlan::new(context, level, config, rng)?,
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
        config: DecompositionConfig,
        masks: Vec<u64>,
    ) -> Result<Self, BgvCollectiveError> {
        Ok(Self {
            plan: LinearPlan::from_masks(context, level, config, masks)?,
        })
    }

    /// Borrows the opaque public common-mask payload.
    #[must_use]
    pub fn common_masks(&self) -> &[u64] {
        &self.plan.masks
    }

    /// Produces p-scaled switching bodies from only this party's two shares.
    /// # Errors
    /// Rejects clients outside this exact context before sampling.
    pub fn contribute(
        &self,
        source: &BgvClient<'_>,
        target: &BgvClient<'_>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.plan.contribute(source, target, None, rng)
    }

    /// Imports an authenticated opaque body payload.
    /// # Errors
    /// Rejects incorrect full length or noncanonical residues.
    pub fn try_import(
        &self,
        values: Vec<u64>,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.plan.binding.message(values, 0, None)
    }

    /// Allocates a public switching-body sum.
    #[must_use]
    pub fn aggregate(&self) -> BgvCollectiveAggregate<'_> {
        self.plan.binding.aggregate(0, None)
    }

    /// Consumes a nonempty complete sum into the existing native role key.
    /// # Errors
    /// Rejects wrong instance or an empty sum; protocol checks roster completeness.
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
    plan: LinearPlan<'c>,
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
        config: DecompositionConfig,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Self, BgvCollectiveError> {
        validate_exponent(context, exponent)?;
        Ok(Self {
            plan: LinearPlan::new(context, level, config, rng)?,
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
        config: DecompositionConfig,
        masks: Vec<u64>,
    ) -> Result<Self, BgvCollectiveError> {
        validate_exponent(context, exponent)?;
        Ok(Self {
            plan: LinearPlan::from_masks(context, level, config, masks)?,
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
    /// Rejects a client outside the exact context before sampling.
    pub fn contribute(
        &self,
        client: &BgvClient<'_>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.plan
            .contribute(client, client, Some(&self.permutation), rng)
    }
    /// Imports an authenticated public contribution.
    /// # Errors
    /// Rejects wrong length or noncanonical residues.
    pub fn try_import(
        &self,
        values: Vec<u64>,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.plan.binding.message(values, 0, None)
    }
    /// Allocates an empty sum of automorphism-switch bodies.
    #[must_use]
    pub fn aggregate(&self) -> BgvCollectiveAggregate<'_> {
        self.plan.binding.aggregate(0, None)
    }
    /// Consumes the complete sum into the native automorphism role key.
    /// # Errors
    /// Rejects an empty or mismatched sum; protocol checks the roster.
    pub fn finalize(
        &self,
        aggregate: BgvCollectiveAggregate<'_>,
    ) -> Result<BgvAutomorphismKey, BgvCollectiveError> {
        Ok(BgvAutomorphismKey {
            key: self.plan.finish(aggregate)?,
            exponent: self.exponent,
            permutation: NttAutomorphismPermutation::new(
                self.exponent,
                self.plan.binding.context.parameters().poly_length(),
            ),
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

/// Two-round collective relinearization with every cross term of `(sum s_i)^2`.
pub struct BgvCollectiveRelinearization<'c> {
    plan: LinearPlan<'c>,
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
/// Private, non-cloneable state for exactly one owner's second-round response.
/// The owner client remains borrowed; consuming/dropping state securely erases u.
pub struct BgvCollectiveRelinearizationState<'p, 'c> {
    plan: &'p BgvCollectiveRelinearization<'c>,
    secret: &'p [u64],
    ephemeral: Zeroizing<Vec<u64>>,
}
impl<'c> BgvCollectiveRelinearization<'c> {
    /// Prepares one exact role/level and independent uniform A_j.
    /// # Errors
    /// Rejects sampling, level or decomposition before randomness.
    pub fn try_new(
        context: &'c BgvContext,
        level: usize,
        config: DecompositionConfig,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Self, BgvCollectiveError> {
        let plan = LinearPlan::new(context, level, config, rng)?;
        let round_one_binding =
            Binding::new(context, level, 2 * plan.template.basis.level_count().get())?;
        Ok(Self {
            plan,
            round_one_binding,
        })
    }
    /// Imports public masks for this exact relinearization setup.
    /// # Correctness
    /// Authenticated metadata binds context, level, role and uniform common coins.
    /// # Errors
    /// Rejects unsupported parameters or incomplete/noncanonical masks.
    pub fn try_from_common_masks(
        context: &'c BgvContext,
        level: usize,
        config: DecompositionConfig,
        masks: Vec<u64>,
    ) -> Result<Self, BgvCollectiveError> {
        let plan = LinearPlan::from_masks(context, level, config, masks)?;
        let round_one_binding =
            Binding::new(context, level, 2 * plan.template.basis.level_count().get())?;
        Ok(Self {
            plan,
            round_one_binding,
        })
    }
    /// Borrows the public common-mask message.
    #[must_use]
    pub fn common_masks(&self) -> &[u64] {
        &self.plan.masks
    }
    /// Samples private CBD1 u_i and produces `(g*s_i-A*u_i+e0,A*s_i+e1)`.
    /// # Errors
    /// Rejects a different client context before sampling. Returned private state
    /// is single-use; caller additionally enforces its roster/setup policy.
    pub fn start<'p>(
        &'p self,
        client: &'p BgvClient<'_>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<
        (
            BgvCollectiveContribution<'p>,
            BgvCollectiveRelinearizationState<'p, 'c>,
        ),
        BgvCollectiveError,
    > {
        self.plan.binding.client(client)?;
        let context = self.plan.binding.context;
        let level = self.plan.binding.level;
        let n = context.parameters().poly_length().get();
        let len = context.rns_poly_len(level);
        let base = context.base_q(level);
        let secret = secret(client, level);
        let mut ephemeral = Zeroizing::new(vec![0; len]);
        primus_distr::sample_crt_sparse_ternary_values_to(
            &mut ephemeral,
            n,
            &context
                .parameters()
                .encryption_parameters()
                .cipher_moduli_minus_one()[..base.moduli_count()],
            rng,
        );
        transform(context, &mut ephemeral);
        let mut values = vec![0; self.round_one_binding.words];
        let mut weights = vec![0; base.moduli_count()];
        for ((column, mask), scalar) in values
            .chunks_exact_mut(2 * len)
            .zip(self.plan.masks.chunks_exact(len))
            .zip(self.plan.template.basis.scalar_iter())
        {
            let (h0, h1) = column.split_at_mut(len);
            noise(context, level, h0, rng);
            noise(context, level, h1, rng);
            base.decompose_to(primus_integer::BigUint(scalar), Residues(&mut weights));
            let mut h0 = DcrtPolynomial(h0);
            h0.add_mul_scalar_assign(&DcrtPolynomial(secret), &weights, n, base.moduli());
            h0.sub_mul_assign(
                &DcrtPolynomial(mask),
                &DcrtPolynomial(ephemeral.as_slice()),
                n,
                base.moduli(),
            );
            DcrtPolynomial(h1).add_mul_assign(
                &DcrtPolynomial(mask),
                &DcrtPolynomial(secret),
                n,
                base.moduli(),
            );
        }
        Ok((
            self.round_one_binding.message(values, 1, None)?,
            BgvCollectiveRelinearizationState {
                plan: self,
                secret,
                ephemeral,
            },
        ))
    }
    /// Imports one authenticated first-round contribution.
    /// # Errors
    /// Rejects wrong full length or noncanonical residues.
    pub fn try_import_round_one(
        &self,
        values: Vec<u64>,
    ) -> Result<BgvCollectiveContribution<'_>, BgvCollectiveError> {
        self.round_one_binding.message(values, 1, None)
    }
    /// Allocates empty first-round public sums.
    #[must_use]
    pub fn round_one_aggregate(&self) -> BgvCollectiveAggregate<'_> {
        self.round_one_binding.aggregate(1, None)
    }
    /// Freezes the complete first-round public sum for subsequent responses.
    /// # Errors
    /// Rejects empty/mismatched sums. Caller authenticates the complete roster.
    pub fn freeze_round_one(
        &self,
        aggregate: BgvCollectiveAggregate<'_>,
    ) -> Result<BgvCollectiveRoundOne<'_>, BgvCollectiveError> {
        check_sum(&self.round_one_binding, &aggregate, 1, None)?;
        Ok(BgvCollectiveRoundOne {
            binding: &self.round_one_binding,
            values: aggregate.values,
            count: aggregate.count,
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
        self.round_one_binding
            .validate(&values, self.round_one_binding.words)?;
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
        if !std::ptr::eq(frozen.binding, &self.round_one_binding) {
            return Err(BgvCollectiveError::Binding);
        }
        Ok(self.plan.binding.aggregate(2, Some(&frozen.values)))
    }
    /// Imports a second-round response bound to the authenticated frozen round.
    /// # Errors
    /// Rejects another setup, wrong full length or noncanonical residues.
    pub fn try_import_round_two<'p>(
        &'p self,
        frozen: &'p BgvCollectiveRoundOne<'_>,
        values: Vec<u64>,
    ) -> Result<BgvCollectiveContribution<'p>, BgvCollectiveError> {
        if !std::ptr::eq(frozen.binding, &self.round_one_binding) {
            return Err(BgvCollectiveError::Binding);
        }
        self.plan.binding.message(values, 2, Some(&frozen.values))
    }
    /// Produces p-scaled native columns `(p*Z,p*H1)` from complete rounds.
    /// # Errors
    /// Rejects empty/mismatched rounds. Both authenticated round rosters must be
    /// complete and identical; contributions' identity remains caller-owned.
    pub fn finalize(
        &self,
        frozen: &BgvCollectiveRoundOne<'_>,
        aggregate: BgvCollectiveAggregate<'_>,
    ) -> Result<BgvRelinearizationKey, BgvCollectiveError> {
        if !std::ptr::eq(frozen.binding, &self.round_one_binding) {
            return Err(BgvCollectiveError::Binding);
        }
        check_sum(&self.plan.binding, &aggregate, 2, Some(&frozen.values))?;
        if aggregate.count != frozen.count {
            return Err(BgvCollectiveError::Binding);
        }
        let context = self.plan.binding.context;
        let level = self.plan.binding.level;
        let len = context.rns_poly_len(level);
        let mut columns = vec![0; 2 * self.plan.binding.words];
        for ((column, z), first) in columns
            .chunks_exact_mut(2 * len)
            .zip(aggregate.values.chunks_exact(len))
            .zip(frozen.values.chunks_exact(2 * len))
        {
            let (c0, c1) = column.split_at_mut(len);
            c0.copy_from_slice(z);
            c1.copy_from_slice(&first[len..]);
            scale_p(context, level, column)
        }
        Ok(BgvRelinearizationKey {
            key: copy_template(&self.plan.template, columns),
        })
    }
}
impl BgvCollectiveRelinearizationState<'_, '_> {
    /// Consumes private u_i, borrows s_i, and returns `s_i*H0+(u_i-s_i)*H1+e2`.
    /// # Errors
    /// Rejects a different first-round setup; the private state remains consumed
    /// on every return/unwind. The protocol authenticates the complete round.
    pub fn round2<'p>(
        mut self,
        frozen: &'p BgvCollectiveRoundOne<'_>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<BgvCollectiveContribution<'p>, BgvCollectiveError>
    where
        Self: 'p,
    {
        let plan = self.plan;
        if !std::ptr::eq(frozen.binding, &plan.round_one_binding) {
            return Err(BgvCollectiveError::Binding);
        }
        let context = plan.plan.binding.context;
        let level = plan.plan.binding.level;
        let len = context.rns_poly_len(level);
        let n = context.parameters().poly_length().get();
        let base = context.base_q(level);
        DcrtPolynomial(self.ephemeral.as_mut_slice()).sub_assign(
            &DcrtPolynomial(self.secret),
            n,
            base.moduli(),
        );
        let mut values = vec![0; plan.plan.binding.words];
        for (body, first) in values
            .chunks_exact_mut(len)
            .zip(frozen.values.chunks_exact(2 * len))
        {
            noise(context, level, body, rng);
            let (h0, h1) = first.split_at(len);
            let mut body = DcrtPolynomial(body);
            body.add_mul_assign(
                &DcrtPolynomial(self.secret),
                &DcrtPolynomial(h0),
                n,
                base.moduli(),
            );
            body.add_mul_assign(
                &DcrtPolynomial(self.ephemeral.as_slice()),
                &DcrtPolynomial(h1),
                n,
                base.moduli(),
            );
        }
        plan.plan.binding.message(values, 2, Some(&frozen.values))
    }
}

impl BgvClient<'_> {
    /// Writes only this owner's native partial phase `c1*s_i`, without c0.
    /// No privacy flooding, roster check or one-use authorization is implied.
    /// # Correctness
    /// Input uses this exact actual secret and context/NTT convention.
    /// # Errors
    /// Rejects an unprepared level, wrong complete lengths or noncanonical input
    /// before writes. Allocates nothing. Arithmetic panic may partially overwrite
    /// output; no secret/noise distribution requirement is imposed by this product.
    pub fn partial_phase_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &self,
        input: &BgvCiphertext<A>,
        level: usize,
        output: &mut DcrtPolynomial<B>,
    ) -> Result<(), BgvCollectiveError> {
        super::validate_level(self.context, level)?;
        let len = self.context.rns_poly_len(level);
        let binding = Binding {
            context: self.context,
            level,
            words: len,
        };
        binding.validate(input.as_ref(), 2 * len)?;
        if output.as_ref().len() != len {
            return Err(BgvCollectiveError::Length {
                expected: len,
                actual: output.as_ref().len(),
            });
        }
        let (_, c1) = input.c0_c1(len);
        output.as_mut().copy_from_slice(c1.as_ref());
        output.mul_assign(
            &DcrtPolynomial(secret(self, level)),
            self.context.parameters().poly_length().get(),
            self.context.base_q(level).moduli(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
