//! Ordinary binary-multiplication families with public deterministic error admission.
use std::sync::Arc;

use dashu_int::UBig;
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_glwe_rns::SecretKeyDistr;
use primus_glwe_rns::rlwe_parameters::{
    RlweParameterError, RlweSecurityInput, search_ntt_primes, security_input, validate_ntt_primes,
};
use primus_lattice::hybrid::{NativeHybridAuxiliary, NativeHybridParameters};

use crate::evaluation::{BfvLeveledMultiplication, BfvMultiplyError};
use crate::keys::{BfvEvaluationKeyConfig, BfvEvaluationKeyError, BfvRelinearizationKey};
pub use crate::parameters::BfvLeveledRequest;
use crate::parameters::DEFAULT_DECODER_MODULUS;
use crate::{BfvClient, BfvContext, BfvContextError, BfvParametersError};

const KEY_P: [u64; 1] = [1152921504606584833];

mod budget;
use budget::{Candidate, words};

/// Actual ordinary evaluation-key configuration covered by the finite budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BfvLeveledKeyBackend {
    /// Full signed radix16; its low-bit residual is included in every budget.
    Radix16,
    /// One Q prime per partition, with one independent key P prime.
    HybridAlpha1,
}

/// An unsupported model, exhausted circuit margin or incompatible ordinary key.
#[derive(Debug, thiserror::Error)]
pub enum BfvLeveledParameterError {
    /// A public model condition is unsupported; no noise or secret was inspected.
    #[error("unsupported ordinary BFV leveled model: {reason}")]
    Unsupported {
        /// Public condition that prevented admission.
        reason: &'static str,
    },
    /// The requested complete schedule exceeds a public deterministic bound.
    #[error("BFV budget exhausted at stage {stage}: input={}, required={}, available={}", bound_decimal(.input), bound_decimal(.required), bound_decimal(.available))]
    Budget {
        /// Zero denotes fresh-input admission; otherwise the multiplication layer.
        stage: usize,
        /// Actual public input-error upper bound, little-endian words.
        input: Vec<u64>,
        /// Required bound at this admission boundary, little-endian words.
        required: Vec<u64>,
        /// Available bound at the same boundary, little-endian words.
        available: Vec<u64>,
    },
    /// A generated or supplied data/key prime fails public arithmetic validation.
    #[error(transparent)]
    Primes(#[from] RlweParameterError),
    /// A supplied client or key differs from this plan's actual owner/backend.
    #[error("ordinary BFV leveled key or client binding mismatch")]
    Binding,
    /// Scheme parameters rejected the selected arithmetic or sampling law.
    #[error(transparent)]
    Parameters(#[from] BfvParametersError),
    /// The context could not prepare the selected levels or NTT tables.
    #[error(transparent)]
    Context(#[from] BfvContextError),
    /// Ordinary key generation or metadata rejected the configuration.
    #[error(transparent)]
    EvaluationKey(#[from] BfvEvaluationKeyError),
    /// The prepared multiplication rejected its arithmetic resources.
    #[error(transparent)]
    Multiplication(#[from] BfvMultiplyError),
}

pub(crate) fn unsupported(reason: &'static str) -> BfvLeveledParameterError {
    BfvLeveledParameterError::Unsupported { reason }
}

fn bound_decimal(words: &[u64]) -> UBig {
    words.iter().rev().fold(UBig::ZERO, |x, &v| (x << 64) + v)
}

/// Public integer error ledger for one actual working-HPS multiplication layer.
///
/// Every bound uses little-endian u64 words. `key_error` combines its rational
/// terms before its final ceiling, so it can be smaller than the sum of the
/// separately rounded diagnostic terms. These are worst-case public bounds,
/// never measurements of a secret key or a ciphertext phase.
#[derive(Clone, Debug)]
pub struct BfvLeveledErrorLedger {
    /// Actual working prefix product q.
    pub working_modulus: Vec<u64>,
    /// Actual restoration multiplier D=Q/q.
    pub restoration_multiplier: Vec<u64>,
    /// Computation-only HPS P, excluded from the exposed RLWE key modulus.
    pub computation_auxiliary_product: Vec<u64>,
    /// Error after exact input reduction, including fixed-Delta mismatch: U.
    pub reduced_input_error: Vec<u64>,
    /// Error after the right HPS P/q conversion, including its residual: V.
    pub converted_right_error: Vec<u64>,
    /// Absolute integer quotient bound for the centered left phase: ZA.
    pub left_phase_quotient: Vec<u64>,
    /// Absolute integer quotient bound including the HPS centered wrap: ZB.
    pub right_phase_quotient: Vec<u64>,
    /// Tensor error before the final component nearest roundings.
    pub product_error: Vec<u64>,
    /// Three final component-rounding errors evaluated under 1,s,s².
    pub component_rounding_error: Vec<u64>,
    /// Upper bound from sampled native key-column errors alone.
    pub key_sampling_error: Vec<u64>,
    /// Radix low-bit residual or Hybrid component-ModDown correction bound.
    pub key_residual_or_moddown_error: Vec<u64>,
    /// Complete key error, using the actual backend's joint integer ceiling.
    pub key_error: Vec<u64>,
    /// Error after multiplication by D=Q/q, before fixed-Delta restoration drift.
    pub restored_error: Vec<u64>,
    /// Additional fixed-Delta restoration drift r*Mout/t, rounded upward.
    pub restoration_drift: Vec<u64>,
    /// Complete external-Q phase-error bound after this layer.
    pub output_error: Vec<u64>,
    /// Maximum integer E admitted by the destination codec, for Mout=floor(t/2).
    pub decoder_capacity: Vec<u64>,
    /// Remaining error capacity after this output.
    pub remaining_error_capacity: Vec<u64>,
}

/// Deterministic ordinary public-encryption error, including unsigned embedding.
/// All integers are public upper bounds encoded as little-endian u64 words.
#[derive(Clone, Debug)]
pub struct BfvLeveledFreshErrorLedger {
    /// Shared public-key error multiplied by a fresh CBD1 ephemeral polynomial.
    pub public_key_product_error: Vec<u64>,
    /// Fresh error added to c0.
    pub body_error: Vec<u64>,
    /// Fresh error added to c1 and multiplied by the secret.
    pub mask_product_error: Vec<u64>,
    /// Unsigned-to-centered fixed-Delta drift, at most Q mod t.
    pub unsigned_embedding_drift: Vec<u64>,
    /// Sum of all four terms.
    pub total_error: Vec<u64>,
}

/// One admitted binary-multiplication layer, retaining external level zero.
///
/// Both operands must have phase error bounded by `input_error_bound`, use this
/// context's actual secret, and have canonical plaintext coefficient norm at
/// most t/2. No ciphertext storage check can infer its actual evaluated error.
/// Only honest ordinary keys from the context's actual sampler are covered; a collective key
/// with the same metadata needs a separate error budget.
pub struct BfvLeveledStep<'a> {
    context: &'a BfvContext,
    working_level: usize,
    backend: BfvLeveledKeyBackend,
    auxiliary_moduli: Vec<u64>,
    input_error: Vec<u64>,
    key_config: BfvEvaluationKeyConfig,
    key_auxiliary_moduli: Vec<u64>,
    ledger: BfvLeveledErrorLedger,
}
impl<'a> BfvLeveledStep<'a> {
    /// Actual prefix level for multiplication and its ordinary relinearization key.
    #[must_use]
    pub const fn working_level(&self) -> usize {
        self.working_level
    }
    /// Ordinary key configuration whose deterministic error was budgeted.
    #[must_use]
    pub const fn key_backend(&self) -> BfvLeveledKeyBackend {
        self.backend
    }
    /// Ordered computation-only P, distinct in meaning from Hybrid key P.
    #[must_use]
    pub fn auxiliary_moduli(&self) -> &[u64] {
        &self.auxiliary_moduli
    }
    /// Actual auxiliary key basis; empty for Radix and distinct from HPS P.
    #[must_use]
    pub fn key_auxiliary_moduli(&self) -> &[u64] {
        &self.key_auxiliary_moduli
    }
    /// Required input phase-error upper bound, as little-endian u64 words.
    #[must_use]
    pub fn input_error_bound(&self) -> &[u64] {
        &self.input_error
    }
    /// Complete restored, relinearized phase-error upper bound in external Q units.
    #[must_use]
    pub fn output_error_bound(&self) -> &[u64] {
        &self.ledger.output_error
    }
    /// Working-level ordinary relinearization error, before multiplication by Q/Q_l.
    #[must_use]
    pub fn key_error_bound(&self) -> &[u64] {
        &self.ledger.key_error
    }
    /// Clones this level's prepared key configuration by sharing its resources.
    /// No secret or NTT table is generated by this getter.
    #[must_use]
    pub fn key_config(&self) -> BfvEvaluationKeyConfig {
        self.key_config.clone()
    }
    /// Complete public decomposition of this layer's deterministic error budget.
    #[must_use]
    pub const fn error_ledger(&self) -> &BfvLeveledErrorLedger {
        &self.ledger
    }
    /// Generates an ordinary key from this exact context owner and selected model.
    pub fn relinearization_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        client: &BfvClient<'a>,
        rng: &mut R,
    ) -> Result<BfvRelinearizationKey, BfvLeveledParameterError> {
        if !std::ptr::eq(client.context(), self.context) {
            return Err(BfvLeveledParameterError::Binding);
        }
        Ok(client.relinearization_key(self.working_level, self.key_config(), rng)?)
    }
    /// Prepares the admitted operation, checking actual key level and backend.
    ///
    /// Inherits this type's input-noise/secret contracts. Numeric metadata does
    /// not prove a key was honestly sampled as an ordinary key under this law.
    pub fn prepare<'s>(
        &'s self,
        key: &'s BfvRelinearizationKey,
    ) -> Result<BfvLeveledMultiplication<'s>, BfvLeveledParameterError> {
        if key.level() != self.working_level
            || !key.matches_leveled_backend(self.backend, &self.key_auxiliary_moduli)
        {
            return Err(BfvLeveledParameterError::Binding);
        }
        Ok(BfvLeveledMultiplication::try_with_auxiliary_moduli(
            self.context,
            0,
            key,
            &self.auxiliary_moduli,
        )?)
    }
}

/// Checked finite-depth plan for ordinary working-basis BFV, using integer admission.
///
/// Covers binary circuits whose depth-d inputs obey depth-(d-1)'s error bound,
/// including square chains. Fresh public-key encryption is covered by the
/// hard support bound `Berror*(N+1+Hs)+(Q mod t)`, including unsigned message lifts.
/// Every planned operation performs a real internal
/// reduction and restores external level zero; no OpenFHE empirical cushion or
/// lower bound on unknown noise is used. This is not an automatic security-level
/// search or a certificate for collective/raw/mixed SSLE arithmetic. Steps
/// share key metadata at the same working level, and Hybrid levels share
/// the key P tables. Data-Q tables remain with the borrowed context.
pub struct BfvLeveledParameters<'a> {
    fresh_ledger: BfvLeveledFreshErrorLedger,
    secret_l1_bound: u64,
    ephemeral_l1_bound: u64,
    error_support_bound: u64,
    decoder_capacity: Vec<u64>,
    security_inputs: Vec<RlweSecurityInput>,
    steps: Vec<BfvLeveledStep<'a>>,
}
impl<'a> BfvLeveledParameters<'a> {
    /// Admits a complete ordinary binary-multiplication circuit of depth 1..=8.
    ///
    /// Each input at layer d has error at most layer d-1's published bound. The
    /// two inputs can be different, and fresh public encryptions may be reused.
    /// No additions, rotations, permanent drops, raw tensors or collective keys
    /// are implicitly admitted. Every selected operation performs a real
    /// internal reduction and restores external level zero.
    ///
    /// The sampler's public hard support bounds honest generated secrets. An
    /// imported secret/key with the same metadata is not authenticated by this
    /// plan. Gaussian bounds cover the implemented truncated sampler, not an
    /// ideal unbounded Gaussian. Separate RLWE analysis inputs remain
    /// `NotEvaluated`; correctness admission never implies a hardness estimate.
    pub fn try_new(
        context: &'a BfvContext,
        depth: usize,
        backend: BfvLeveledKeyBackend,
    ) -> Result<Self, BfvLeveledParameterError> {
        if !(1..=8).contains(&depth) {
            return Err(unsupported("binary multiplication depth must be in 1..=8"));
        }
        let parameters = context.parameters();
        let n = parameters.poly_length().get();
        let qs = parameters.base_q().moduli_values();
        let sampling = parameters.encryption_parameters();
        let mut data_security = security_input(sampling, qs, &[])?;
        data_security.ephemeral_distribution = Some(SecretKeyDistr::SparseTernary);
        if qs.len() < 2 || context.level_count() != qs.len() {
            return Err(unsupported(
                "all Q prefixes and at least one smaller working basis are required",
            ));
        }
        if backend == BfvLeveledKeyBackend::Radix16 && qs.iter().any(|&q| q <= (1 << 16)) {
            return Err(unsupported(
                "Radix16 requires every data prime to exceed its radix 65536",
            ));
        }
        if parameters.codec().gamma() != DEFAULT_DECODER_MODULUS {
            return Err(unsupported(
                "this family uses the default prime decoder gamma=2^61-1",
            ));
        }
        let support = sampling.secret_key_sampler().maximum_magnitude();
        let secret_l1_bound = match sampling.secret_key_distr() {
            SecretKeyDistr::FixedHammingWeightBinary { hamming_weight }
            | SecretKeyDistr::FixedHammingWeightTernary { hamming_weight } => hamming_weight as u64,
            SecretKeyDistr::FixedCompositionTernary {
                negative_one_weight,
                one_weight,
            } => (negative_one_weight + one_weight) as u64,
            SecretKeyDistr::BlockBinary { block_size, .. } => (n / block_size) as u64,
            _ => (n as u64).checked_mul(support).ok_or_else(|| {
                unsupported("secret L1 support does not fit the supported u64 model")
            })?,
        };
        // Public encryption deliberately samples CBD1 independently of the
        // long-term secret law (public_key.rs); do not reuse secret support.
        let ephemeral_l1_bound = n as u64;
        let eta = sampling.noise_distribution().maximum_magnitude();
        if secret_l1_bound.checked_mul(secret_l1_bound).is_none()
            || secret_l1_bound.checked_add(1).is_none()
        {
            return Err(unsupported(
                "squared-secret L1 support exceeds the supported u64 model",
            ));
        }
        let t = parameters.codec().t();
        let q = bound_decimal(parameters.base_q().moduli_product().0);
        let gamma = UBig::from(DEFAULT_DECODER_MODULUS);
        let r = &q % t;
        let decoder_overhead = UBig::from(2u8) * r * (t / 2) * &gamma + &q * (2 * qs.len());
        if &q * &gamma <= decoder_overhead {
            return Err(unsupported(
                "destination codec has no error capacity for canonical messages",
            ));
        }
        let capacity = (&q * &gamma - 1u8 - decoder_overhead) / (UBig::from(2u8) * t * &gamma);
        let key_p = match backend {
            BfvLeveledKeyBackend::Radix16 => Vec::new(),
            BfvLeveledKeyBackend::HybridAlpha1 => {
                if !qs.contains(&KEY_P[0]) && validate_ntt_primes(n, &KEY_P).is_ok() {
                    KEY_P.to_vec()
                } else {
                    search_ntt_primes(n, 60, 1, None, qs)?
                }
            }
        };
        let candidates = (1..qs.len())
            .map(|keep| Candidate::new(context, keep, backend, secret_l1_bound, eta, &key_p, &q))
            .collect::<Result<Vec<_>, _>>()?;
        let fresh = UBig::from(eta) * (UBig::from(secret_l1_bound) + ephemeral_l1_bound + 1u8) + r;
        let fresh_ledger = BfvLeveledFreshErrorLedger {
            public_key_product_error: words(&(UBig::from(eta) * ephemeral_l1_bound)),
            body_error: words(&UBig::from(eta)),
            mask_product_error: words(&(UBig::from(eta) * secret_l1_bound)),
            unsigned_embedding_drift: words(&UBig::from(r)),
            total_error: words(&fresh),
        };
        let mut limits = vec![capacity.clone()];
        for _ in 0..depth {
            let target = limits.last().expect("initial capacity");
            let mut best = UBig::ZERO;
            for c in &candidates {
                if c.output(&UBig::ZERO) > *target {
                    continue;
                }
                let (mut lo, mut hi) = (UBig::ZERO, capacity.clone());
                while lo < hi {
                    let middle = (&lo + &hi + 1u8) / 2u8;
                    if c.output(&middle) <= *target {
                        lo = middle;
                    } else {
                        hi = middle - 1u8;
                    }
                }
                best = best.max(lo);
            }
            limits.push(best);
        }
        if fresh > limits[depth] {
            return Err(BfvLeveledParameterError::Budget {
                stage: 0,
                input: words(&fresh),
                required: words(&fresh),
                available: words(&limits[depth]),
            });
        }
        let mut error = fresh.clone();
        let mut steps = Vec::with_capacity(depth);
        let mut key_configs = vec![None; qs.len()];
        let mut hybrid_auxiliary = None;
        let mut security_inputs = vec![data_security];
        for index in 0..depth {
            let limit = &limits[depth - index - 1];
            let (c, bounds) = candidates
                .iter()
                .map(|c| (c, c.evaluate(&error)))
                .find(|(_, bounds)| bounds.output_error <= *limit)
                .ok_or_else(|| BfvLeveledParameterError::Budget {
                    stage: index + 1,
                    input: words(&error),
                    required: words(
                        &candidates
                            .iter()
                            .map(|c| c.output(&error))
                            .min()
                            .expect("working candidates"),
                    ),
                    available: words(limit),
                })?;
            let working_level = qs.len() - c.keep;
            if key_configs[working_level].is_none() {
                let config = match backend {
                    BfvLeveledKeyBackend::Radix16 => context
                        .radix_key_parameters(
                            working_level,
                            DecompositionConfig {
                                log_basis: DecompositionBaseLog::new(16),
                                level_count: None,
                            },
                        )?
                        .into(),
                    BfvLeveledKeyBackend::HybridAlpha1 => {
                        let mut key_security = security_input(sampling, &qs[..c.keep], &key_p)?;
                        key_security.ephemeral_distribution = Some(SecretKeyDistr::SparseTernary);
                        security_inputs.push(key_security);
                        if hybrid_auxiliary.is_none() {
                            hybrid_auxiliary = Some(Arc::new(
                                NativeHybridAuxiliary::try_new(parameters.poly_length(), &key_p)
                                    .map_err(BfvEvaluationKeyError::from)?,
                            ));
                        }
                        let prepared = NativeHybridParameters::try_with_auxiliary(
                            context.codec(working_level).base_q(),
                            qs.len(),
                            Arc::clone(hybrid_auxiliary.as_ref().expect("prepared key P")),
                            qs.len(),
                        )
                        .map_err(BfvEvaluationKeyError::from)?;
                        BfvEvaluationKeyConfig::Hybrid(Arc::new(prepared))
                    }
                };
                key_configs[working_level] = Some(config);
            }
            let key_config = key_configs[working_level]
                .as_ref()
                .expect("selected key configuration prepared");
            steps.push(BfvLeveledStep {
                context,
                working_level,
                backend,
                auxiliary_moduli: c.auxiliary.clone(),
                input_error: words(&error),
                key_config: key_config.clone(),
                key_auxiliary_moduli: key_p.clone(),
                ledger: c.ledger(&bounds, &capacity),
            });
            error = bounds.output_error;
        }
        Ok(Self {
            fresh_ledger,
            steps,
            secret_l1_bound,
            ephemeral_l1_bound,
            error_support_bound: eta,
            decoder_capacity: words(&capacity),
            security_inputs,
        })
    }
    /// Deterministic fresh public-key phase-error bound, little-endian u64 words.
    #[must_use]
    pub fn fresh_error_bound(&self) -> &[u64] {
        &self.fresh_ledger.total_error
    }
    /// Full public-encryption error decomposition; no secret/phase observation.
    #[must_use]
    pub const fn fresh_error_ledger(&self) -> &BfvLeveledFreshErrorLedger {
        &self.fresh_ledger
    }
    /// Honest sampled secret's public L1 bound, without inspecting its values.
    #[must_use]
    pub const fn secret_l1_bound(&self) -> u64 {
        self.secret_l1_bound
    }
    /// Public CBD1 ephemeral L1 bound, independent of the long-term secret law.
    #[must_use]
    pub const fn ephemeral_l1_bound(&self) -> u64 {
        self.ephemeral_l1_bound
    }
    /// Actual error sampler's hard coefficient support, including truncation.
    #[must_use]
    pub const fn error_support_bound(&self) -> u64 {
        self.error_support_bound
    }
    /// Destination codec's strict maximum integer error, in little-endian words.
    #[must_use]
    pub fn decoder_capacity(&self) -> &[u64] {
        &self.decoder_capacity
    }
    /// Independent RLWE analysis inputs for the data domain and selected key domains.
    ///
    /// No hardness estimate is inferred from correctness admission. Computation
    /// P is deliberately absent; Hybrid key P is included at its actual level.
    #[must_use]
    pub fn security_inputs(&self) -> &[RlweSecurityInput] {
        &self.security_inputs
    }
    /// Complete ordered multiplication-layer schedule.
    #[must_use]
    pub fn steps(&self) -> &[BfvLeveledStep<'a>] {
        &self.steps
    }
}
