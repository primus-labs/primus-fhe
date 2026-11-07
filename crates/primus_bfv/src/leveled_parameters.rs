//! Ordinary binary-multiplication families with public deterministic error admission.
use dashu_int::{UBig, ops::BitTest};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_glwe_rns::rlwe_parameters::{
    RlweParameterError, RlweSecurityInput, search_ntt_primes, security_input, validate_ntt_primes,
};
use primus_modulus::{BarrettModulus, is_prime_u64 as is_prime};
use primus_shape::PolyLength;

use crate::evaluation::{BfvLeveledMultiplication, BfvMultiplyError};
use crate::keys::{BfvEvaluationKeyConfig, BfvEvaluationKeyError, BfvRelinearizationKey};
use crate::parameters::DEFAULT_DECODER_MODULUS;
use crate::{BfvClient, BfvContext, BfvParameters};

const KEY_P: [u64; 1] = [1152921504606584833];

/// Numerical context request for the ordinary working-basis multiplication family.
///
/// The returned context is a candidate, not an admitted depth or a security
/// certificate. Pass it to [`BfvLeveledParameters::try_new`] for full admission.
/// The message bound covers every canonical coefficient in the plaintext ring;
/// a slot-value bound alone is not a coefficient bound.
#[derive(Clone, Copy, Debug)]
pub struct BfvLeveledRequest {
    /// Full power-of-two polynomial length.
    pub poly_length: PolyLength,
    /// Plaintext coefficient modulus, strictly between one and the default gamma.
    pub plaintext_modulus: u64,
    /// Also require a prime plaintext modulus supporting all N batching slots.
    pub require_batching: bool,
    /// Bit width of every generated data-Q prime, in 2..=62.
    /// The codec, plaintext and chosen radix can impose stricter conditions.
    pub ciphertext_prime_bits: u32,
    /// Number of generated Q primes and prepared prefix levels, at least two.
    pub ciphertext_prime_count: usize,
    /// Honest ordinary secret-key sampling law; the public ephemeral remains CBD1.
    pub secret_distribution: SecretKeyDistr,
    /// Actual error sampling law, including a Gaussian sampler's hard cutoff.
    pub error_distribution: ErrorDistribution,
}

impl BfvLeveledRequest {
    /// Generates distinct, certified NTT primes and prepares one numerical context.
    ///
    /// # Errors
    /// Rejects unsupported plaintext conditions, finite-search exhaustion or
    /// ordinary parameter/context errors. It does not attempt depth admission.
    pub fn create_context(self) -> Result<BfvContext, BfvLeveledParameterError> {
        let n = self.poly_length.get();
        if self.plaintext_modulus <= 1 || self.plaintext_modulus >= DEFAULT_DECODER_MODULUS {
            return Err(unsupported("plaintext modulus must satisfy 1 < t < gamma"));
        }
        if self.ciphertext_prime_count < 2 {
            return Err(unsupported(
                "working-basis admission needs at least two data primes",
            ));
        }
        if self.require_batching
            && (!is_prime(self.plaintext_modulus)
                || n.checked_mul(2)
                    .is_none_or(|step| !(self.plaintext_modulus - 1).is_multiple_of(step as u64)))
        {
            return Err(unsupported(
                "full batching requires prime t congruent to 1 modulo 2N",
            ));
        }
        let q = search_ntt_primes(
            n,
            self.ciphertext_prime_bits,
            self.ciphertext_prime_count,
            None,
            &[self.plaintext_modulus, DEFAULT_DECODER_MODULUS],
        )?;
        let moduli = q.into_iter().map(BarrettModulus::new).collect::<Vec<_>>();
        let parameters = BfvParameters::try_coefficients(
            self.poly_length,
            BarrettModulus::new(self.plaintext_modulus),
            &moduli,
            self.secret_distribution,
            self.error_distribution,
        )
        .map_err(|e| BfvLeveledParameterError::Context(e.to_string()))?;
        BfvContext::try_with_levels(parameters, self.ciphertext_prime_count)
            .map_err(|e| BfvLeveledParameterError::Context(e.to_string()))
    }
}

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
    /// A numerical context constructor rejected its parameters.
    #[error("BFV leveled context: {0}")]
    Context(String),
    /// Ordinary key generation or metadata rejected the configuration.
    #[error(transparent)]
    EvaluationKey(#[from] BfvEvaluationKeyError),
    /// The prepared multiplication rejected its arithmetic resources.
    #[error(transparent)]
    Multiplication(#[from] BfvMultiplyError),
}

fn unsupported(reason: &'static str) -> BfvLeveledParameterError {
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
    output_error: Vec<u64>,
    key_error: Vec<u64>,
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
        &self.output_error
    }
    /// Working-level ordinary relinearization error, before multiplication by Q/Q_l.
    #[must_use]
    pub fn key_error_bound(&self) -> &[u64] {
        &self.key_error
    }
    /// Clones the prepared actual key configuration, sharing Hybrid tables by Arc.
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
/// search or a certificate for collective/raw/mixed SSLE arithmetic. Actual
/// working-level Hybrid tables are prepared once per selected level and shared
/// by the steps; data-Q tables remain with the borrowed context.
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
        validate_ntt_primes(n, qs)?;
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
        let sampling = parameters.encryption_parameters();
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
        let q = product(qs);
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
            .map(|keep| Candidate::new(context, keep, backend, secret_l1_bound, eta, &key_p))
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
        let mut data_security = security_input(sampling, qs, &[])?;
        data_security.ephemeral_distribution = Some(SecretKeyDistr::SparseTernary);
        let mut security_inputs = vec![data_security];
        for index in 0..depth {
            let limit = &limits[depth - index - 1];
            let c = candidates
                .iter()
                .find(|c| c.output(&error) <= *limit)
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
            let next = c.output(&error);
            let working_level = qs.len() - c.keep;
            if key_configs[working_level].is_none() {
                let config = match backend {
                    BfvLeveledKeyBackend::Radix16 => DecompositionConfig {
                        log_basis: DecompositionBaseLog::new(16),
                        level_count: None,
                    }
                    .into(),
                    BfvLeveledKeyBackend::HybridAlpha1 => {
                        let mut key_security = security_input(sampling, &qs[..c.keep], &key_p)?;
                        key_security.ephemeral_distribution = Some(SecretKeyDistr::SparseTernary);
                        security_inputs.push(key_security);
                        BfvEvaluationKeyConfig::Hybrid(context.hybrid_key_parameters(
                            working_level,
                            qs.len(),
                            &key_p,
                        )?)
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
                output_error: words(&next),
                key_error: words(&c.key_error),
                key_config: key_config.clone(),
                key_auxiliary_moduli: key_p.clone(),
                ledger: c.ledger(&error, &capacity),
            });
            error = next;
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

fn product(q: &[u64]) -> UBig {
    q.iter().fold(UBig::ONE, |x, &q| x * q)
}
fn ceil(a: UBig, b: UBig) -> UBig {
    (&a + &b - 1u8) / b
}
fn words(v: &UBig) -> Vec<u64> {
    let mut x = v.clone();
    let mask = UBig::from(u64::MAX);
    let mut out = Vec::new();
    while x != UBig::ZERO {
        out.push(u64::try_from(&x & &mask).expect("masked word"));
        x >>= 64;
    }
    if out.is_empty() {
        out.push(0);
    }
    out
}

struct Candidate {
    n: usize,
    t: u64,
    h: u64,
    keep: usize,
    q: UBig,
    p: UBig,
    d: UBig,
    r: u64,
    key_sampling: UBig,
    key_residual: UBig,
    key_error: UBig,
    auxiliary: Vec<u64>,
}
impl Candidate {
    fn new(
        context: &BfvContext,
        keep: usize,
        backend: BfvLeveledKeyBackend,
        h: u64,
        eta: u64,
        key_p: &[u64],
    ) -> Result<Self, BfvLeveledParameterError> {
        let parameters = context.parameters();
        let n = parameters.poly_length().get();
        let t = parameters.codec().t();
        let qs = parameters.base_q().moduli_values();
        let q = product(&qs[..keep]);
        let full = product(qs);
        let lower =
            (UBig::from(4u8) * t * t * n * keep * UBig::from(h + 1) * (h + 1)).max(q.clone());
        let primes = search_ntt_primes(n, 60, lower.bit_len().div_ceil(59), None, qs)?;
        let mut auxiliary = Vec::new();
        let mut p = UBig::ONE;
        for prime in primes {
            if p >= lower {
                break;
            }
            auxiliary.push(prime);
            p *= prime;
        }
        let (key_sampling, key_residual, key_error) = match backend {
            BfvLeveledKeyBackend::Radix16 => {
                let digits = q.bit_len() / 16;
                let rem = q.bit_len() % 16;
                let sampling = UBig::from(n) * digits * (1u64 << 15) * eta;
                let residual = if rem == 0 {
                    UBig::ZERO
                } else {
                    UBig::from(h) * h * (1u64 << (rem - 1))
                };
                let total = &sampling + &residual;
                (sampling, residual, total)
            }
            BfvLeveledKeyBackend::HybridAlpha1 => {
                let p = product(key_p);
                let numerator = UBig::from(n)
                    * eta
                    * qs[..keep].iter().fold(UBig::ZERO, |sum, &x| sum + x - 1u8);
                let sampling = ceil(numerator.clone(), p.clone());
                let residual = ceil(UBig::from(h + 1), UBig::from(2u8));
                let total = ceil(numerator * 2u8 + UBig::from(h + 1) * &p, p * 2u8);
                (sampling, residual, total)
            }
        };
        Ok(Self {
            n,
            t,
            h,
            keep,
            d: &full / &q,
            r: &full % t,
            q,
            p,
            key_sampling,
            key_residual,
            key_error,
            auxiliary,
        })
    }
    fn terms(&self, e: &UBig) -> (UBig, UBig, UBig, UBig, UBig, UBig, UBig, UBig) {
        // Rational q/t phases retain their integer quotients and HPS wrap.
        // Every displayed ceil is part of the public deterministic model.
        let h = self.h;
        let m = self.t / 2;
        let h1 = h + 1;
        let u = ceil(
            (e * self.t + UBig::from(self.r) * m) * 2u8 + &self.d * self.t * h1,
            &self.d * self.t * 2u8,
        );
        let v = ceil(&self.p * &u, self.q.clone()) + UBig::from(self.keep) * h1;
        let za = ceil(
            (UBig::from(h1) * self.t + UBig::from(2u8) * m) * &self.q + &u * self.t * 2u8,
            &self.q * self.t * 2u8,
        );
        let zb = ceil(
            (UBig::from(h1) * self.t + UBig::from(2u8) * m) * &self.p + &v * self.t * 2u8,
            &self.p * self.t * 2u8,
        );
        let product = ceil(
            (&self.q * (UBig::from(m) + &za * self.t) * &v
                + &self.p * &u * (UBig::from(m) + &zb * self.t)
                + UBig::from(self.t) * &u * &v)
                * self.n,
            self.p.clone(),
        );
        let rounding = ceil(UBig::ONE + h + UBig::from(h) * h, UBig::from(2u8));
        let restored = &self.d * (&product + &rounding + &self.key_error);
        let drift = ceil(UBig::from(self.r) * m, UBig::from(self.t));
        (u, v, za, zb, product, rounding, restored, drift)
    }
    fn output(&self, e: &UBig) -> UBig {
        let (_, _, _, _, _, _, restored, drift) = self.terms(e);
        restored + drift
    }
    fn ledger(&self, e: &UBig, capacity: &UBig) -> BfvLeveledErrorLedger {
        let (u, v, za, zb, product, rounding, restored, drift) = self.terms(e);
        let output = &restored + &drift;
        BfvLeveledErrorLedger {
            working_modulus: words(&self.q),
            restoration_multiplier: words(&self.d),
            computation_auxiliary_product: words(&self.p),
            reduced_input_error: words(&u),
            converted_right_error: words(&v),
            left_phase_quotient: words(&za),
            right_phase_quotient: words(&zb),
            product_error: words(&product),
            component_rounding_error: words(&rounding),
            key_sampling_error: words(&self.key_sampling),
            key_residual_or_moddown_error: words(&self.key_residual),
            key_error: words(&self.key_error),
            restored_error: words(&restored),
            restoration_drift: words(&drift),
            output_error: words(&output),
            decoder_capacity: words(capacity),
            remaining_error_capacity: words(&(capacity - output)),
        }
    }
}
