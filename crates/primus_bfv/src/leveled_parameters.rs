//! Finite ordinary-BFV profiles with deterministic, depth-aware working-basis admission.
use dashu_int::{UBig, ops::BitTest};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;

use crate::multiply::is_prime;
use crate::{
    BfvClient, BfvContext, BfvEvaluationKeyConfig, BfvEvaluationKeyError, BfvLeveledMultiplication,
    BfvMultiplyError, BfvParameters, BfvRelinearizationKey,
};

const Q: [u64; 6] = [
    1152921422732787713,
    1152921409847689217,
    1152921396962590721,
    1152921311061934081,
    1152920937394077697,
    1152920907328847873,
];
const KEY_P: [u64; 1] = [1152921504606584833];
const ETA: u64 = 21;
const GAMMA: u64 = (1 << 61) - 1;

/// Finite numerical geometry; choosing it does not establish RLWE hardness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BfvLeveledProfile {
    /// N=16384 and the prescribed four 60-bit data primes.
    N16384Q240,
    /// N=32768 and the prescribed six 60-bit data primes.
    N32768Q360,
}
impl BfvLeveledProfile {
    fn geometry(self) -> (usize, &'static [u64]) {
        match self {
            Self::N16384Q240 => (16384, &Q[..4]),
            Self::N32768Q360 => (32768, &Q),
        }
    }
    /// Builds all prefix levels with CBD1 secrets/ephemerals and CBD21 errors.
    ///
    /// Only plaintext moduli257 and65537 are included in this arithmetic family.
    /// Tables are owned by the returned context, never by the parameter plan.
    pub fn create_context(self, plaintext: u64) -> Result<BfvContext, BfvLeveledParameterError> {
        if ![257, 65537].contains(&plaintext) {
            return Err(BfvLeveledParameterError::Model);
        }
        let (n, q) = self.geometry();
        let moduli = q
            .iter()
            .copied()
            .map(BarrettModulus::new)
            .collect::<Vec<_>>();
        let parameters = BfvParameters::try_with_error_distribution(
            PolyLength::new(n),
            BarrettModulus::new(plaintext),
            BarrettModulus::new(GAMMA),
            &moduli,
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 21 },
        )
        .map_err(|e| BfvLeveledParameterError::Context(e.to_string()))?;
        BfvContext::try_with_levels(parameters, q.len())
            .map_err(|e| BfvLeveledParameterError::Context(e.to_string()))
    }
}

/// Actual ordinary evaluation-key configuration covered by the finite budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BfvLeveledKeyBackend {
    /// Full signed radix16; its low-bit residual is included in every budget.
    Radix16,
    /// One Q prime per partition, with the prescribed independent key P basis.
    HybridAlpha1,
}

/// An unsupported model, exhausted circuit margin or incompatible ordinary key.
#[derive(Debug, thiserror::Error)]
pub enum BfvLeveledParameterError {
    /// Numerical geometry, distribution, gamma or level inventory is outside the finite family.
    #[error("context is outside the reviewed ordinary BFV leveled arithmetic family")]
    Model,
    /// The requested depth has no admitted schedule containing a real internal reduction.
    #[error("no complete internally reduced BFV schedule meets the requested depth budget")]
    Budget,
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

/// One admitted binary-multiplication layer, retaining external level zero.
///
/// Both operands must have phase error bounded by `input_error_bound`, use this
/// context's actual secret, and have canonical plaintext coefficient norm at
/// most t/2. No ciphertext storage check can infer its actual evaluated error.
/// Only ordinary keys from the stated CBD21 model are covered; a collective key
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
    /// not prove a key was honestly sampled as an ordinary CBD21 key.
    pub fn prepare<'s>(
        &'s self,
        key: &'s BfvRelinearizationKey,
    ) -> Result<BfvLeveledMultiplication<'s>, BfvLeveledParameterError> {
        if key.level() != self.working_level || !key.matches_leveled_backend(self.backend, &KEY_P) {
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

/// Checked finite-depth plan for ordinary BFV, using exact integer admission.
///
/// Covers binary circuits whose depth-d inputs obey depth-(d-1)'s error bound,
/// including square chains. Fresh public-key encryption is covered by the hard
/// CBD1/CBD21 bound21*(2N+1)+(Q mod t), including unsigned message lifts.
/// Every planned operation performs a real internal
/// reduction and restores external level zero; no OpenFHE empirical cushion or
/// lower bound on unknown noise is used. This is not an automatic security-level
/// search or a certificate for collective/raw/mixed SSLE arithmetic. Actual
/// working-level Hybrid tables are prepared once per selected level and shared
/// by the steps; data-Q tables remain with the borrowed context.
pub struct BfvLeveledParameters<'a> {
    profile: BfvLeveledProfile,
    fresh_error: Vec<u64>,
    steps: Vec<BfvLeveledStep<'a>>,
}
impl<'a> BfvLeveledParameters<'a> {
    /// Admits a complete circuit of depth1..=8 on an exact finite-profile context.
    ///
    /// Backward monotone integer admission reserves enough margin for all
    /// remaining layers; forward selection chooses the smallest feasible
    /// working basis at each layer. Failure never silently substitutes a
    /// no-reduction backend or promises that arbitrary evaluated inputs fit.
    pub fn try_new(
        context: &'a BfvContext,
        depth: usize,
        backend: BfvLeveledKeyBackend,
    ) -> Result<Self, BfvLeveledParameterError> {
        if !(1..=8).contains(&depth) {
            return Err(BfvLeveledParameterError::Budget);
        }
        let parameters = context.parameters();
        let n = parameters.poly_length().get();
        let qs = parameters.base_q().moduli_values();
        let profile = match n {
            16384 if qs == &Q[..4] => BfvLeveledProfile::N16384Q240,
            32768 if qs == Q => BfvLeveledProfile::N32768Q360,
            _ => return Err(BfvLeveledParameterError::Model),
        };
        if ![257, 65537].contains(&parameters.codec().t())
            || parameters.codec().gamma() != GAMMA
            || context.level_count() != qs.len()
            || parameters.encryption_parameters().secret_key_distr()
                != SecretKeyDistr::SparseTernary
            || parameters
                .encryption_parameters()
                .noise_distribution()
                .distribution()
                != (ErrorDistribution::CenteredBinomial { eta: 21 })
        {
            return Err(BfvLeveledParameterError::Model);
        }
        let t = parameters.codec().t();
        let q = product(qs);
        let gamma = UBig::from(GAMMA);
        let r = &q % t;
        let capacity =
            (&q * &gamma - 1u8 - UBig::from(2 * r * (t / 2)) * &gamma - &q * (2 * qs.len()))
                / (UBig::from(2 * t) * &gamma);
        let candidates = (1..qs.len())
            .map(|keep| Candidate::new(n, t, qs, keep, backend))
            .collect::<Vec<_>>();
        let fresh = UBig::from(ETA * (2 * n as u64 + 1) + r);
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
            return Err(BfvLeveledParameterError::Budget);
        }
        let mut error = fresh.clone();
        let mut steps = Vec::with_capacity(depth);
        let mut key_configs = vec![None; qs.len()];
        for index in 0..depth {
            let limit = &limits[depth - index - 1];
            let c = candidates
                .iter()
                .find(|c| c.output(&error) <= *limit)
                .ok_or(BfvLeveledParameterError::Budget)?;
            let next = c.output(&error);
            let working_level = qs.len() - c.keep;
            if key_configs[working_level].is_none() {
                let config = match backend {
                    BfvLeveledKeyBackend::Radix16 => DecompositionConfig {
                        log_basis: DecompositionBaseLog::new(16),
                        level_count: None,
                    }
                    .into(),
                    BfvLeveledKeyBackend::HybridAlpha1 => BfvEvaluationKeyConfig::Hybrid(
                        context.hybrid_key_parameters(working_level, qs.len(), &KEY_P)?,
                    ),
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
            });
            error = next;
        }
        Ok(Self {
            profile,
            fresh_error: words(&fresh),
            steps,
        })
    }
    /// Numerical geometry selected by the actual checked context.
    #[must_use]
    pub const fn profile(&self) -> BfvLeveledProfile {
        self.profile
    }
    /// Deterministic fresh public-key phase-error bound, little-endian u64 words.
    #[must_use]
    pub fn fresh_error_bound(&self) -> &[u64] {
        &self.fresh_error
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
    keep: usize,
    q: UBig,
    p: UBig,
    d: UBig,
    r: u64,
    key_error: UBig,
    auxiliary: Vec<u64>,
}
impl Candidate {
    fn new(n: usize, t: u64, qs: &[u64], keep: usize, backend: BfvLeveledKeyBackend) -> Self {
        let q = product(&qs[..keep]);
        let full = product(qs);
        let h = n as u64;
        let lower = (UBig::from(4 * t * t) * n * keep * (h + 1) * (h + 1)).max(q.clone());
        let mut auxiliary = Vec::new();
        let mut p = UBig::ONE;
        let step = 2 * n as u64;
        let mut prime = ((1u64 << 60) - 2) / step * step + 1;
        while p < lower {
            if !qs.contains(&prime) && is_prime(prime) {
                auxiliary.push(prime);
                p *= prime;
            }
            prime -= step;
        }
        let key_error = match backend {
            BfvLeveledKeyBackend::Radix16 => {
                let digits = q.bit_len() / 16;
                let rem = q.bit_len() % 16;
                UBig::from(n) * digits * (1u64 << 15) * ETA
                    + if rem == 0 {
                        UBig::ZERO
                    } else {
                        UBig::from(h) * h * (1u64 << (rem - 1))
                    }
            }
            BfvLeveledKeyBackend::HybridAlpha1 => ceil(
                UBig::from(n)
                    * ETA
                    * qs[..keep].iter().fold(UBig::ZERO, |sum, &x| sum + x - 1u8)
                    * 2u8
                    + UBig::from(h + 1) * KEY_P[0],
                UBig::from(KEY_P[0]) * 2u8,
            ),
        };
        Self {
            n,
            t,
            keep,
            d: &full / &q,
            r: &full % t,
            q,
            p,
            key_error,
            auxiliary,
        }
    }
    fn output(&self, e: &UBig) -> UBig {
        // Track q/t plaintext scaling; integer phase quotients are bounded, not
        // discarded. Each ceiling is conservative and explicitly part of the ledger.
        let h = self.n as u64;
        let m = self.t / 2;
        let h1 = h + 1;
        let u = ceil(
            (e * self.t + UBig::from(self.r * m)) * 2u8 + &self.d * (self.t * h1),
            &self.d * (2 * self.t),
        );
        let v = ceil(&self.p * &u, self.q.clone()) + self.keep as u64 * h1;
        let za = ceil(
            UBig::from(h1) * self.t * &self.q + UBig::from(2 * m) * &self.q + &u * (2 * self.t),
            &self.q * (2 * self.t),
        );
        let zb = ceil(
            UBig::from(h1) * self.t * &self.p + UBig::from(2 * m) * &self.p + &v * (2 * self.t),
            &self.p * (2 * self.t),
        );
        let w = ceil(
            (&self.q * (UBig::from(m) + &za * self.t) * &v
                + &self.p * &u * (UBig::from(m) + &zb * self.t)
                + UBig::from(self.t) * &u * &v)
                * self.n,
            self.p.clone(),
        ) + ceil(UBig::from(1 + h + h * h), UBig::from(2u8));
        &self.d * (w + &self.key_error) + ceil(UBig::from(self.r * m), UBig::from(self.t))
    }
}
