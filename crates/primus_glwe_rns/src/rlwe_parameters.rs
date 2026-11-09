//! Cold prime preparation and explicit inputs for an external RLWE review.
//!
//! These helpers prepare ordinary rank-one negacyclic parameters. Arithmetic
//! admissibility and correctness budgets do not establish RLWE hardness. In
//! particular, no estimate or 128-bit security verdict is produced here.

use primus_distr::{ErrorDistribution, SecretKeyDistr};
use primus_integer::multiply_many_values;
use primus_modulus::is_prime_u64;
use primus_ntt::{U64_NTT_MAX_MODULUS_BITS, U64NttPrimeBasisError, validate_u64_ntt_primes};
use primus_shape::PolyLength;

use crate::CrtGlweEncryptionParameters;

/// Invalid prime preparation or an unrepresentable diagnostic input.
#[derive(Debug, thiserror::Error)]
pub enum RlweParameterError {
    /// The polynomial length is outside the shared FHE shape range.
    #[error(transparent)]
    PolyLength(#[from] primus_shape::PolyLengthError),
    /// A ciphertext or combined key basis must contain at least one prime.
    #[error("an RLWE basis must be nonempty")]
    EmptyBasis,
    /// This inventory describes a rank-one ring secret, rather than general GLWE.
    #[error("ordinary RLWE security input requires rank one, got {dimension}")]
    Rank {
        /// Number of mask polynomials in the supplied sampling parameters.
        dimension: usize,
    },
    /// Lazy u64 NTT kernels require every modulus to be below 2^62.
    #[error("RLWE modulus {modulus} must be below 2^62")]
    ModulusTooLarge {
        /// Rejected modulus.
        modulus: u64,
    },
    /// An externally supplied modulus is composite or less than two.
    #[error("RLWE modulus {modulus} is not prime")]
    NotPrime {
        /// Rejected modulus.
        modulus: u64,
    },
    /// Each prime can occur only once in the combined Q/key-P basis.
    #[error("RLWE modulus {modulus} occurs more than once")]
    DuplicatePrime {
        /// Repeated modulus.
        modulus: u64,
    },
    /// A prime does not support the ring's negacyclic transform.
    #[error("RLWE modulus {modulus} is not congruent to 1 modulo {order}")]
    NttOrder {
        /// Rejected modulus.
        modulus: u64,
        /// Required root order, 2N.
        order: u64,
    },
    /// Search requests must fit the supported bit range and progression.
    #[error(
        "NTT prime search requires bits in 2..=62, positive count and a representable positive congruence modulus"
    )]
    SearchRequest,
    /// The fixed candidate budget or the requested bit interval was exhausted.
    #[error("bounded NTT prime search found {found} of {requested} requested primes")]
    SearchExhausted {
        /// Number of primes found before the search stopped.
        found: usize,
        /// Requested number of primes.
        requested: usize,
    },
    /// The existing arbitrary-precision bit-width representation was exceeded.
    #[error("RLWE modulus product bit width is not representable")]
    ProductWidth,
    /// The prepared secret sampler's support does not fit the reported basis.
    #[error(transparent)]
    SecretSampler(#[from] primus_distr::SecretKeySamplerError),
    /// The prepared error sampler's support does not fit the reported basis.
    #[error(transparent)]
    ErrorSampler(#[from] primus_distr::ErrorSamplerError),
}

/// Validates a nonempty ordered basis for the existing u64 negacyclic kernels.
///
/// Every value must be a distinct prime below `2^62` with `2N | q - 1`.
/// This checks primality rather than relying on successful root search.
/// Pass the combined Q and key-P values when checking their disjointness.
/// Plaintext conditions and security/correctness budgets belong to the scheme.
pub fn validate_ntt_primes(n: usize, primes: &[u64]) -> Result<(), RlweParameterError> {
    use U64NttPrimeBasisError as Error;

    validate_u64_ntt_primes(PolyLength::try_new(n)?, primes).map_err(|error| match error {
        Error::EmptyBasis => RlweParameterError::EmptyBasis,
        Error::ModulusTooLarge { modulus } => RlweParameterError::ModulusTooLarge { modulus },
        Error::DuplicatePrime { modulus } => RlweParameterError::DuplicatePrime { modulus },
        Error::NotPrime { modulus } => RlweParameterError::NotPrime { modulus },
        Error::NttOrder { modulus, order } => RlweParameterError::NttOrder { modulus, order },
    })
}

/// Searches downward for distinct NTT primes of exactly `bits` bits.
///
/// `one_modulo=Some(t)` additionally requires `q ≡ 1 (mod t)`; no primality
/// condition on t is implied. Values in `exclude` are skipped. At most one
/// million progression candidates are tested in total, so exhaustion is an
/// explicit error rather than an unbounded setup search. The result is only
/// numerical preparation; choosing its count/width is a separate budget task.
pub fn search_ntt_primes(
    n: usize,
    bits: u32,
    count: usize,
    one_modulo: Option<u64>,
    exclude: &[u64],
) -> Result<Vec<u64>, RlweParameterError> {
    const MAX_CANDIDATES: usize = 1_000_000;
    let order = root_order(n)?;
    if !(2..=U64_NTT_MAX_MODULUS_BITS).contains(&bits) || count == 0 {
        return Err(RlweParameterError::SearchRequest);
    }
    let congruence = one_modulo.unwrap_or(1);
    if congruence == 0 {
        return Err(RlweParameterError::SearchRequest);
    }
    let mut a = order;
    let mut b = congruence;
    while b != 0 {
        (a, b) = (b, a % b);
    }
    let step = (order / a)
        .checked_mul(congruence)
        .ok_or(RlweParameterError::SearchRequest)?;
    if count > MAX_CANDIDATES {
        return Err(RlweParameterError::SearchExhausted {
            found: 0,
            requested: count,
        });
    }
    let lower = 1u64 << (bits - 1);
    let upper = (1u64 << bits) - 1;
    let mut candidate = upper - (upper - 1) % step;
    let mut primes = Vec::with_capacity(count);
    for _ in 0..MAX_CANDIDATES {
        if candidate < lower {
            break;
        }
        if !exclude.contains(&candidate) && is_prime_u64(candidate) {
            primes.push(candidate);
            if primes.len() == count {
                return Ok(primes);
            }
        }
        let Some(next) = candidate.checked_sub(step) else {
            break;
        };
        candidate = next;
    }
    Err(RlweParameterError::SearchExhausted {
        found: primes.len(),
        requested: count,
    })
}

/// The library has not evaluated the computational hardness of these inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RlweSecurityStatus {
    /// No attack estimator or reviewed standard table has been applied.
    NotEvaluated,
}

/// Public diagnostic data for one actual exposed rank-one RLWE modulus domain.
///
/// This is an input inventory, not an authorization object or a certificate.
/// Different key domains must be recorded separately, including earlier high-Q
/// public material retained after ciphertext drops. Ring rows are correlated;
/// this structure supplies no independent-LWE sample count or KDM reduction.
#[derive(Clone, Debug, PartialEq)]
pub struct RlweSecurityInput {
    /// Degree N of the actual negacyclic ring and full secret.
    pub poly_length: usize,
    /// Ordered active ciphertext Q primes for this material.
    pub data_moduli: Vec<u64>,
    /// Ordered auxiliary primes actually used by a secret-bearing Hybrid key.
    /// Computation-only BFV tensor/HPS primes must not be included.
    pub key_auxiliary_moduli: Vec<u64>,
    /// Exact Q or QP product, in little-endian u64 words.
    pub modulus_words: Vec<u64>,
    /// Exact bit length of `modulus_words`, not a sum of prime bit lengths.
    pub modulus_bits: usize,
    /// Actual secret sampler law, without a Gaussian/ternary substitution.
    pub secret_distribution: SecretKeyDistr,
    /// Actual integer key-row error law before scheme scaling.
    /// BGV's p factor is normalized by its invertible scalar in the bare row;
    /// this does not resolve secret-dependent evaluation-key messages.
    pub error_distribution: ErrorDistribution,
    /// Inclusive magnitude support of the prepared secret coefficient sampler.
    pub secret_maximum_magnitude: u64,
    /// Inclusive magnitude support of the prepared integer error sampler.
    pub error_maximum_magnitude: u64,
    /// Actual public-encryption ephemeral law, if supplied by the scheme plan.
    /// It is a distinct role from the key-row target secret above.
    pub ephemeral_distribution: Option<SecretKeyDistr>,
    /// Explicitly remains unevaluated until an external review is performed.
    pub status: RlweSecurityStatus,
}

/// Prepares the exact domain and sampler inventory for an external review.
///
/// Reads the actual rank-one layout and already-prepared samplers without
/// rebuilding sampling tables. The reported basis can differ from the original
/// sampling basis; this diagnostic validates its prime/NTT and sampler-support
/// conditions, but does not establish a context/key identity binding.
///
/// An empty `key_p` denotes data-Q material. A nonempty `key_p` denotes an
/// actual QP key domain and must be disjoint from Q. Each actual working-basis
/// key uses its own active Q prefix. Do not multiply unrelated domain products
/// together and claim they were a single observed RLWE modulus.
///
/// No security estimate is performed. Unsupported structured, joint-material,
/// circular/KDM and sample-count assumptions remain for the external reviewer.
pub fn security_input(
    sampling: &CrtGlweEncryptionParameters<u64>,
    data_q: &[u64],
    key_p: &[u64],
) -> Result<RlweSecurityInput, RlweParameterError> {
    let size = sampling.size();
    if size.dimension().get() != 1 {
        return Err(RlweParameterError::Rank {
            dimension: size.dimension().get(),
        });
    }
    let n = size.poly_length().get();
    if data_q.is_empty() {
        return Err(RlweParameterError::EmptyBasis);
    }
    let moduli = data_q.iter().chain(key_p).copied().collect::<Vec<_>>();
    validate_ntt_primes(n, &moduli)?;
    let secret_sampler = sampling.secret_key_sampler();
    let error_sampler = sampling.noise_distribution();
    let minimum = *moduli.iter().min().expect("validated nonempty basis");
    secret_sampler.validate_modulus(minimum - 1)?;
    error_sampler.validate_modulus(minimum - 1)?;
    let product = multiply_many_values(&moduli);
    let modulus_bits = product
        .checked_bit_width()
        .ok_or(RlweParameterError::ProductWidth)? as usize;
    Ok(RlweSecurityInput {
        poly_length: n,
        data_moduli: data_q.to_vec(),
        key_auxiliary_moduli: key_p.to_vec(),
        modulus_words: product.0,
        modulus_bits,
        secret_distribution: sampling.secret_key_distr(),
        error_distribution: error_sampler.distribution(),
        secret_maximum_magnitude: secret_sampler.maximum_magnitude(),
        error_maximum_magnitude: error_sampler.maximum_magnitude(),
        ephemeral_distribution: None,
        status: RlweSecurityStatus::NotEvaluated,
    })
}

fn root_order(n: usize) -> Result<u64, RlweParameterError> {
    // PolyLength's range guarantees that 2N fits both usize and u64.
    let length = PolyLength::try_new(n)?;
    Ok(2 * length.get() as u64)
}
