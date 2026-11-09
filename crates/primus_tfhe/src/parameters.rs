//! Independent choices for evaluation keys and bootstrapping.

use primus_decompose::DecompositionConfig;

/// Gadget decomposition and row-encryption noise for one evaluation-key role.
///
/// By default, `D` is [`DecompositionConfig`], resolved at parameter construction.
/// Constructors that accept a prepared basis use it as `D` and take ownership
/// without rebuilding it.
/// The consuming constructor supplies the key's layout and modulus and validates
/// the choices; this configuration alone does not establish a noise/security budget.
#[derive(Debug, Clone, Copy)]
pub struct GadgetEncryptionConfig<D = DecompositionConfig> {
    /// Decomposition choices or an already prepared basis, as required by the constructor.
    pub decomposition: D,
    /// Encryption noise standard deviation in coefficient units at the key's modulus.
    /// The consuming parameters specify whether ordinary encryption shares this noise.
    pub noise_standard_deviation: f64,
}

/// Blind-rotation algorithm used for fresh paired keys or an existing client.
///
/// This choice does not change the secret distribution in TFHE parameters. A fixed-weight
/// binary secret can use either algorithm; selecting sparse with an unsupported distribution
/// is an error, never a request to resample the secret or fall back to classic.
/// Backend key generation validates bucket geometry against the actual secret and ciphertext
/// layout. This algorithm choice carries no encryption parameters, keys, return policy,
/// CBS material or runtime scratch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindRotationMethod {
    /// Per-coordinate binary or ternary CMux controls, including fixed-weight distributions.
    Classic,
    /// Bucketed controls for a fixed-weight binary secret with weight `0 < h < n`.
    /// Matching retries the public map while keeping the client secret fixed.
    Sparse {
        /// Number of distinct buckets containing each input index; must be at least one.
        copy_count: usize,
        /// Number of buckets; must be at least `max(copy_count, h)`.
        bucket_count: usize,
    },
}

/// Independent decompositions for circuit-bootstrap output, trace and scheme switching.
///
/// Trace and scheme-switch rows use the TFHE accumulator's ring layout, modulus,
/// secret distribution and fresh encryption noise. Their immutable sampler state
/// is shared with blind rotation; bases and random draws remain independent.
/// The consuming parameters still require a CBS noise/security analysis.
#[derive(Debug, Clone, Copy)]
pub struct CbsGadgetConfig {
    /// Reverse-trace key decomposition at the accumulator modulus.
    pub trace: DecompositionConfig,
    /// Scheme-switch key decomposition at the accumulator modulus.
    pub scheme_switch: DecompositionConfig,
    /// Gadget scalars encoded by the output GGSW/NGSW.
    /// This selects the output encoding, not a separate key's encryption noise.
    pub output: DecompositionConfig,
}
