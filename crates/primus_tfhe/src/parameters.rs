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
/// Classic accepts binary and ternary secrets, including fixed-weight binary.
/// Block requires a block-binary distribution. Key generation checks block
/// geometry before allocating control rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindRotationMethod {
    /// Per-coordinate binary or ternary CMux controls, including fixed-weight distributions.
    Classic,
    /// Contiguous equal-sized blocks with at most one `1` per block.
    /// The block width is owned by the input secret distribution; all-zero
    /// blocks are valid. Backend key generation must support this method.
    Block,
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
