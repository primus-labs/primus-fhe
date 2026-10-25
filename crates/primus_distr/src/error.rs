use thiserror::Error;

/// Invalid secret-key sampling configuration, logical key length or output modulus.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum SecretKeySamplerError {
    /// Binary/ternary probabilities are non-finite, out of range or sum above one.
    #[error("secret-key probabilities must be finite, in [0, 1], and sum to at most one")]
    InvalidProbabilities,
    /// Gaussian preparation failed for the selected signed coefficient type.
    #[error("invalid secret-key Gaussian distribution")]
    Gaussian(#[from] GaussianError),
    /// Fixed weights overflow or exceed the logical key length.
    #[error("secret-key fixed weight must fit the logical key length {length}")]
    InvalidWeight {
        /// Complete logical key length, not a polynomial or batch stride.
        length: usize,
    },
    /// The selected modulus cannot encode every supported secret magnitude.
    #[error(
        "secret-key maximum magnitude {maximum_magnitude} must not exceed modulus minus one {modulus_minus_one}"
    )]
    ModulusTooSmall {
        /// Inclusive bound on magnitudes produced by this sampler.
        maximum_magnitude: u128,
        /// Output modulus minus one; the coefficient maximum denotes Native.
        modulus_minus_one: u128,
    },
}

/// Invalid discrete Gaussian parameters, backend capacity or output representation.
/// Shared by signed and modular samplers and their CDT/Ziggurat implementations.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum GaussianError {
    /// The standard deviation is unsupported by the floating-point kernels.
    #[error(
        "standard deviation must be at least {minimum} with finite variance, got {value}",
        minimum = crate::MIN_STANDARD_DEVIATION
    )]
    InvalidStandardDeviation {
        /// Invalid standard deviation.
        value: f64,
    },

    /// The tail cut is non-finite or not positive.
    #[error("tail cut must be finite and positive, got {value}")]
    InvalidTailCut {
        /// Invalid tail cut.
        value: f64,
    },

    /// The truncated support cannot be represented as a `u64` magnitude.
    #[error(
        "Gaussian support is too large for standard deviation {standard_deviation} and tail cut {tail_cut}"
    )]
    MaximumMagnitudeTooLarge {
        /// Requested standard deviation.
        standard_deviation: f64,
        /// Requested tail cut.
        tail_cut: f64,
    },

    /// The requested support exceeds a CDT backend's table limit.
    #[error(
        "maximum magnitude {maximum_magnitude} exceeds the CDT backend limit {supported_maximum}"
    )]
    CdtTableTooLarge {
        /// Requested maximum magnitude.
        maximum_magnitude: u64,
        /// Largest magnitude supported by the backend.
        supported_maximum: u64,
    },

    /// The modular output cannot encode every supported magnitude.
    #[error(
        "maximum magnitude {maximum_magnitude} must not exceed modulus minus one {modulus_minus_one}"
    )]
    ModulusTooSmall {
        /// Requested maximum magnitude.
        maximum_magnitude: u64,
        /// Supplied modulus minus one.
        modulus_minus_one: u128,
    },

    /// The signed output type cannot represent every supported magnitude.
    #[error("maximum magnitude {maximum_magnitude} exceeds output type maximum {output_maximum}")]
    OutputTypeTooNarrow {
        /// Requested maximum magnitude.
        maximum_magnitude: u64,
        /// Largest positive value of the output type.
        output_maximum: u128,
    },

    /// Ziggurat setup could not represent the requested distribution.
    #[error(
        "cannot construct Ziggurat for standard deviation {standard_deviation} and tail cut {tail_cut}"
    )]
    ZigguratConstructionFailed {
        /// Requested standard deviation.
        standard_deviation: f64,
        /// Requested tail cut.
        tail_cut: f64,
    },
}
