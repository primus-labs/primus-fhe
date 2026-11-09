//! Errors owned by the GLWE TFHE parameter, client and key-generation boundaries.

use crate::PbsOrder;
use primus_decompose::ApproxSignedBasisError;
use primus_glwe::GlevParameterError;

/// An invalid combination of GLWE-based TFHE parameters.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum TfheParameterError {
    /// The accumulator modulus does not fit its reduction representation.
    #[error("invalid accumulator modulus")]
    RingModulus(#[source] primus_tfhe::ModulusConfigError),
    /// A CBS gadget or its selected numerical representation is invalid.
    #[error("invalid circuit-bootstrap parameters")]
    CircuitBootstrap(#[source] CircuitBootstrapParameterError),
    /// The CBS selector's input message encoding is invalid.
    #[error("invalid selector-input encoding")]
    InputEncoding(#[source] primus_encoding::CodecError),

    /// The numerical LWE description or its fresh encryption sampler is invalid.
    #[error("invalid input LWE configuration")]
    InputParameters(#[source] primus_tfhe::LweConfigError),
    /// The configured accumulator layout, encoding or samplers are invalid.
    #[error("invalid accumulator parameters")]
    AccumulatorParameters(#[source] primus_glwe::GlweParameterError),
    /// Classic blind rotation supports binary and ternary input LWE secrets.
    #[error("TFHE bootstrapping requires a binary or ternary input LWE secret key")]
    UnsupportedInputLweSecretKey,

    /// The rotation domain `2N` cannot be represented by the input coefficient type.
    #[error("rotation domain must fit the input coefficient type")]
    RotationDomainTooLarge,

    /// The accumulator layout cannot be represented.
    #[error("invalid TFHE accumulator layout")]
    AccumulatorLayout(#[source] primus_lattice::GlweSizeError),

    /// The bootstrapping basis or gadget layout is incompatible with the accumulator.
    #[error("invalid GLWE bootstrapping parameters")]
    BootstrappingParameters(#[source] GlevParameterError),

    /// The small LWE key does not fit in the main GLWE key capacity and
    /// therefore cannot be represented as a padded GLWE key with `k' <= k`.
    #[error(
        "small LWE dimension {small_lwe_dimension} exceeds GLWE secret-key capacity {capacity}"
    )]
    SmallLweDimensionExceedsGlweCapacity {
        /// Configured small LWE dimension.
        small_lwe_dimension: usize,
        /// Main GLWE secret-key capacity `kN`.
        capacity: usize,
    },

    /// The GLWE key-switching basis or output gadget layout is incompatible.
    #[error("invalid GLWE key-switching parameters")]
    KeySwitchingParameters(#[source] GlevParameterError),

    /// The ring key-switching encryption samplers are invalid.
    #[error("invalid GLWE key-switching encryption parameters")]
    KeySwitchingEncryption(#[source] primus_glwe::GlweParameterError),
}

/// An incompatibility between secret keys and TFHE parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheKeyError {
    /// The encoded LWE secret was generated or imported under another modulus.
    #[error("LWE secret-key ciphertext modulus mismatch")]
    LweSecretKeyModulusMismatch,
    /// The setup bundle or selected external secret uses a different PBS order.
    #[error("PBS order mismatch: expected {expected:?}, got {actual:?}")]
    PbsOrderMismatch {
        /// PBS order required by the parameters.
        expected: PbsOrder,
        /// PBS order associated with the setup bundle or external secret.
        actual: PbsOrder,
    },

    /// The LWE secret key has the wrong dimension.
    #[error("LWE secret-key dimension mismatch: expected {expected}, got {actual}")]
    LweDimensionMismatch {
        /// Dimension required by the parameters.
        expected: usize,
        /// Dimension found in the key.
        actual: usize,
    },

    /// The LWE secret-key distribution does not match the parameters.
    #[error("LWE secret-key distribution mismatch")]
    LweSecretKeyDistributionMismatch,

    /// A small-LWE coefficient lies outside the declared binary/ternary domain.
    #[error("small-LWE secret coefficient is outside its declared binary or ternary support")]
    InvalidLweSecretKeyCoefficient,

    /// The GLWE secret key has the wrong dimension.
    #[error("GLWE secret-key dimension mismatch: expected {expected}, got {actual}")]
    GlweDimensionMismatch {
        /// Dimension required by the parameters.
        expected: usize,
        /// Dimension found in the key.
        actual: usize,
    },

    /// The GLWE secret key has the wrong polynomial length.
    #[error("GLWE polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Polynomial length required by the parameters.
        expected: usize,
        /// Polynomial length found in the key.
        actual: usize,
    },

    /// The GLWE secret-key distribution does not match the parameters.
    #[error("GLWE secret-key distribution mismatch")]
    GlweSecretKeyDistributionMismatch,

    /// A ring-secret coefficient exceeds its declared encryption support.
    #[error("GLWE secret coefficient exceeds its declared support")]
    InvalidGlweSecretKeyCoefficient,
}

/// A failure to construct a family client.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheClientError {
    /// A CBS-specific client needs a context prepared for CBS.
    #[error("context has no circuit-bootstrap parameters")]
    MissingCircuitBootstrapParameters,
    /// The client key does not match the parameter set.
    #[error(transparent)]
    IncompatibleKey(#[from] TfheKeyError),
    /// The selected LWE key does not match its external domain.
    #[error(transparent)]
    Client(#[from] primus_tfhe::ClientError),
    /// The Boolean client requires plaintext modulus four.
    #[error(transparent)]
    Boolean(#[from] primus_tfhe::BooleanError),
}

/// An invalid circuit-bootstrapping parameter set.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CircuitBootstrapParameterError {
    /// Split35 cannot represent this ring domain or secret distribution.
    #[error("split35 trace requires native u64, rank one and a binary/ternary ring secret")]
    UnsupportedSplitTrace,
    /// The configured output radix or retained-level count is invalid.
    #[error("invalid circuit-bootstrap output basis")]
    InvalidOutputBasis(#[from] ApproxSignedBasisError),
    /// A configured key decomposition or derived gadget layout is invalid.
    #[error("invalid circuit-bootstrap {role} parameters")]
    GadgetParameters {
        /// Key role: trace or scheme-switch.
        role: &'static str,
        /// Invalid basis or gadget layout.
        #[source]
        source: primus_glwe::GlevParameterError,
    },
    /// The output basis belongs to another explicit or native modulus.
    #[error("circuit-bootstrap output basis modulus does not match the accumulator")]
    OutputBasisModulusMismatch,
    /// A gadget parameter set uses a different GLWE dimension or polynomial
    /// length from the TFHE accumulator.
    #[error("circuit-bootstrap {role} GLWE layout does not match the TFHE accumulator")]
    GlweLayoutMismatch {
        /// Role of the incompatible gadget parameter set.
        role: &'static str,
    },
    /// A gadget parameter set uses a different ciphertext modulus.
    #[error("circuit-bootstrap {role} modulus does not match the TFHE accumulator")]
    CipherModulusMismatch {
        /// Role of the incompatible gadget parameter set.
        role: &'static str,
    },
    /// The output gadget layout cannot be represented.
    #[error("circuit-bootstrap output gadget layout overflows")]
    OutputDecompositionTooLarge,
}

/// Failure to generate ordinary or circuit-bootstrap keys for this TFHE family.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum KeyGenerationError {
    /// The context has no complete ring-output CBS configuration.
    #[error("context has no circuit-bootstrap parameters")]
    MissingCircuitBootstrapParameters,
    /// Independently supplied KS parameters do not match the BR input/return domain.
    #[error("key-switching parameters do not match the blind-rotation domain")]
    IncompatibleKeySwitchingParameters,

    /// The supplied client secrets do not match the TFHE parameters.
    #[error(transparent)]
    ClientKey(#[from] TfheKeyError),
    /// Sparse blind-rotation key generation failed.
    #[error(transparent)]
    SparseBootstrapping(#[from] SparseBootstrappingKeyError),
    /// Prepared CBS parameters belong to another accumulator domain.
    #[error("circuit-bootstrap parameters do not match this TFHE context")]
    IncompatibleCircuitBootstrapParameters,
}

/// Failure to construct an experimental sparse bootstrapping key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SparseBootstrappingKeyError {
    /// The prepared rotation modulus switch requires 2N to fit T.
    #[error("rotation domain must fit the input coefficient type")]
    RotationDomainTooLarge,
    /// Sparse generation requires a fixed-weight binary small-LWE distribution.
    #[error("sparse bootstrapping requires a fixed-weight binary small-LWE secret")]
    UnsupportedSecretDistribution,
    /// The public weight must be positive and strictly less than the input dimension.
    #[error("sparse Hamming weight must satisfy 0 < h < n")]
    InvalidHammingWeight,
    /// Public bucket-map validation or private matching failed.
    #[error(transparent)]
    BucketMap(#[from] primus_tfhe::sparse::BucketMapError),
    /// Actual secret coefficients are not binary or do not have the declared weight.
    #[error("small-LWE coefficients do not match the declared binary Hamming weight")]
    InvalidSecretCoefficients,
    /// GGSW ciphertext storage lengths exceed addressable allocation sizes.
    #[error("sparse GGSW storage size overflow")]
    StorageSizeOverflow,
    /// Coefficient storage must contain every public selection and one dummy per bucket.
    #[error("sparse coefficient storage length mismatch: expected {expected}, got {actual}")]
    StorageLengthMismatch {
        /// Required coefficient count, including all dummy controls.
        expected: usize,
        /// Supplied coefficient count.
        actual: usize,
    },
}
