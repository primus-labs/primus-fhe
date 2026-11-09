//! Errors owned by the NTRU TFHE parameter, client and key-generation boundaries.

use primus_decompose::ApproxSignedBasisError;
use primus_ntru::NlevParameterError;

/// An invalid combination of NTRU-based TFHE parameters.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum TfheParameterError {
    /// Preparing a CBS trace, scheme-switch or output gadget failed.
    #[error("invalid circuit-bootstrap gadget parameters")]
    CircuitBootstrap(#[source] CircuitBootstrapParameterError),
    /// The CBS selector's input message encoding is invalid.
    #[error("invalid selector-input encoding")]
    InputEncoding(#[source] primus_encoding::CodecError),

    /// The numerical external LWE description or fresh encryption sampler is invalid.
    #[error("invalid external LWE configuration")]
    InputParameters(#[source] primus_tfhe::LweConfigError),
    /// The ring-Q description does not fit its selected reduction representation.
    #[error("invalid accumulator modulus configuration")]
    AccumulatorModulus(#[source] primus_tfhe::ModulusConfigError),
    /// Return-key sampling state or its basis pairing at external q is invalid.
    #[error("invalid return-key encryption parameters")]
    KeySwitchingEncryption(#[source] primus_lwe::LweParameterError),
    /// The configured accumulator layout or samplers are invalid.
    #[error("invalid accumulator parameters")]
    AccumulatorParameters(#[source] primus_ntru::NtruParameterError),
    /// Invalid NLev/NGSW decomposition or layout for blind rotation.
    #[error("invalid NTRU bootstrapping parameters")]
    BootstrappingParameters(#[source] NlevParameterError),
    /// Invalid decomposition at external q for the LWE return key.
    #[error("invalid LWE return key-switching parameters")]
    KeySwitchingParameters(#[source] ApproxSignedBasisError),
    /// The rotation domain `2N` cannot be represented by the input coefficient type.
    #[error("rotation domain must fit the input coefficient type")]
    RotationDomainTooLarge,
    /// The external LWE distribution must be binary or ternary.
    #[error("NTRU TFHE requires a binary or ternary client secret-key distribution")]
    UnsupportedClientSecretKeyDistribution,
}

/// An incompatibility between NTRU client keys and TFHE parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheKeyError {
    /// The encoded LWE secret was generated or imported under another modulus.
    #[error("LWE secret-key ciphertext modulus mismatch")]
    LweSecretKeyModulusMismatch,
    /// At least one NTRU secret has the wrong polynomial length.
    #[error("NTRU client-key polynomial length mismatch")]
    PolynomialLengthMismatch,
    /// The external LWE secret has a different distribution label.
    #[error("NTRU client secret-key distribution mismatch")]
    ClientSecretKeyDistributionMismatch,
    /// An external LWE coefficient is outside the declared binary or ternary domain.
    #[error("NTRU TFHE client coefficients do not match their binary or ternary domain")]
    InvalidClientSecretKeyCoefficient,
    /// The external secret has the wrong LWE dimension.
    #[error("NTRU client key has the wrong external LWE dimension")]
    ExternalLweDimensionMismatch,
    /// A signed accumulator coefficient cannot be represented by the return key at q.
    #[error("accumulator secret magnitude must be less than the external LWE modulus")]
    AccumulatorSecretOutsideLweModulus,
    /// The accumulator key distribution differs from its parameter set.
    #[error("NTRU accumulator secret-key distribution mismatch")]
    AccumulatorSecretKeyDistributionMismatch,
}

/// A failure to construct a family client or prepare its secret representation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheClientError {
    /// The client key does not match the parameter set.
    #[error(transparent)]
    IncompatibleKey(#[from] TfheKeyError),
    /// The selected LWE key does not match its external domain.
    #[error(transparent)]
    Client(#[from] primus_tfhe::ClientError),
    /// The Boolean client requires plaintext modulus four.
    #[error(transparent)]
    Boolean(#[from] primus_tfhe::BooleanError),
    /// Preparing the accumulator secret representation failed.
    #[error("NTRU accumulator secret conversion failed")]
    Ntru(#[from] primus_ntru::NtruError),
}

/// An incompatible circuit-bootstrap parameter set.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CircuitBootstrapParameterError {
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
        source: primus_ntru::NlevParameterError,
    },
    /// The output basis belongs to another explicit or native modulus.
    #[error("circuit-bootstrap output basis modulus does not match the accumulator")]
    OutputBasisModulusMismatch,
    /// A gadget parameter set uses another ring length.
    #[error("circuit-bootstrap {role} polynomial length differs from the accumulator")]
    PolynomialLengthMismatch {
        /// The incompatible parameter role.
        role: &'static str,
    },
    /// A gadget parameter set uses another ciphertext modulus.
    #[error("circuit-bootstrap {role} modulus differs from the accumulator")]
    CipherModulusMismatch {
        /// The incompatible parameter role.
        role: &'static str,
    },
    /// Trace normalization requires an odd field modulus with Shoup headroom.
    #[error("circuit-bootstrap trace requires odd q below 2^(T::BITS-1)")]
    UnsupportedTraceModulus,
}

/// Failure to generate classic, sparse or circuit-bootstrap keys for this TFHE family.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum KeyGenerationError {
    /// The context has no complete ring-output CBS configuration.
    #[error("context has no circuit-bootstrap parameters")]
    MissingCircuitBootstrapParameters,
    /// Independently supplied KS parameters do not match the BR input/return domain.
    #[error("key-switching parameters do not match the blind-rotation domain")]
    IncompatibleKeySwitchingParameters,

    /// Sparse blind-rotation key generation failed.
    #[error(transparent)]
    SparseBootstrapping(#[from] SparseBootstrappingKeyError),
    /// The supplied client secrets do not match the TFHE parameters.
    #[error(transparent)]
    ClientKey(#[from] TfheKeyError),
    /// Prepared CBS parameters belong to another accumulator or input domain.
    #[error("circuit-bootstrap parameters do not match this TFHE context")]
    IncompatibleCircuitBootstrapParameters,
    /// Public-lift parameters use another accumulator ring.
    #[error("public-lift parameters do not match this TFHE context")]
    IncompatiblePublicLiftParameters,
    /// NTRU rejection sampling or transform conversion failed.
    #[error("NTRU key generation or conversion failed")]
    Ntru(#[from] primus_ntru::NtruError),
}

/// Failure to construct an experimental NTRU sparse bootstrapping key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SparseBootstrappingKeyError {
    /// Bucket selections require a fixed-weight binary client secret.
    #[error("sparse bootstrapping requires a fixed-weight binary client secret")]
    UnsupportedSecretDistribution,
    /// The public weight must satisfy `0 < h < n`.
    #[error("sparse Hamming weight must satisfy 0 < h < n")]
    InvalidHammingWeight,
    /// Actual client coefficients have a different weight from the declared one.
    #[error("client coefficients do not match the declared Hamming weight")]
    InvalidSecretWeight,
    /// Public map validation or private matching failed.
    #[error(transparent)]
    BucketMap(#[from] primus_tfhe::sparse::BucketMapError),
    /// Coefficient NGSW storage exceeds addressable allocation sizes.
    #[error("sparse NGSW storage size overflow")]
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
