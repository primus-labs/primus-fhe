//! Errors from LUT compilation and evaluator construction.

/// An error produced while constructing a TFHE evaluator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheEvaluationError {
    /// The context has no complete ring-output CBS configuration.
    #[error("context has no circuit-bootstrap parameters")]
    MissingCircuitBootstrapParameters,
    /// Boolean gates require input modulus 4 and signed LUT values at modulus-8 scale.
    #[error("Boolean evaluation requires plaintext modulus 4 and ciphertext moduli greater than 8")]
    InvalidBooleanEncoding,
    /// The GLWE Boolean wrapper has no separate small-q LUT compilation path.
    #[error("GLWE Boolean gates currently require equal small-LWE and ring moduli")]
    BooleanRequiresSameModulus,
    /// The selected KS→BR order requires input ring key-switching material.
    #[error("keyswitch-bootstrap requires a GLWE key-switching key")]
    MissingGlweKeySwitchingKey,
    /// Ring KS material has another input/output layout or decomposition basis/modulus.
    #[error("GLWE key-switching key is incompatible with the evaluation context")]
    IncompatibleGlweKeySwitchingKey,
    /// Blind-rotation material has another layout, distribution or basis/modulus.
    #[error("blind-rotation key is incompatible with the evaluation context")]
    IncompatibleBlindRotationKey,
    /// NTRU return material has another ring, target dimension or Q→q decomposition.
    #[error("LWE return key is incompatible with the evaluation context")]
    IncompatibleLweReturnKey,
    /// CBS parameters belong to another accumulator or input domain.
    #[error("circuit-bootstrap parameters do not match the TFHE context")]
    IncompatibleCircuitBootstrapParameters,
    /// CBS material has a different layout or decomposition basis.
    #[error("circuit-bootstrap key is incompatible with its parameters")]
    IncompatibleCircuitBootstrapKey,
    /// A CBS program has another ring, external modulus or output gadget basis.
    #[error("circuit-bootstrap lookup table is incompatible with the evaluation parameters")]
    IncompatibleCircuitBootstrapLookupTable,
    /// Compiling an evaluator's internal LUT failed.
    #[error(transparent)]
    LookupTable(#[from] LookupTableError),
}

/// An error produced while compiling a TFHE lookup table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LookupTableError {
    /// The MSB lane stride or quantized bit center has no strict half-ring protection interval.
    #[error("MSB Boolean CBS requires a stride at most N/2 and interior bit centers")]
    InvalidMsbGeometry,
    /// An even/native ring has no exact half for an odd gadget scalar.
    #[error("MSB Boolean CBS requires even gadget scalars under an even or native modulus")]
    OddMsbGadgetScale,
    /// The requested input encoding is invalid at external q.
    #[error("invalid lookup-table input encoding")]
    InputEncoding(#[source] primus_encoding::CodecError),
    /// The requested output encoding is invalid at accumulator Q or external q.
    #[error("invalid lookup-table output encoding")]
    OutputEncoding(#[from] primus_encoding::CodecError),
    /// The program's input codec uses another external ciphertext modulus.
    #[error("input codec ciphertext modulus differs from the external modulus")]
    InputModulusMismatch,
    /// The rotation domain `2N` cannot be represented by the coefficient word.
    #[error("lookup-table rotation domain does not fit the coefficient word")]
    RotationDomainTooLarge,
    /// The rounded input encoding requires `t > 1` and explicit `q > t`.
    #[error("invalid lookup-table input encoding")]
    InvalidInputEncoding,
    /// Full-domain signed folding requires an odd plaintext modulus.
    #[error("full-domain lookup-table compilation requires an odd plaintext modulus")]
    EvenPlaintextModulus,
    /// Fixed-scale difference factorization supports odd explicit moduli and Native.
    #[error("factorized lookup tables require an odd explicit coefficient modulus or Native")]
    UnsupportedFactorizationModulus,
    /// Native difference factorization requires an even Scaled output scale.
    #[error("Native factorized lookup tables require an even output scale")]
    OddFactorizationScale,
    /// The selected input domain must be a non-empty prefix of the front half.
    #[error("lookup-table input domain {domain_len} must belong to 1..={max_domain_len}")]
    InvalidInputDomain {
        /// Supplied domain length.
        domain_len: usize,
        /// Largest independently programmable domain length.
        max_domain_len: usize,
    },
    /// Bivariate domain lengths must be nonzero and their product must fit `usize`.
    #[error("invalid bivariate domain lengths: {lhs_domain_len} by {rhs_domain_len}")]
    InvalidBivariateDomain {
        /// Number of possible left-hand messages; also the packing base.
        lhs_domain_len: usize,
        /// Number of possible right-hand messages.
        rhs_domain_len: usize,
    },
    /// A raw output is not canonical under the accumulator modulus.
    #[error("encoded lookup-table output for input {input} is outside the accumulator modulus")]
    EncodedOutputOutOfRange {
        /// Input whose encoded output is invalid.
        input: usize,
    },
    /// The plaintext modulus cannot be used as a platform-sized domain length.
    #[error("plaintext modulus is too large for lookup-table compilation")]
    PlaintextModulusTooLarge,
    /// The input domain needs more coefficients than each output has available.
    #[error(
        "plaintext domain of length {domain_len} exceeds the {coefficients_per_output} coefficients available per output"
    )]
    PlaintextDomainTooLarge {
        /// Number of independently programmable plaintext inputs.
        domain_len: usize,
        /// Coefficient capacity used by this check: polynomial length `N` for
        /// the initial domain check, `N / s` for the interleaved layout check,
        /// where `s` is the padded output count.
        coefficients_per_output: usize,
    },
    /// Adjacent centers in compilation order collide after encoding, modulus
    /// switching and, for an odd full domain, signed folding.
    #[error(
        "rotation-center collision between inputs {first_input} and {second_input} at compilation position {center_position}"
    )]
    RotationCenterCollision {
        /// Input at the first center in compilation order.
        first_input: usize,
        /// Input at the next center; front-half compilation uses the domain length
        /// for its terminating center, odd full-domain compilation uses input zero.
        second_input: usize,
        /// Center position in the compiler's per-output coefficient coordinates.
        /// For an interleaved table, multiply by the padded output count to get
        /// the position in polynomial coefficient coordinates. Odd full-domain
        /// centers are folded modulo the polynomial length.
        center_position: usize,
    },
    /// A slice has the wrong domain length for the selected compilation mode.
    #[error("lookup-table domain length mismatch: expected {expected}, got {actual}")]
    DomainLengthMismatch {
        /// Required output count.
        expected: usize,
        /// Supplied output count.
        actual: usize,
    },
    /// The flattened LUT or factor buffer length does not fit in `usize`.
    #[error("flattened lookup-table length overflows usize")]
    TableLengthOverflow,
    /// A lookup table must have at least one output.
    #[error("lookup table requires at least one output")]
    EmptyOutputs,
    /// The requested number of outputs exceeds the accumulator length.
    #[error("many-LUT output count {output_count} exceeds polynomial length {poly_length}")]
    OutputCountTooLarge {
        /// Supplied output count.
        output_count: usize,
        /// Accumulator polynomial length.
        poly_length: usize,
    },
    /// The output codec uses a different modulus from the accumulator.
    #[error("output codec ciphertext modulus differs from the accumulator modulus")]
    OutputModulusMismatch,
    /// The CBS output gadget basis uses another accumulator modulus.
    #[error("output gadget basis modulus differs from the accumulator modulus")]
    OutputBasisModulusMismatch,
    /// A function output lies outside the output codec's plaintext domain.
    #[error("lookup-table output for input {input} is outside the output plaintext domain")]
    OutputOutOfRange {
        /// Input whose output is invalid.
        input: usize,
    },
}
