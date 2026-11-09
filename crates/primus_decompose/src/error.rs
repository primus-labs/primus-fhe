/// An invalid base-2 logarithm of the gadget radix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("log_basis must be at least 2, got {log_basis}")]
pub struct DecompositionBaseLogError {
    /// The rejected value.
    pub log_basis: u32,
}

/// An invalid number of retained gadget decomposition levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("level_count must be at least 1, got {level_count}")]
pub struct DecompositionLevelCountError {
    /// The rejected value.
    pub level_count: usize,
}

/// Errors returned when constructing an approximate signed decomposition basis.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApproxSignedBasisError {
    /// A multi-limb modulus is empty or has a zero most-significant limb.
    #[error("modulus must be nonempty with a nonzero most-significant limb")]
    InvalidModulusRepresentation,
    /// The effective multi-limb modulus width does not fit the bit-index type.
    #[error("modulus bit width exceeds u32::MAX")]
    ModulusBitWidthTooLarge,
    /// The packed reconstruction weights have an unrepresentable element count.
    #[error(
        "scalar storage length overflows usize for {limb_count} limbs and {level_count} levels"
    )]
    ScalarStorageLengthOverflow {
        /// Number of limbs in each reconstruction weight.
        limb_count: usize,
        /// Number of retained reconstruction weights.
        level_count: usize,
    },
    /// The logarithm of the decomposition basis is outside the supported range.
    #[error("log_basis must satisfy 2 <= log_basis < {limb_bits}, got {log_basis}")]
    InvalidLogBasis {
        /// Requested base-2 logarithm.
        log_basis: u32,
        /// Bit width of the primitive value or one multi-limb value limb.
        limb_bits: u32,
    },
    /// The decomposition basis is larger than the modulus.
    #[error("decomposition basis must not exceed the modulus")]
    BasisExceedsModulus,
    /// The requested retained level count exceeds the full level count.
    #[error(
        "level_count must not exceed the full decomposition level count {full_level_count}, got {level_count}"
    )]
    LevelCountTooLarge {
        /// Requested retained level count.
        level_count: usize,
        /// Maximum level count for this modulus and basis.
        full_level_count: usize,
    },
}
