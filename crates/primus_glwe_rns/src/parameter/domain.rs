use primus_integer::FheUint;
use primus_lattice::RnsGlweSize;
use primus_ntt::{DcrtTable, NttTable};
use primus_reduce::FieldContext;
use primus_shape::PolyLength;

/// An incompatibility between RNS parameters, keys, layouts or transform tables.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RnsDomainError<T: FheUint> {
    /// Bound resources use different polynomial lengths.
    #[error("polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Required polynomial length.
        expected: usize,
        /// Supplied polynomial length.
        actual: usize,
    },
    /// Bound resources use different numbers of modulus limbs.
    #[error("RNS modulus count mismatch: expected {expected}, got {actual}")]
    ModuliCountMismatch {
        /// Required modulus count.
        expected: usize,
        /// Supplied modulus count.
        actual: usize,
    },
    /// Ordered bases differ at a modulus limb.
    #[error("RNS modulus mismatch at index {index}: expected {expected:?}, got {actual:?}")]
    ModulusOrderMismatch {
        /// Index of the mismatching modulus.
        index: usize,
        /// Required modulus.
        expected: T,
        /// Supplied modulus.
        actual: T,
    },
    /// A key and its bound parameters use different GLWE mask dimensions.
    #[error("GLWE dimension mismatch: expected {expected}, got {actual}")]
    DimensionMismatch {
        /// Required mask-polynomial count.
        expected: usize,
        /// Supplied mask-polynomial count.
        actual: usize,
    },
    /// A key and its parameters retain different numbers of gadget levels.
    #[error("decomposition level count mismatch: expected {expected}, got {actual}")]
    DecompositionLevelCountMismatch {
        /// Retained count used at key generation.
        expected: usize,
        /// Retained count supplied by the parameters.
        actual: usize,
    },
    /// A key and its parameters use different signed-decomposition radices.
    #[error("decomposition base log mismatch: expected {expected}, got {actual}")]
    DecompositionBaseLogMismatch {
        /// Base log used at key generation.
        expected: u32,
        /// Base log supplied by the parameters.
        actual: u32,
    },
    /// A hybrid key and its parameters partition Q differently.
    #[error("hybrid partition width mismatch: expected {expected}, got {actual}")]
    PartitionWidthMismatch {
        /// Maximum Q moduli per partition used at key generation.
        expected: usize,
        /// Maximum Q moduli per partition supplied by the parameters.
        actual: usize,
    },
}

/// Validates the numerical table binding once; transform identity remains a caller contract.
pub(crate) fn validate_dcrt_table<T, M, Table>(
    poly_length: PolyLength,
    moduli: &[M],
    table: &DcrtTable<Table>,
) -> Result<(), RnsDomainError<T>>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    let expected = poly_length.get();
    let actual = table.poly_length().get();
    if actual != expected {
        return Err(RnsDomainError::PolynomialLengthMismatch { expected, actual });
    }
    validate_moduli(
        moduli.iter().map(|m| m.value()),
        table.ntt_tables().iter().map(NttTable::modulus),
    )
}

/// Compares complete ordered bases at construction/binding, before zip can truncate.
pub(crate) fn validate_moduli<T: FheUint>(
    expected: impl ExactSizeIterator<Item = T>,
    actual: impl ExactSizeIterator<Item = T>,
) -> Result<(), RnsDomainError<T>> {
    if expected.len() != actual.len() {
        return Err(RnsDomainError::ModuliCountMismatch {
            expected: expected.len(),
            actual: actual.len(),
        });
    }
    for (index, (expected, actual)) in expected.zip(actual).enumerate() {
        if expected != actual {
            return Err(RnsDomainError::ModulusOrderMismatch {
                index,
                expected,
                actual,
            });
        }
    }
    Ok(())
}

/// Checks a secret or ciphertext key's owned layout against its parameter binding.
pub(crate) fn validate_glwe_size<T: FheUint>(
    expected: RnsGlweSize,
    actual: RnsGlweSize,
) -> Result<(), RnsDomainError<T>> {
    if expected.poly_length() != actual.poly_length() {
        return Err(RnsDomainError::PolynomialLengthMismatch {
            expected: expected.poly_length().get(),
            actual: actual.poly_length().get(),
        });
    }
    if expected.moduli_count() != actual.moduli_count() {
        return Err(RnsDomainError::ModuliCountMismatch {
            expected: expected.moduli_count(),
            actual: actual.moduli_count(),
        });
    }
    if expected.dimension() != actual.dimension() {
        return Err(RnsDomainError::DimensionMismatch {
            expected: expected.dimension().get(),
            actual: actual.dimension().get(),
        });
    }
    Ok(())
}
