use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{RnsGadgetSize, RnsGlweSize};
use primus_ntt::{DcrtTable, NttTable};
use primus_reduce::FieldContext;
use primus_rns::{HybridRNS, RNSBase};
use primus_shape::PolyLength;

use super::CrtGlevParameters;

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
    /// A key and its domain retain different numbers of gadget levels.
    #[error("decomposition level count mismatch: expected {expected}, got {actual}")]
    DecompositionLevelCountMismatch {
        /// Retained count used at key generation.
        expected: usize,
        /// Retained count supplied by the domain.
        actual: usize,
    },
    /// A key and its domain use different signed-decomposition radices.
    #[error("decomposition base log mismatch: expected {expected}, got {actual}")]
    DecompositionBaseLogMismatch {
        /// Base log used at key generation.
        expected: u32,
        /// Base log supplied by the domain.
        actual: u32,
    },
    /// A hybrid key and its domain partition Q differently.
    #[error("hybrid partition width mismatch: expected {expected}, got {actual}")]
    PartitionWidthMismatch {
        /// Maximum Q moduli per partition used at key generation.
        expected: usize,
        /// Maximum Q moduli per partition supplied by the domain.
        actual: usize,
    },
}

/// A checked, read-only binding of RNS gadget parameters and a DCRT table.
pub struct DcrtGadgetDomain<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    parameters: &'a CrtGlevParameters<T, M>,
    table: &'a DcrtTable<Table>,
}

impl<'a, T, M, Table> DcrtGadgetDomain<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Binds compatible RNS gadget parameters and a DCRT table.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] for a polynomial-length, modulus-count or order mismatch.
    pub fn try_new(
        parameters: &'a CrtGlevParameters<T, M>,
        table: &'a DcrtTable<Table>,
    ) -> Result<Self, RnsDomainError<T>> {
        validate_dcrt_table(parameters.poly_length(), parameters.cipher_moduli(), table)?;

        Ok(Self { parameters, table })
    }

    /// Returns the bound RNS gadget parameters.
    #[must_use]
    #[inline]
    pub fn parameters(&self) -> &'a CrtGlevParameters<T, M> {
        self.parameters
    }

    /// Returns the bound RNS gadget layout.
    #[must_use]
    #[inline]
    pub fn size(&self) -> RnsGadgetSize {
        self.parameters.size()
    }

    /// Returns the bound decomposition basis.
    #[must_use]
    #[inline]
    pub fn basis(&self) -> &BigUintApproxSignedBasis<T> {
        self.parameters.basis()
    }

    /// Returns the bound DCRT table.
    #[must_use]
    #[inline]
    pub fn table(&self) -> &'a DcrtTable<Table> {
        self.table
    }

    /// Returns the RNS basis used by the bound parameters.
    #[must_use]
    #[inline]
    pub fn rns_base(&self) -> &'a RNSBase<T, M> {
        self.parameters.base_q()
    }
}

/// A checked binding of hybrid-RNS bases and converters to their DCRT table.
pub struct HybridRnsKeySwitchDomain<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    hybrid_rns: &'a HybridRNS<T, M>,
    table: &'a DcrtTable<Table>,
}

impl<'a, T, M, Table> HybridRnsKeySwitchDomain<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Binds a complete ordered `Q/P` basis to a matching DCRT table.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] for a modulus-count or order mismatch.
    pub fn try_new(
        hybrid_rns: &'a HybridRNS<T, M>,
        table: &'a DcrtTable<Table>,
    ) -> Result<Self, RnsDomainError<T>> {
        // DcrtTable construction establishes one shared N. The evaluator later
        // compares it with the key's N; this binding owns the ordered QP basis.
        validate_moduli(
            hybrid_rns.qp_base().moduli().iter().map(|m| m.value()),
            table.iter().map(NttTable::modulus),
        )?;
        Ok(Self { hybrid_rns, table })
    }

    /// Returns the bound hybrid-RNS bases and converters.
    #[must_use]
    #[inline]
    pub fn hybrid_rns(&self) -> &'a HybridRNS<T, M> {
        self.hybrid_rns
    }

    /// Returns the bound DCRT table.
    #[must_use]
    #[inline]
    pub fn table(&self) -> &'a DcrtTable<Table> {
        self.table
    }

    /// Returns the ordered `Q` basis.
    #[must_use]
    #[inline]
    pub fn q_base(&self) -> &'a RNSBase<T, M> {
        self.hybrid_rns.q_base()
    }

    /// Returns the ordered auxiliary `P` basis.
    #[must_use]
    #[inline]
    pub fn p_base(&self) -> &'a RNSBase<T, M> {
        self.hybrid_rns.p_base()
    }

    /// Returns the complete ordered `Q || P` basis.
    #[must_use]
    #[inline]
    pub fn qp_base(&self) -> &'a RNSBase<T, M> {
        self.hybrid_rns.qp_base()
    }
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
