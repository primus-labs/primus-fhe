//! Configuration and mathematical units for gadget decomposition.
//!
//! These types establish basic ranges without binding a word type or modulus.
//! A basis constructor still validates the radix against its limb width and
//! modulus, and the retained count against the available decomposition levels.

use primus_integer::FheUint;

use crate::{
    ApproxSignedBasisError, DecompositionBaseLogError, DecompositionLevelCountError,
    primitive::ApproxSignedBasis,
};

/// Base-2 logarithm of the gadget radix.
///
/// Values are at least 2. Word-width, modulus and paired decomposition
/// constraints belong to the basis constructor; this type adds no fixed upper bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DecompositionBaseLog(u32);

impl DecompositionBaseLog {
    /// Checks the basic range of this decomposition parameter.
    ///
    /// # Errors
    /// Returns [`DecompositionBaseLogError`] for values below 2.
    pub const fn try_new(log_basis: u32) -> Result<Self, DecompositionBaseLogError> {
        if log_basis >= crate::MIN_DECOMPOSITION_LOG_BASIS {
            Ok(Self(log_basis))
        } else {
            Err(DecompositionBaseLogError { log_basis })
        }
    }

    /// Creates a checked decomposition parameter.
    ///
    /// # Panics
    /// Panics if [`Self::try_new`] rejects the value.
    #[must_use]
    pub const fn new(log_basis: u32) -> Self {
        match Self::try_new(log_basis) {
            Ok(value) => value,
            Err(_) => panic!("invalid log_basis"),
        }
    }

    /// Returns the underlying mathematical count.
    #[must_use]
    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for DecompositionBaseLog {
    type Error = DecompositionBaseLogError;
    #[inline]
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<DecompositionBaseLog> for u32 {
    #[inline]
    fn from(value: DecompositionBaseLog) -> Self {
        value.get()
    }
}

/// Number of retained gadget decomposition levels.
///
/// Values are at least 1. Word-width, modulus and paired decomposition
/// constraints belong to the basis constructor; this type adds no fixed upper bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DecompositionLevelCount(usize);

impl DecompositionLevelCount {
    /// Checks the basic range of this decomposition parameter.
    ///
    /// # Errors
    /// Returns [`DecompositionLevelCountError`] for values below 1.
    pub const fn try_new(level_count: usize) -> Result<Self, DecompositionLevelCountError> {
        if level_count >= 1 {
            Ok(Self(level_count))
        } else {
            Err(DecompositionLevelCountError { level_count })
        }
    }

    /// Creates a checked decomposition parameter.
    ///
    /// # Panics
    /// Panics if [`Self::try_new`] rejects the value.
    #[must_use]
    pub const fn new(level_count: usize) -> Self {
        match Self::try_new(level_count) {
            Ok(value) => value,
            Err(_) => panic!("invalid level_count"),
        }
    }

    /// Returns the underlying mathematical count.
    #[must_use]
    #[inline]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl TryFrom<usize> for DecompositionLevelCount {
    type Error = DecompositionLevelCountError;
    #[inline]
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<DecompositionLevelCount> for usize {
    #[inline]
    fn from(value: DecompositionLevelCount) -> Self {
        value.get()
    }
}

/// Signed gadget decomposition before binding it to a ciphertext modulus.
///
/// Convert `(config, modulus)` with [`ApproxSignedBasis::try_from`]. The modulus
/// is `None` for the implicit native modulus `2^T::BITS`, or `Some(q)` for an
/// explicit modulus. Conversion validates the radix and retained levels through
/// [`ApproxSignedBasis::try_new`], once the word width and modulus are known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecompositionConfig {
    /// Base-2 logarithm of the radix. The checked value is at least 2;
    /// basis construction additionally requires it to be below `T::BITS`.
    pub log_basis: DecompositionBaseLog,
    /// Retained high levels, or `None` for the full decomposition.
    /// Nonzero by construction; basis construction checks it against the full count.
    pub level_count: Option<DecompositionLevelCount>,
}

impl<T: FheUint> TryFrom<(DecompositionConfig, Option<T>)> for ApproxSignedBasis<T> {
    type Error = ApproxSignedBasisError;

    fn try_from(
        (decomposition, modulus): (DecompositionConfig, Option<T>),
    ) -> Result<Self, Self::Error> {
        Self::try_new(modulus, decomposition.log_basis, decomposition.level_count)
    }
}
