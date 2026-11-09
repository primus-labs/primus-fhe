//! Checked dimensions for parameter and layout metadata.
//!
//! Raw ciphertext and secret-key buffers may have dimension zero. These types
//! describe nonzero cryptographic domains; they do not validate raw storage,
//! modulus suitability, allocation size or security.

/// An invalid nonzero LWE dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("dimension must be nonzero and dimension + 1 must fit usize, got {dimension}")]
pub struct LweDimensionError {
    /// The rejected dimension.
    pub dimension: usize,
}

/// Checked number of scalar mask coefficients.
///
/// Construction guarantees a positive dimension and a representable body-inclusive
/// count. There is no parameter-preset or security-level upper bound. Products
/// with other dimensions, polynomial lengths or batch counts require layout checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LweDimension(usize);

impl LweDimension {
    /// Checks the nonzero dimension and body-inclusive count.
    ///
    /// # Errors
    /// Returns [`LweDimensionError`] for zero or an overflowing `dimension + 1`.
    pub const fn try_new(dimension: usize) -> Result<Self, LweDimensionError> {
        if dimension > 0 && dimension < usize::MAX {
            Ok(Self(dimension))
        } else {
            Err(LweDimensionError { dimension })
        }
    }

    /// Creates a checked dimension.
    ///
    /// # Panics
    /// Panics if [`Self::try_new`] rejects the dimension.
    #[must_use]
    pub const fn new(dimension: usize) -> Self {
        match Self::try_new(dimension) {
            Ok(value) => value,
            Err(_) => panic!("invalid dimension"),
        }
    }

    /// Returns the number of scalar mask coefficients.
    #[must_use]
    #[inline]
    pub const fn get(self) -> usize {
        self.0
    }

    /// Returns the number of mask and body scalars.
    #[must_use]
    #[inline]
    pub const fn ciphertext_len(self) -> usize {
        self.0 + 1
    }
}

impl TryFrom<usize> for LweDimension {
    type Error = LweDimensionError;
    #[inline]
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<LweDimension> for usize {
    #[inline]
    fn from(value: LweDimension) -> Self {
        value.get()
    }
}

/// An invalid nonzero GLWE dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("dimension must be nonzero and dimension + 1 must fit usize, got {dimension}")]
pub struct GlweDimensionError {
    /// The rejected dimension.
    pub dimension: usize,
}

/// Checked number of mask polynomials.
///
/// Construction guarantees a positive dimension and a representable body-inclusive
/// count. There is no parameter-preset or security-level upper bound. Products
/// with other dimensions, polynomial lengths or batch counts require layout checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GlweDimension(usize);

impl GlweDimension {
    /// Checks the nonzero dimension and body-inclusive count.
    ///
    /// # Errors
    /// Returns [`GlweDimensionError`] for zero or an overflowing `dimension + 1`.
    pub const fn try_new(dimension: usize) -> Result<Self, GlweDimensionError> {
        if dimension > 0 && dimension < usize::MAX {
            Ok(Self(dimension))
        } else {
            Err(GlweDimensionError { dimension })
        }
    }

    /// Creates a checked dimension.
    ///
    /// # Panics
    /// Panics if [`Self::try_new`] rejects the dimension.
    #[must_use]
    pub const fn new(dimension: usize) -> Self {
        match Self::try_new(dimension) {
            Ok(value) => value,
            Err(_) => panic!("invalid dimension"),
        }
    }

    /// Returns the number of mask polynomials.
    #[must_use]
    #[inline]
    pub const fn get(self) -> usize {
        self.0
    }

    /// Returns the number of mask and body polynomials.
    #[must_use]
    #[inline]
    pub const fn component_count(self) -> usize {
        self.0 + 1
    }
}

impl TryFrom<usize> for GlweDimension {
    type Error = GlweDimensionError;
    #[inline]
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<GlweDimension> for usize {
    #[inline]
    fn from(value: GlweDimension) -> Self {
        value.get()
    }
}

/// A polynomial sample has one LWE mask coefficient per ring coefficient.
/// A representable power of two is strictly smaller than `usize::MAX`, so
/// the dimension and its body-inclusive count fit without another check.
impl From<primus_shape::PolyLength> for LweDimension {
    #[inline]
    fn from(poly_length: primus_shape::PolyLength) -> Self {
        Self(poly_length.get())
    }
}

/// A sample extracted from a GLWE has one LWE mask scalar per mask coefficient.
/// The checked layout guarantees kN > 0 and kN+1 <= (k+1)N, so the derived
/// dimension and its body-inclusive count fit without another range check.
impl From<crate::GlweSize> for LweDimension {
    #[inline]
    fn from(size: crate::GlweSize) -> Self {
        Self(size.mask_len())
    }
}
