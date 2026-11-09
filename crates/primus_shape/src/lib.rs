//! Checked power-of-two polynomial lengths.
//!
//! [`PolyLength`] describes `Z_q[X]/(X^N + 1)` with `N >= 32`. It does not
//! establish a modulus, transform convention, buffer layout or security level.
//! Transform constructors retain their own numerical requirements.

#![deny(missing_docs)]

/// Smallest supported FHE polynomial length.
///
/// The shared range starts at a full SIMD transform block (32 coefficients),
/// while remaining small enough for focused arithmetic tests.
pub const MIN_POLY_LENGTH: usize = 32;

/// Largest supported FHE polynomial length.
pub const MAX_POLY_LENGTH: usize = 1 << 17;

/// A coefficient count outside the supported power-of-two range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "polynomial length must be a power of two in {MIN_POLY_LENGTH}..={MAX_POLY_LENGTH}, got {poly_length}"
)]
pub struct PolyLengthError {
    /// The rejected polynomial length.
    pub poly_length: usize,
}

/// Checked coefficient count `N` for a ring modulo `X^N + 1`.
///
/// Accepts powers of two in [`MIN_POLY_LENGTH`]..=[`MAX_POLY_LENGTH`], the
/// shared supported range for FHE layouts and transform tables. This bound
/// ensures `2N` fits in `usize`; allocation sizes, products with other counts
/// and transform availability still require their own checks.
///
/// ```
/// use primus_shape::PolyLength;
///
/// let length = PolyLength::try_new(1024)?;
/// assert_eq!(length.get(), 1024);
/// assert_eq!(length.log_n(), 10);
/// assert_eq!(length.fourier_poly_len(), 512);
/// # Ok::<(), primus_shape::PolyLengthError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolyLength(usize);

impl PolyLength {
    /// Checks the supported range and power-of-two requirement.
    ///
    /// # Errors
    ///
    /// Returns [`PolyLengthError`] if the count is outside the supported range
    /// or not a power of two.
    pub const fn try_new(poly_length: usize) -> Result<Self, PolyLengthError> {
        if poly_length >= MIN_POLY_LENGTH
            && poly_length <= MAX_POLY_LENGTH
            && poly_length.is_power_of_two()
        {
            Ok(Self(poly_length))
        } else {
            Err(PolyLengthError { poly_length })
        }
    }

    /// Creates a checked polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_new`] rejects the coefficient count.
    #[must_use]
    pub const fn new(poly_length: usize) -> Self {
        match Self::try_new(poly_length) {
            Ok(length) => length,
            Err(_) => panic!("polynomial length must be a power of two in the supported range"),
        }
    }

    /// Returns `N`, the number of coefficients modulo `X^N + 1`.
    #[must_use]
    #[inline]
    pub const fn get(self) -> usize {
        self.0
    }

    /// Returns `log2(N)`, as used by transform constructors.
    #[must_use]
    #[inline]
    pub const fn log_n(self) -> u32 {
        self.0.trailing_zeros()
    }

    /// Returns `N/2`, the complex element count of a packed Fourier polynomial.
    ///
    /// This count does not establish a particular Fourier backend's supported range.
    #[must_use]
    #[inline]
    pub const fn fourier_poly_len(self) -> usize {
        self.0 / 2
    }
}

impl TryFrom<usize> for PolyLength {
    type Error = PolyLengthError;

    #[inline]
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<PolyLength> for usize {
    #[inline]
    fn from(value: PolyLength) -> Self {
        value.get()
    }
}
