use primus_integer::FheUint;

/// Conversion between torus (integer) values and centered floating-point
/// representation for negacyclic FFT.
///
/// # Centered representation
///
/// A torus value `x` in `[0, 2^BITS)` is mapped to the centered range
/// `[-2^(BITS-1), 2^(BITS-1) - 1]` by reinterpreting the bit pattern as a
/// signed integer of the same width, then widening to `f64`.
///
/// # Precision notes
///
/// - `u32`: exact, because `f64` has 53 mantissa bits so every `u32` value
///   is representable.
/// - `u64`: values above `2^53` lose integer precision in `f64`. This is
///   acceptable for noise terms in FHE but users should be aware of the limit.
///   A future split/high-low or double-double precision backend can strengthen
///   this without changing the high-level lattice APIs.
pub trait TorusFftValue: FheUint {
    /// Convert `self` (a torus/unsigned value) to a centered `f64`.
    ///
    /// Maps `[0, 2^BITS)` to `[-2^(BITS-1), 2^(BITS-1) - 1]` via a
    /// signed-integer reinterpret cast.
    fn into_f64_centered(self) -> f64;

    /// Convert a centered `f64` back to the torus value, rounding to nearest
    /// integer and wrapping modulo `2^BITS`.
    fn from_f64_wrapping_rounded(value: f64) -> Self;
}

impl TorusFftValue for u32 {
    #[inline]
    fn into_f64_centered(self) -> f64 {
        (self as i32) as f64
    }

    #[inline]
    fn from_f64_wrapping_rounded(value: f64) -> Self {
        // Use i64 intermediate so values that round to i32::MIN (as an i64)
        // are correctly cast back to u32 without going through i32 overflow.
        (value.round() as i64) as u32
    }
}

impl TorusFftValue for u64 {
    #[inline]
    fn into_f64_centered(self) -> f64 {
        // WARNING: f64 has 53-bit mantissa; values above 2^53 lose precision.
        (self as i64) as f64
    }

    #[inline]
    fn from_f64_wrapping_rounded(value: f64) -> Self {
        // Use i128 intermediate to avoid truncation issues at the i64 boundary.
        (value.round() as i128) as u64
    }
}

impl TorusFftValue for u16 {
    #[inline]
    fn into_f64_centered(self) -> f64 {
        (self as i16) as f64
    }

    #[inline]
    fn from_f64_wrapping_rounded(value: f64) -> Self {
        (value.round() as i32) as u16
    }
}
