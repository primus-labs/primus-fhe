use primus_integer::FheUint;

/// Conversion between unsigned torus bit patterns and `f64`.
pub trait TorusFftValue: FheUint {
    /// Exact `2^-BITS` scaling factor used by the forward torus conversion.
    const TORUS_SCALE: f64;
    /// Exact `2^BITS` scaling factor used by the backward torus conversion.
    const TORUS_SCALE_INVERSE: f64;

    /// Reinterprets the bit pattern as a signed integer and converts it to `f64`.
    fn into_signed_f64(self) -> f64;

    /// Converts the bit pattern to a normalized torus value in `[-0.5, 0.5]`.
    ///
    /// For `u64`, rounding the signed integer to `f64` can produce `+0.5`
    /// at the positive endpoint.
    #[inline]
    fn into_torus_f64(self) -> f64 {
        self.into_signed_f64() * Self::TORUS_SCALE
    }

    /// Converts a normalized torus value back to its unsigned bit pattern.
    ///
    /// Built-in implementations scale by `2^BITS`, round half-way cases away
    /// from zero, saturate to a signed integer with twice the word width, then
    /// retain the low `BITS` bits. NaN converts to zero. Values outside one
    /// torus period are accepted; this is not a saturating unsigned conversion.
    fn from_torus_f64(value: f64) -> Self;
}

macro_rules! impl_torus_fft_value {
    ($unsigned:ty, $signed:ty, $wide:ty, $scale:expr, $scale_inverse:expr) => {
        impl TorusFftValue for $unsigned {
            const TORUS_SCALE: f64 = $scale;
            const TORUS_SCALE_INVERSE: f64 = $scale_inverse;

            #[inline]
            fn into_signed_f64(self) -> f64 {
                (self as $signed) as f64
            }
            #[inline]
            fn from_torus_f64(value: f64) -> Self {
                let scaled = value * Self::TORUS_SCALE_INVERSE;
                (scaled.round() as $wide) as Self
            }
        }
    };
}

impl_torus_fft_value!(u16, i16, i32, 1.0 / 65_536.0, 65_536.0);
impl TorusFftValue for u32 {
    const TORUS_SCALE: f64 = 1.0 / 4_294_967_296.0;
    const TORUS_SCALE_INVERSE: f64 = 4_294_967_296.0;

    #[inline]
    fn into_signed_f64(self) -> f64 {
        (self as i32) as f64
    }

    #[inline]
    fn from_torus_f64(value: f64) -> Self {
        // Preserve round -> saturating i64 -> wrapping u32 without forcing
        // vector loops to extract each lane for a scalar saturating cast.
        let bits = (value * Self::TORUS_SCALE_INVERSE).round().to_bits();
        let exponent = ((bits >> 52) & 0x7ff) as u32;
        let fraction = bits & ((1u64 << 52) - 1);
        let negative = bits >> 63 != 0;
        if exponent >= 1023 + 63 {
            // i64::MIN has zero low bits; i64::MAX has all low bits set.
            // NaN converts to zero, including positive NaNs.
            return if negative || (exponent == 0x7ff && fraction != 0) {
                0
            } else {
                u32::MAX
            };
        }
        let significand = fraction | (1u64 << 52);
        let magnitude = if exponent < 1023 {
            0
        } else if exponent < 1023 + 52 {
            significand >> (1023 + 52 - exponent)
        } else {
            // The saturation check bounds this left shift to at most 10.
            significand << (exponent - (1023 + 52))
        } as u32;
        if negative {
            magnitude.wrapping_neg()
        } else {
            magnitude
        }
    }
}

impl TorusFftValue for u64 {
    const TORUS_SCALE: f64 = 1.0 / 18_446_744_073_709_551_616.0;
    const TORUS_SCALE_INVERSE: f64 = 18_446_744_073_709_551_616.0;

    #[inline]
    fn into_signed_f64(self) -> f64 {
        (self as i64) as f64
    }

    #[inline]
    fn from_torus_f64(value: f64) -> Self {
        // Preserve round -> saturating i128 -> wrapping u64. Positive i128
        // saturation starts at x=2^63 before scaling, including +infinity.
        if value >= 9_223_372_036_854_775_808.0 {
            return u64::MAX;
        }
        // NaN casts to zero; -infinity saturates to i128::MIN, with zero low bits.
        if !value.is_finite() {
            return 0;
        }
        // Integer periods contribute zero modulo 2^64. For |x|<1 trunc is zero;
        // otherwise Sterbenz's lemma makes this subtraction exact. Finite
        // negative overflow also has an integral magnitude and gives zero.
        let magnitude = value.abs();
        let fraction = magnitude - magnitude.trunc();
        let rounded = (fraction * Self::TORUS_SCALE_INVERSE).round();
        // SAFETY: fraction is finite and in [0, 1-2^-53], so rounded is in
        // [0, 2^64-2048] and fits u64. Avoid a redundant saturating cast so
        // conversion loops can use vector float-to-integer instructions.
        let bits = unsafe { rounded.to_int_unchecked::<u64>() };
        // Rounding the magnitude first preserves half-way cases away from zero.
        if value.is_sign_negative() {
            bits.wrapping_neg()
        } else {
            bits
        }
    }
}
