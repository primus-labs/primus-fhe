use num_traits::Zero;

/// When true, the `div_wide` path (which uses a wider integer type or hardware
/// division) is preferred over the `div_half` path (which splits into two
/// half-word divisions).  This is a compile-time decision based on the target
/// architecture's integer-division performance.
///
/// Currently enabled on x86_64 and aarch64, which have fast hardware division
/// for their native word size.  Additional architectures (e.g. loongarch64)
/// can be added as needed.
///
/// Types with `BITS ≤ 16` always use `div_wide` regardless of this flag: their
/// cast target types (u16 / u32) are native on all supported targets.
const FAST_DIV_WIDE: bool = cfg!(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64"
));

/// A trait for types that support combined division and remainder operation.
pub trait DivRem: Sized {
    /// Computes `(self / divisor, self % divisor)` in one operation.
    fn div_rem(self, divisor: Self) -> (Self, Self);
}

macro_rules! impl_div_rem {
    ($($T:ty)*) => {$(
        impl DivRem for $T {
            #[inline]
            fn div_rem(self, rhs: Self) -> (Self, Self) {
                (self / rhs, self % rhs)
            }
        })*
    };
}

impl_div_rem! { u8 u16 u32 u64 u128 usize }

/// A trait for types that support division and remainder operation by a scalar.
pub trait DivRemScalar: Sized {
    /// Divides a multi-limb `dividend` by a single-limb `divisor`, writing the
    /// quotient into `quotient` and returning the remainder.
    fn div_rem_scalar(dividend: &[Self], divisor: Self, quotient: &mut [Self]) -> Self;
}

/// Divides two limbs `(hi << BITS) | lo` by `divisor`, returning the quotient.
///
/// Callers must ensure `hi < divisor`.
pub trait DivWide: Sized {
    /// Computes `((hi << BITS) | lo) / divisor`.
    fn div_wide(lo: Self, hi: Self, divisor: Self) -> Self;
}

macro_rules! impl_div_wide {
    ($T:ty, $W:ty) => {
        impl DivWide for $T {
            #[inline]
            fn div_wide(lo: Self, hi: Self, divisor: Self) -> Self {
                debug_assert!(hi < divisor);
                let dividend = (lo as $W) | ((hi as $W) << <$T>::BITS);
                (dividend / divisor as $W) as $T
            }
        }
    };
}

impl_div_wide!(u8, u16);
impl_div_wide!(u16, u32);
impl_div_wide!(u32, u64);
impl_div_wide!(u64, u128);

#[cfg(target_pointer_width = "64")]
impl_div_wide!(usize, u128);

#[cfg(target_pointer_width = "32")]
impl_div_wide!(usize, u64);

impl DivWide for u128 {
    #[inline]
    fn div_wide(lo: Self, hi: Self, divisor: Self) -> Self {
        debug_assert!(hi < divisor);
        let mut quotient = [0u128; 2];
        Self::div_rem_scalar(&[lo, hi], divisor, &mut quotient);
        quotient[0]
    }
}

/// Multi-limb division by a scalar for types that fit in a wider word.
///
/// The helper functions and constants are kept inside the method body so they do
/// not pollute the module namespace.
macro_rules! impl_div_rem_scalar {
    ($T:ty, $W:ty) => {
        impl DivRemScalar for $T {
            fn div_rem_scalar(dividend: &[Self], divisor: Self, quotient: &mut [Self]) -> $T {
                const HALF_BITS: u32 = <$T>::BITS >> 1;
                const LO_MASK: $T = (<$T>::MAX) >> HALF_BITS;

                debug_assert!(!dividend.is_empty());
                debug_assert_eq!(dividend.len(), quotient.len());

                if divisor.is_zero() {
                    panic!("attempt to divide by zero")
                }

                if divisor == 1 {
                    quotient.copy_from_slice(dividend);
                    return 0;
                }

                // Only the lowest limb is non-zero — use native division directly.
                if dividend[1..].iter().all(|&v| v.is_zero()) {
                    quotient.fill(0);
                    let (q, r) = dividend[0].div_rem(divisor);
                    quotient[0] = q;
                    return r;
                }

                // Strip trailing zero limbs so the per-limb loop processes fewer
                // iterations.
                let mut dividend = dividend;
                let mut quotient = quotient;
                if dividend.last().is_some_and(|v| v.is_zero()) {
                    let last_non_zero = dividend.iter().rposition(|&v| !v.is_zero()).unwrap();
                    quotient[last_non_zero + 1..].fill(0);
                    dividend = &dividend[..=last_non_zero];
                    quotient = &mut quotient[..=last_non_zero];
                }

                let mut rem = 0;

                // u8 / u16 always use div_wide: their cast target types
                // (u16 / u32) are native division on every supported target.
                if <$T>::BITS > 16 && !FAST_DIV_WIDE && divisor <= LO_MASK {
                    /// Divide `(rem << BITS) | digit` by `divisor`, returning
                    /// `(quotient, remainder)`.
                    ///
                    /// This splits the dividend into two half-width pieces and
                    /// performs two native divisions, avoiding the need for a
                    /// wider type.
                    #[inline]
                    fn div_half(rem: $T, digit: $T, divisor: $T) -> ($T, $T) {
                        const HALF: u32 = <$T>::BITS >> 1;
                        const MASK: $T = (<$T>::MAX) >> HALF;
                        debug_assert!(rem < divisor && divisor <= MASK);
                        let (hi, rem) = ((rem << HALF) | (digit >> HALF)).div_rem(divisor);
                        let (lo, rem) = ((rem << HALF) | (digit & MASK)).div_rem(divisor);
                        ((hi << HALF) | lo, rem)
                    }

                    for (&d_elem, q_elem) in dividend.iter().rev().zip(quotient.iter_mut().rev()) {
                        let (q, r) = div_half(rem, d_elem, divisor);
                        *q_elem = q;
                        rem = r;
                    }
                } else {
                    /// Divide `(hi << BITS) | lo` by `divisor`, returning
                    /// `(quotient, remainder)` using a wider integer type.
                    #[inline]
                    fn div_wide(hi: $T, lo: $T, divisor: $T) -> ($T, $T) {
                        debug_assert!(hi < divisor);
                        let lhs = lo as $W | ((hi as $W) << <$T>::BITS);
                        let rhs = divisor as $W;
                        ((lhs / rhs) as $T, (lhs % rhs) as $T)
                    }

                    for (&d_elem, q_elem) in dividend.iter().rev().zip(quotient.iter_mut().rev()) {
                        let (q, r) = div_wide(rem, d_elem, divisor);
                        *q_elem = q;
                        rem = r;
                    }
                }

                rem
            }
        }
    };
}

impl_div_rem_scalar!(u8, u16);
impl_div_rem_scalar!(u16, u32);
impl_div_rem_scalar!(u32, u64);
impl_div_rem_scalar!(u64, u128);

#[cfg(target_pointer_width = "64")]
impl_div_rem_scalar!(usize, u128);

#[cfg(target_pointer_width = "32")]
impl_div_rem_scalar!(usize, u64);

// ---------------------------------------------------------------------------
// u128 – no wider standard integer type exists, so the implementation is
// manual.  Structure parallels the macro-generated versions: early returns,
// `div_half` for divisors fitting in 64 bits, and Knuth Algorithm D for
// full-width divisors.
// ---------------------------------------------------------------------------

use std::num::NonZeroU128;

/// Divide `(rem << 128) | digit` by `divisor`, returning `(quotient, remainder)`.
///
/// # Correctness
///
/// * `rem < divisor`
/// * `divisor` must fit in 64 bits (`divisor <= u64::MAX as u128`)
#[inline]
fn div_half_u128(rem: u128, digit: u128, divisor: u128) -> (u128, u128) {
    debug_assert!(rem < divisor && divisor <= u64::MAX as u128);
    let (hi, rem) = ((rem << 64) | (digit >> 64)).div_rem(divisor);
    let (lo, rem) = ((rem << 64) | (digit & (u64::MAX as u128))).div_rem(divisor);
    ((hi << 64) | lo, rem)
}

impl DivRemScalar for u128 {
    fn div_rem_scalar(dividend: &[u128], divisor: u128, quotient: &mut [u128]) -> u128 {
        debug_assert!(!dividend.is_empty());
        debug_assert_eq!(dividend.len(), quotient.len());

        if divisor == 0 {
            panic!("attempt to divide by zero")
        }

        if divisor == 1 {
            quotient.copy_from_slice(dividend);
            return 0;
        }

        // Only the lowest limb is non-zero.
        if dividend[1..].iter().all(|&v| v == 0) {
            quotient.fill(0);
            quotient[0] = dividend[0] / divisor;
            return dividend[0] % divisor;
        }

        // Strip trailing zero limbs.
        let mut dividend = dividend;
        let mut quotient = quotient;
        if dividend.last().copied() == Some(0) {
            let last_non_zero = dividend.iter().rposition(|&v| v != 0).unwrap();
            quotient[last_non_zero + 1..].fill(0);
            dividend = &dividend[..=last_non_zero];
            quotient = &mut quotient[..=last_non_zero];
        }

        let mut rem = 0;

        // Divisor fits in 64 bits → use the half-word path (same as the
        // !FAST_DIV_WIDE branch in the macro).
        if divisor <= u64::MAX as u128 {
            for (&d_elem, q_elem) in dividend.iter().rev().zip(quotient.iter_mut().rev()) {
                let (q, r) = div_half_u128(rem, d_elem, divisor);
                *q_elem = q;
                rem = r;
            }
            return rem;
        }

        // Full-width divisor — Knuth Algorithm D.
        let len = dividend.len();
        // SAFETY: `divisor != 0` checked above.
        let non_zero_divisor = unsafe { NonZeroU128::new_unchecked(divisor) };

        if dividend[len - 1] < divisor {
            quotient[len - 1] = 0;
            quotient[len - 2] = udiv256_by_128_to_128(
                dividend[len - 1],
                dividend[len - 2],
                non_zero_divisor,
                &mut rem,
            );
        } else {
            let (q, r) = dividend[len - 1].div_rem(divisor);
            quotient[len - 1] = q;
            quotient[len - 2] =
                udiv256_by_128_to_128(r, dividend[len - 2], non_zero_divisor, &mut rem);
        }

        for (&d, q) in dividend[0..len - 2]
            .iter()
            .rev()
            .zip(quotient[0..len - 2].iter_mut().rev())
        {
            *q = udiv256_by_128_to_128(rem, d, non_zero_divisor, &mut rem);
        }

        rem
    }
}

/// Knuth Algorithm D: divide a 256-bit number `(u1 << 128) | u0` by a 128-bit
/// divisor `v`, returning the quotient and storing the remainder in `r`.
///
/// The divisor is passed as [`NonZeroU128`] to enable the compiler to optimize
/// division.
///
/// # Correctness
///
/// * `u1 < v.get()` (the high limb must be smaller than the divisor)
#[inline(always)]
fn udiv256_by_128_to_128(u1: u128, u0: u128, mut v: NonZeroU128, r: &mut u128) -> u128 {
    const N_UDWORD_BITS: u32 = 128;

    #[inline]
    /// Left-shift a [`NonZeroU128`] by `n`, preserving non-zeroness.
    ///
    /// # Safety
    ///
    /// Caller must ensure `n < 128` and that `x << n != 0` (i.e. the shift
    /// does not push every set bit out of the 128-bit word). Both conditions
    /// are checked under `debug_assert!`.
    unsafe fn shl_nz(x: NonZeroU128, n: u32) -> NonZeroU128 {
        debug_assert!(n < N_UDWORD_BITS);
        let res: u128 = x.get() << n;
        debug_assert_ne!(res, 0);
        // SAFETY: caller guarantees `res != 0` (see `# Safety` on `shl_nz`).
        unsafe { NonZeroU128::new_unchecked(res) }
    }

    #[inline]
    /// Right-shift a [`NonZeroU128`] by `n`, preserving non-zeroness.
    ///
    /// # Safety
    ///
    /// Caller must ensure `n < 128` and that `x >> n != 0` (i.e. the shift
    /// does not erase every set bit). Both conditions are checked under
    /// `debug_assert!`.
    unsafe fn shr_nz(x: NonZeroU128, n: u32) -> NonZeroU128 {
        debug_assert!(n < N_UDWORD_BITS);
        let res: u128 = x.get() >> n;
        debug_assert_ne!(res, 0);
        // SAFETY: caller guarantees `res != 0` (see `# Safety` on `shr_nz`).
        unsafe { NonZeroU128::new_unchecked(res) }
    }

    const B: u128 = 1 << (N_UDWORD_BITS / 2); // Number base (2^64)
    let (un1, un0): (u128, u128); // Norm. dividend LSD's
    let (vn1, vn0): (NonZeroU128, u128); // Norm. divisor digits
    let (mut q1, mut q0): (u128, u128); // Quotient digits
    let (un128, un21, un10): (u128, u128, u128); // Dividend digit pairs

    debug_assert!(v.get() > u1);

    let s = v.leading_zeros();
    debug_assert_ne!(s, N_UDWORD_BITS);
    if s > 0 {
        // Normalize the divisor.
        // SAFETY: `s = v.leading_zeros()` so `v << s` still has its top bit
        // set and is therefore non-zero; `s < 128` since `v != 0`.
        v = unsafe { shl_nz(v, s) };
        un128 = (u1 << s) | (u0 >> (N_UDWORD_BITS - s));
        un10 = u0 << s;
    } else {
        // Avoid undefined behavior of (u0 >> 128).
        un128 = u1;
        un10 = u0;
    }

    // Break divisor up into two 64-bit digits.
    // SAFETY: after normalization the top bit of `v` is set, so `v >> 64`
    // still has at least one bit and is non-zero; `64 < 128`.
    vn1 = unsafe { shr_nz(v, N_UDWORD_BITS / 2) };
    let vn1_val = vn1.get();
    let vn1_u64 = vn1_val as u64; // safe: vn1 < 2^64 by construction
    vn0 = v.get() & 0xFFFF_FFFF_FFFF_FFFF;

    // Break right half of dividend into two digits.
    un1 = un10 >> (N_UDWORD_BITS / 2);
    un0 = un10 & 0xFFFF_FFFF_FFFF_FFFF;

    // Compute the first quotient digit, q1.
    //
    // Use standard Knuth D estimation: if the high 64 bits of the
    // dividend are ≥ vn1, clamp to B-1 immediately.  Otherwise the
    // quotient fits in 64 bits and we can use native u128 / u64 division
    // (hardware `div` on x86_64 / aarch64) instead of the slower u128 /
    // u128 software routine.
    q1 = if (un128 >> 64) as u64 >= vn1_u64 {
        B - 1
    } else {
        un128 / (vn1_u64 as u128)
    };
    let mut rhat = un128 - q1 * vn1_val;

    // q1 has at most error 2. No more than 2 iterations.
    while q1 >= B || q1 * vn0 > B * rhat + un1 {
        q1 -= 1;
        rhat += vn1_val;
        if rhat >= B {
            break;
        }
    }

    un21 = un128
        .wrapping_mul(B)
        .wrapping_add(un1)
        .wrapping_sub(q1.wrapping_mul(v.get()));

    // Compute the second quotient digit.  Same 128/64 optimization.
    q0 = if (un21 >> 64) as u64 >= vn1_u64 {
        B - 1
    } else {
        un21 / (vn1_u64 as u128)
    };
    rhat = un21 - q0 * vn1_val;

    // q0 has at most error 2. No more than 2 iterations.
    while q0 >= B || q0 * vn0 > B * rhat + un0 {
        q0 -= 1;
        rhat += vn1_val;
        if rhat >= B {
            break;
        }
    }

    *r = (un21
        .wrapping_mul(B)
        .wrapping_add(un0)
        .wrapping_sub(q0.wrapping_mul(v.get())))
        >> s;
    q1 * B + q0
}

#[cfg(test)]
mod tests {
    use super::DivRemScalar;

    fn limbs_to_u128(limbs: &[u32]) -> u128 {
        limbs.iter().enumerate().fold(0u128, |acc, (i, &limb)| {
            acc | ((limb as u128) << (u32::BITS as usize * i))
        })
    }

    #[test]
    fn div_rem_scalar_u32_divisor_one_copies_all_limbs() {
        let dividend = [3u32, 5, 7, 11];
        let mut quotient = [u32::MAX; 4];

        let remainder = u32::div_rem_scalar(&dividend, 1, &mut quotient);

        assert_eq!(remainder, 0);
        assert_eq!(quotient, dividend);
    }

    #[test]
    fn div_rem_scalar_u32_zero_dividend_clears_quotient() {
        let dividend = [0u32; 4];
        let mut quotient = [u32::MAX; 4];

        let remainder = u32::div_rem_scalar(&dividend, 7, &mut quotient);

        assert_eq!(remainder, 0);
        assert_eq!(quotient, [0; 4]);
    }

    #[test]
    fn div_rem_scalar_u32_single_effective_limb_clears_tail() {
        let dividend = [29u32, 0, 0, 0];
        let mut quotient = [u32::MAX; 4];

        let remainder = u32::div_rem_scalar(&dividend, 7, &mut quotient);

        assert_eq!(remainder, 1);
        assert_eq!(quotient, [4, 0, 0, 0]);
    }

    #[test]
    fn div_rem_scalar_u32_single_effective_limb_less_than_divisor() {
        let dividend = [5u32, 0, 0, 0];
        let mut quotient = [u32::MAX; 4];

        let remainder = u32::div_rem_scalar(&dividend, 7, &mut quotient);

        assert_eq!(remainder, 5);
        assert_eq!(quotient, [0, 0, 0, 0]);
    }

    #[test]
    fn div_rem_scalar_u32_general_path_matches_u128_arithmetic() {
        let dividend = [0xfedc_ba98u32, 0x7654_3210, 0x89ab_cdef, 0x0123_4567];
        let divisor = 132_120_577u32;
        let mut quotient = [u32::MAX; 4];

        let remainder = u32::div_rem_scalar(&dividend, divisor, &mut quotient);

        let dividend_u128 = limbs_to_u128(&dividend);
        let quotient_u128 = limbs_to_u128(&quotient);

        assert_eq!(quotient_u128, dividend_u128 / divisor as u128);
        assert_eq!(remainder as u128, dividend_u128 % divisor as u128);
    }

    #[test]
    fn div_rem_scalar_u32_skips_zero_high_limbs_and_clears_tail() {
        let dividend = [0x89ab_cdefu32, 0x0123_4567, 0, 0];
        let divisor = 132_120_577u32;
        let mut quotient = [u32::MAX; 4];

        let remainder = u32::div_rem_scalar(&dividend, divisor, &mut quotient);

        let dividend_u128 = limbs_to_u128(&dividend[..2]);
        let quotient_u128 = limbs_to_u128(&quotient[..2]);

        assert_eq!(quotient[2..], [0, 0]);
        assert_eq!(quotient_u128, dividend_u128 / divisor as u128);
        assert_eq!(remainder as u128, dividend_u128 % divisor as u128);
    }

    #[test]
    fn div_rem_scalar_u128_divisor_one_copies_all_limbs() {
        let dividend = [3u128, 5, 7];
        let mut quotient = [u128::MAX; 3];

        let remainder = u128::div_rem_scalar(&dividend, 1, &mut quotient);

        assert_eq!(remainder, 0);
        assert_eq!(quotient, dividend);
    }

    #[test]
    fn div_rem_scalar_u128_zero_dividend_clears_quotient() {
        let dividend = [0u128; 3];
        let mut quotient = [u128::MAX; 3];

        let remainder = u128::div_rem_scalar(&dividend, 17, &mut quotient);

        assert_eq!(remainder, 0);
        assert_eq!(quotient, [0; 3]);
    }

    // Exercises the Knuth Algorithm D path for u128 (full-width divisor > 64 bits,
    // multi-limb dividend) by cross-checking against the analogous u64 division
    // on a small enough quantity to fit in u128 arithmetic, then by self-consistency
    // (`quotient * divisor + remainder == dividend`).
    #[test]
    fn div_rem_scalar_u128_full_width_divisor_self_consistent() {
        // Dividend: 3-limb u128 number.  All three limbs non-zero, all top
        // 2 bits clear so Knuth D doesn't take the `dividend[len-1] < divisor`
        // shortcut blindly.
        let dividend = [
            0xfedc_ba98_7654_3210_dead_beef_cafe_babe_u128,
            0x0123_4567_89ab_cdef_1122_3344_5566_7788,
            0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
        ];
        // Divisor: a full-width 128-bit value (top bit set after normalization
        // means `s = 0` so the un-shifted path is exercised in `udiv256_by_128_to_128`).
        let divisor = 0xc0ff_ee15_dead_beef_face_b00c_1337_4242_u128;

        let mut quotient = [u128::MAX; 3];
        let remainder = u128::div_rem_scalar(&dividend, divisor, &mut quotient);

        // Reconstruct dividend = quotient * divisor + remainder limb-wise and
        // verify equality.  Use carrying_mul to do the multi-limb multiply.
        let mut reconstructed = [0u128; 3];
        let mut carry: u128 = 0;
        for (i, &q) in quotient.iter().enumerate() {
            let (lo, hi) = q.carrying_mul(divisor, carry);
            reconstructed[i] = lo;
            carry = hi;
        }
        // No room for `carry` to be non-zero because quotient[2] * divisor + carry
        // already fits the reconstructed slot when quotient < 2^128 / divisor * limbs.
        assert_eq!(carry, 0, "unexpected high carry from quotient*divisor");

        // Add remainder to limb 0.
        let (new0, overflow) = reconstructed[0].overflowing_add(remainder);
        reconstructed[0] = new0;
        if overflow {
            let (new1, of1) = reconstructed[1].overflowing_add(1);
            reconstructed[1] = new1;
            if of1 {
                reconstructed[2] = reconstructed[2].wrapping_add(1);
            }
        }

        assert_eq!(reconstructed, dividend);
        assert!(remainder < divisor);
    }

    // Exercises the s > 0 normalization branch (divisor without the top bit set)
    // and the divisor ≤ 64-bit shortcut at line 247.
    #[test]
    fn div_rem_scalar_u128_normalization_branch() {
        let dividend = [
            0xdead_beef_cafe_babe_1234_5678_9abc_def0_u128,
            0x0001_0203_0405_0607_0809_0a0b_0c0d_0e0f,
        ];
        // 65-bit divisor: forces the full-width Knuth D path, not the 64-bit shortcut.
        let divisor: u128 = (1u128 << 64) | 0x1234_5678_9abc_def1;

        let mut quotient = [u128::MAX; 2];
        let remainder = u128::div_rem_scalar(&dividend, divisor, &mut quotient);

        // Self-consistency: quotient * divisor + remainder == dividend.
        let mut reconstructed = [0u128; 2];
        let mut carry: u128 = 0;
        for (i, &q) in quotient.iter().enumerate() {
            let (lo, hi) = q.carrying_mul(divisor, carry);
            reconstructed[i] = lo;
            carry = hi;
        }
        assert_eq!(carry, 0);

        let (new0, overflow) = reconstructed[0].overflowing_add(remainder);
        reconstructed[0] = new0;
        if overflow {
            reconstructed[1] = reconstructed[1].wrapping_add(1);
        }

        assert_eq!(reconstructed, dividend);
        assert!(remainder < divisor);
    }

    // Divisor ≤ 64 bits forces the `divisor <= u64::MAX as u128` short-circuit
    // (the `div_half_u128` path), distinct from full-width Knuth D.
    #[test]
    fn div_rem_scalar_u128_half_width_divisor() {
        let dividend = [
            0xfedc_ba98_7654_3210_0fed_cba9_8765_4321_u128,
            0x1234_5678_9abc_def0_0123_4567_89ab_cdef,
        ];
        let divisor: u128 = 0xdead_beef_cafe_babe;

        let mut quotient = [u128::MAX; 2];
        let remainder = u128::div_rem_scalar(&dividend, divisor, &mut quotient);

        // Reconstruct
        let mut reconstructed = [0u128; 2];
        let mut carry: u128 = 0;
        for (i, &q) in quotient.iter().enumerate() {
            let (lo, hi) = q.carrying_mul(divisor, carry);
            reconstructed[i] = lo;
            carry = hi;
        }
        assert_eq!(carry, 0);

        let (new0, overflow) = reconstructed[0].overflowing_add(remainder);
        reconstructed[0] = new0;
        if overflow {
            reconstructed[1] = reconstructed[1].wrapping_add(1);
        }

        assert_eq!(reconstructed, dividend);
        assert!(remainder < divisor);
    }
}
