use std::num::NonZeroU128;

use super::{DivRem, DivRemScalar, DivWide};

impl DivWide for u128 {
    #[inline]
    fn div_wide(lo: Self, hi: Self, divisor: Self) -> Self {
        debug_assert!(hi < divisor);
        if divisor <= u64::MAX as u128 {
            div_half_u128(hi, lo, divisor).0
        } else {
            let mut remainder = 0;
            // SAFETY: this branch requires `divisor > u64::MAX`.
            let divisor = unsafe { NonZeroU128::new_unchecked(divisor) };
            udiv256_by_128_to_128(hi, lo, divisor, &mut remainder)
        }
    }
}

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
        // !PREFER_WIDE_DIVISION branch in the macro).
        if divisor <= u64::MAX as u128 {
            for (&d_elem, q_elem) in dividend.iter().rev().zip(quotient.iter_mut().rev()) {
                let (q, r) = div_half_u128(rem, d_elem, divisor);
                *q_elem = q;
                rem = r;
            }
            return rem;
        }

        // Full-width divisor — Knuth Algorithm D.
        // SAFETY: zero was rejected and divisors fitting in 64 bits returned
        // above.
        let non_zero_divisor = unsafe { NonZeroU128::new_unchecked(divisor) };
        let top = dividend.len() - 1;
        let (top_quotient, top_remainder) = if dividend[top] < divisor {
            (0, dividend[top])
        } else {
            dividend[top].div_rem(divisor)
        };
        quotient[top] = top_quotient;
        rem = top_remainder;

        for (&d, q) in dividend[..top]
            .iter()
            .rev()
            .zip(quotient[..top].iter_mut().rev())
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
    // dividend are ≥ vn1, clamp to B-1 immediately. Otherwise the
    // quotient fits in 64 bits and can use native u128 / u64 division.
    q1 = if (un128 >> 64) as u64 >= vn1_u64 {
        B - 1
    } else {
        un128 / (vn1_u64 as u128)
    };
    let mut rhat = un128 - q1 * vn1_val;

    // The estimate is at most two greater than the true quotient digit, so at
    // most two corrections are required. Once `rhat >= B`, the correction
    // condition is necessarily false.
    while rhat < B && q1 * vn0 > B * rhat + un1 {
        q1 -= 1;
        rhat += vn1_val;
    }

    un21 = un128
        .wrapping_mul(B)
        .wrapping_add(un1)
        .wrapping_sub(q1.wrapping_mul(v.get()));

    // Compute the second quotient digit. Same 128/64 optimization.
    q0 = if (un21 >> 64) as u64 >= vn1_u64 {
        B - 1
    } else {
        un21 / (vn1_u64 as u128)
    };
    rhat = un21 - q0 * vn1_val;

    // The estimate is at most two greater than the true quotient digit, so at
    // most two corrections are required. Once `rhat >= B`, the correction
    // condition is necessarily false.
    while rhat < B && q0 * vn0 > B * rhat + un0 {
        q0 -= 1;
        rhat += vn1_val;
    }

    *r = (un21
        .wrapping_mul(B)
        .wrapping_add(un0)
        .wrapping_sub(q0.wrapping_mul(v.get())))
        >> s;
    q1 * B + q0
}

// These stay as unit tests because their inputs intentionally target private
// branches in the manual u128 half-word and Knuth-D implementations.
#[cfg(test)]
mod tests {
    use crate::BigUint;

    use super::{DivRemScalar, DivWide};

    /// Force the quotient estimate to clamp at the half-word radix.
    #[test]
    fn u128_div_wide_handles_clamped_quotient_estimate() {
        const B: u128 = 1 << 64;

        let divisor = u128::MAX;
        let hi = (B - 1) * B + 1;

        // Since 2^128 = divisor + 1 and hi < divisor, the quotient of
        // hi * 2^128 by divisor is hi, with remainder hi.
        assert_eq!(u128::div_wide(0, hi, divisor), hi);
    }

    /// Prefilled output detects partial writes in the u128 fast exits.
    #[test]
    fn u128_special_cases_clear_the_full_quotient() {
        for (dividend, divisor, expected_quotient) in
            [([3u128, 5, 7], 1, [3, 5, 7]), ([0u128; 3], 17, [0; 3])]
        {
            let mut quotient = [u128::MAX; 3];
            let remainder = u128::div_rem_scalar(&dividend, divisor, &mut quotient);

            assert_eq!(quotient, expected_quotient);
            assert_eq!(remainder, 0);
        }
    }

    /// Reconstruct dividend = quotient * divisor + remainder using separate limb arithmetic.
    fn assert_division_identity(dividend: &[u128], divisor: u128) {
        let mut quotient = vec![u128::MAX; dividend.len()];
        let remainder = u128::div_rem_scalar(dividend, divisor, &mut quotient);
        let quotient = BigUint(&quotient[..]);
        let mut reconstructed = BigUint(vec![0u128; dividend.len()]);

        assert_eq!(quotient.mul_value_to(divisor, &mut reconstructed), 0);
        assert!(!reconstructed.add_value_assign(remainder));
        assert_eq!(reconstructed.digits(), dividend);
        assert!(remainder < divisor);
    }

    /// Full and half-word divisors select both manual kernels, including trimmed high limbs.
    #[test]
    fn u128_half_word_and_knuth_paths_are_self_consistent() {
        let cases: &[(&[u128], u128)] = &[
            (
                &[
                    0xfedc_ba98_7654_3210_dead_beef_cafe_babe,
                    0x0123_4567_89ab_cdef_1122_3344_5566_7788,
                    0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
                ],
                0xc0ff_ee15_dead_beef_face_b00c_1337_4242,
            ),
            (
                &[
                    0xdead_beef_cafe_babe_1234_5678_9abc_def0,
                    0x0001_0203_0405_0607_0809_0a0b_0c0d_0e0f,
                    0,
                ],
                (1u128 << 64) | 0x1234_5678_9abc_def1,
            ),
            (
                &[
                    0xfedc_ba98_7654_3210_0fed_cba9_8765_4321,
                    0x1234_5678_9abc_def0_0123_4567_89ab_cdef,
                ],
                0xdead_beef_cafe_babe,
            ),
        ];

        for &(dividend, divisor) in cases {
            assert_division_identity(dividend, divisor);
        }
    }
}
