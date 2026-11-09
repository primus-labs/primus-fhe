//! Integer SIMD for canonical Barrett multiply-add slices.
//!
//! Kernels use or derive their reciprocal from the scalar two-limb reciprocal.
//! There is no key-dependent precomputation or change to residue representation.
use super::BarrettModulus;
use primus_integer::FheUint;

#[inline]
pub(super) fn try_add_mul<T: FheUint, const FIXED_MODULUS: bool>(
    modulus: BarrettModulus<T>,
    acc: &mut [T],
    lhs: &[T],
    rhs: &[T],
) -> bool {
    try_mul_add::<T, FIXED_MODULUS, false>(modulus, acc, lhs, rhs, None)
}

#[inline]
pub(super) fn try_mul_add_to<T: FheUint, const FIXED_MODULUS: bool>(
    modulus: BarrettModulus<T>,
    lhs: &[T],
    rhs: &[T],
    addend: &[T],
    output: &mut [T],
) -> bool {
    try_mul_add::<T, FIXED_MODULUS, true>(modulus, output, lhs, rhs, Some(addend))
}

// The optional addend preserves disjoint slice borrows for overwrite operations.
// OVERWRITE specializes the loops: assign reads acc, while to reads only addend.
// No shared reference to acc is constructed alongside its mutable borrow.
// Expose eligibility to constant-modulus callers before considering a kernel.
#[inline(always)]
fn try_mul_add<T: FheUint, const FIXED_MODULUS: bool, const OVERWRITE: bool>(
    modulus: BarrettModulus<T>,
    acc: &mut [T],
    lhs: &[T],
    rhs: &[T],
    addend: Option<&[T]>,
) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        use std::any::TypeId;
        // This bridge only proves the concrete type and preserves slice borrows.
        // Each typed entry owns its eligibility, length and CPU checks.
        macro_rules! dispatch_type {
            ($t:ty, $entry:ident) => {
                if TypeId::of::<T>() == TypeId::of::<$t>() {
                    // SAFETY: TypeId proves the exact primitive type, including
                    // size/alignment. Borrowing preserves length and disjointness.
                    let (acc, lhs, rhs) = unsafe {
                        (
                            std::slice::from_raw_parts_mut(
                                acc.as_mut_ptr().cast::<$t>(),
                                acc.len(),
                            ),
                            std::slice::from_raw_parts(lhs.as_ptr().cast::<$t>(), lhs.len()),
                            std::slice::from_raw_parts(rhs.as_ptr().cast::<$t>(), rhs.len()),
                        )
                    };
                    // SAFETY: the same exact-type proof applies to the optional
                    // shared addend; its lifetime and length are preserved.
                    let addend = addend.map(|values| unsafe {
                        std::slice::from_raw_parts(values.as_ptr().cast::<$t>(), values.len())
                    });
                    let q: $t = modulus.value().as_into();
                    let ratio = modulus.ratio().map(|x| x.as_into());
                    let modulus = BarrettModulus::<$t>::from_parts(q, ratio);
                    return avx512::$entry::<FIXED_MODULUS, OVERWRITE>(
                        modulus, acc, lhs, rhs, addend,
                    );
                }
            };
        }
        dispatch_type!(u32, try_add_mul_u32);
        dispatch_type!(u64, try_add_mul_u64);
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = (modulus, acc, lhs, rhs, addend);
    false
}

#[cfg(target_arch = "x86_64")]
mod avx512 {
    // Private kernels require their target features, valid Barrett parts and
    // equal-length canonical operands. OVERWRITE additionally requires Some
    // addend of that length; otherwise acc supplies the canonical addend.
    // The typed dispatchers establish all lengths before any raw vector access.

    use super::BarrettModulus;
    use primus_reduce::ReduceMulAdd;
    use std::arch::x86_64::*;

    const MIN_NATIVE_LEN: usize = 32;
    pub(super) const IFMA_MODULUS_LIMIT: u64 = 1 << 50;

    #[inline(always)]
    pub(super) fn try_add_mul_u32<const FIXED_MODULUS: bool, const OVERWRITE: bool>(
        modulus: BarrettModulus<u32>,
        acc: &mut [u32],
        lhs: &[u32],
        rhs: &[u32],
        addend: Option<&[u32]>,
    ) -> bool {
        // Fixed-modulus eligibility precedes length checks so an ineligible
        // derive folds directly to its original constant-modulus fallback.
        if FIXED_MODULUS && modulus.value().is_power_of_two() {
            return false;
        }
        if acc.len() < MIN_NATIVE_LEN {
            return false;
        }
        assert_eq!(acc.len(), lhs.len(), "multiply-add length mismatch");
        assert_eq!(acc.len(), rhs.len(), "multiply-add length mismatch");
        if OVERWRITE {
            assert_eq!(
                acc.len(),
                addend.unwrap().len(),
                "multiply-add length mismatch"
            );
        }
        if !is_x86_feature_detected!("avx512f") {
            return false;
        }
        // SAFETY: AVX-512F is available and the slices have equal lengths.
        unsafe { add_mul_u32::<OVERWRITE>(modulus, acc, lhs, rhs, addend) };
        true
    }

    #[inline(always)]
    pub(super) fn try_add_mul_u64<const FIXED_MODULUS: bool, const OVERWRITE: bool>(
        modulus: BarrettModulus<u64>,
        acc: &mut [u64],
        lhs: &[u64],
        rhs: &[u64],
        addend: Option<&[u64]>,
    ) -> bool {
        let q = modulus.value();
        // Preserve constant arithmetic for powers of two and large moduli;
        // this check must fold away before introducing length/ISA dispatch.
        if FIXED_MODULUS && (q.is_power_of_two() || q >= IFMA_MODULUS_LIMIT) {
            return false;
        }
        if acc.len() < MIN_NATIVE_LEN {
            return false;
        }
        assert_eq!(acc.len(), lhs.len(), "multiply-add length mismatch");
        assert_eq!(acc.len(), rhs.len(), "multiply-add length mismatch");
        if OVERWRITE {
            assert_eq!(
                acc.len(),
                addend.unwrap().len(),
                "multiply-add length mismatch"
            );
        }
        if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("avx512dq") {
            return false;
        }
        if q < IFMA_MODULUS_LIMIT && is_x86_feature_detected!("avx512ifma") {
            // SAFETY: F/DQ/IFMA, the modulus bound and equal lengths are checked.
            unsafe { add_mul_u64_ifma::<OVERWRITE>(modulus, acc, lhs, rhs, addend) };
        } else if FIXED_MODULUS {
            // Without IFMA, derives retain their scalar/portable constant loop.
            return false;
        } else {
            // SAFETY: AVX-512F/DQ and equal slice lengths are checked above.
            unsafe { add_mul_u64_dq::<OVERWRITE>(modulus, acc, lhs, rhs, addend) };
        }
        true
    }

    // Truncated Barrett with radix 2^52, inspired by HEXL's variable-operand
    // IFMA multiplication. For k=bit_width(q), s=k-2 and U=a*b, use
    // mu=floor(2^(k+50)/q), t=floor(U/2^s), h=floor(t*mu/2^52).
    // Both t and mu fit in 52 bits. The error before rounding h down is
    // < 2^s/q + t/2^52 < 1/2 + 1, so 0 <= U-h*q < 3q.
    // Adding canonical acc gives a value below 4q < 2^52; subtracting 2q
    // and then q conditionally yields the canonical result. This keeps the
    // addend out of the wide product and needs no carry between 52-bit limbs.
    // Keep one shared function per output form rather than duplicating the
    // large loop inside each PBS caller.
    #[inline(never)]
    #[target_feature(enable = "avx512f,avx512dq,avx512ifma")]
    pub(super) unsafe fn add_mul_u64_ifma<const OVERWRITE: bool>(
        modulus: BarrettModulus<u64>,
        acc: &mut [u64],
        lhs: &[u64],
        rhs: &[u64],
        addend: Option<&[u64]>,
    ) {
        debug_assert_eq!(acc.len(), lhs.len());
        debug_assert_eq!(acc.len(), rhs.len());
        debug_assert!(modulus.value() < IFMA_MODULUS_LIMIT);
        let q = modulus.value();
        let k = u64::BITS - q.leading_zeros();
        let [low, high] = modulus.ratio();
        // floor(floor(2^128/q) / 2^(78-k)) == floor(2^(k+50)/q).
        // The batch setup only shifts the existing reciprocal; no division.
        let reciprocal = (((u128::from(high) << 64) | u128::from(low)) >> (78 - k)) as u64;
        let mu = _mm512_set1_epi64(reciprocal as i64);
        let vq = _mm512_set1_epi64(q as i64);
        let twice_q = _mm512_set1_epi64((2 * q) as i64);
        let neg_q = _mm512_set1_epi64(-(q as i64));
        let low_mask = _mm512_set1_epi64((1 << 52) - 1);
        let right_shift = _mm512_set1_epi64(i64::from(k - 2));
        let left_shift = _mm512_set1_epi64(i64::from(54 - k));
        let zero = _mm512_setzero_si512();
        let end = acc.len() / 8 * 8;
        for i in (0..end).step_by(8) {
            // SAFETY: the dispatch boundary checked equal lengths, and each
            // vector lies wholly in its slice. No alignment beyond u64 is used.
            unsafe {
                let a = _mm512_loadu_si512(lhs.as_ptr().add(i).cast());
                let b = _mm512_loadu_si512(rhs.as_ptr().add(i).cast());
                let c_ptr = if OVERWRITE {
                    addend.unwrap().as_ptr()
                } else {
                    acc.as_ptr()
                };
                let c = _mm512_loadu_si512(c_ptr.add(i).cast());
                let lo = _mm512_madd52lo_epu64(zero, a, b);
                let hi = _mm512_madd52hi_epu64(zero, a, b);
                let truncated = _mm512_or_si512(
                    _mm512_srlv_epi64(lo, right_shift),
                    _mm512_sllv_epi64(hi, left_shift),
                );
                let quotient = _mm512_madd52hi_epu64(zero, truncated, mu);
                let residue =
                    _mm512_and_si512(_mm512_madd52lo_epu64(lo, quotient, neg_q), low_mask);
                let value = normalize(normalize(_mm512_add_epi64(residue, c), twice_q), vq);
                _mm512_storeu_si512(acc.as_mut_ptr().add(i).cast(), value);
            }
        }
        if end != acc.len() {
            // Reuse the DQ kernel for at most seven elements. Inlining the
            // scalar u128 expression here can make LLVM emit a masked vector
            // tail with lane extraction and a large stack frame for this kernel.
            // SAFETY: DQ is enabled above; the remaining slices are equal in length.
            unsafe {
                add_mul_u64_dq::<OVERWRITE>(
                    modulus,
                    &mut acc[end..],
                    &lhs[end..],
                    &rhs[end..],
                    if OVERWRITE {
                        Some(&addend.unwrap()[end..])
                    } else {
                        None
                    },
                )
            };
        }
    }

    #[inline(always)]
    fn mul_low32(a: u64, b: u64) -> u64 {
        (a & 0xffff_ffff) * (b & 0xffff_ffff)
    }

    // Fuse c into the 32-bit partial products instead of adding it to a
    // completed 128-bit product. Every intermediate sum fits in u64, even
    // for full-width inputs; the returned pair is (low, high) of a*b+c.
    #[inline(always)]
    fn carrying_mul(a: u64, b: u64, c: u64) -> (u64, u64) {
        let p0 = mul_low32(a, b) + (c & 0xffff_ffff);
        let p1 = mul_low32(a, b >> 32) + (c >> 32);
        let p2 = mul_low32(a >> 32, b);
        let p3 = mul_low32(a >> 32, b >> 32);
        let s1 = p1 + (p0 >> 32);
        let s2 = (s1 & 0xffff_ffff) + p2;
        (
            (p0 & 0xffff_ffff) | (s2 << 32),
            p3 + (s1 >> 32) + (s2 >> 32),
        )
    }

    // Omitting the low-low partial product underestimates mulhi by at most one.
    // The middle sum fits u64: (2^32-1)^2 + (2^32-1) < 2^64.
    #[inline(always)]
    fn mul_hi_approx(a: u64, b: u64) -> u64 {
        let p01 = mul_low32(a, b >> 32);
        let p10 = mul_low32(a >> 32, b);
        let p11 = mul_low32(a >> 32, b >> 32);
        p11 + (p01 >> 32) + (((p01 & 0xffff_ffff) + p10) >> 32)
    }

    // Truncated Barrett, including the addend in U=a*b+c<q^2. For
    // k=bit_width(q)<=62, s=k-2, t=floor(U/2^s), mu=floor(2^(k+62)/q),
    // both t and mu fit u64. Before rounding the quotient, the error is
    // < 2^s/q + t/2^64 < 1.5. Approximate mulhi loses at most one more,
    // hence 0 <= U-qhat*q < 3.5q < 4q < 2^64. Subtract 2q then q.
    // Adding c only after estimation could exceed this four-modulus bound.
    // Keep 32-bit partial products in the target-feature loop so LLVM can
    // vectorize them without scalar u128 multiplication or lane extraction.
    #[target_feature(enable = "avx512f,avx512dq")]
    pub(super) unsafe fn add_mul_u64_dq<const OVERWRITE: bool>(
        modulus: BarrettModulus<u64>,
        acc: &mut [u64],
        lhs: &[u64],
        rhs: &[u64],
        addend: Option<&[u64]>,
    ) {
        debug_assert_eq!(acc.len(), lhs.len());
        debug_assert_eq!(acc.len(), rhs.len());
        let q = modulus.value();
        let k = u64::BITS - q.leading_zeros();
        let [low, high] = modulus.ratio();
        // Shift floor(2^128/q); batch setup needs no division.
        let reciprocal = (((u128::from(high) << 64) | u128::from(low)) >> (66 - k)) as u64;
        let len = acc.len().min(lhs.len()).min(rhs.len());
        // Include the separate addend so LLVM can vectorize the final full block.
        let len = if OVERWRITE {
            len.min(addend.unwrap().len())
        } else {
            len
        };
        for i in 0..len {
            let addend = if OVERWRITE {
                addend.unwrap()[i]
            } else {
                acc[i]
            };
            let (lo, hi) = carrying_mul(lhs[i], rhs[i], addend);
            // When k=2, the left shift count wraps to zero; hi is zero as well.
            let truncated = (lo >> (k - 2)) | hi.wrapping_shl(66 - k);
            let quotient = mul_hi_approx(truncated, reciprocal);
            let value = lo.wrapping_sub(quotient.wrapping_mul(q));
            let value = value.min(value.wrapping_sub(2 * q));
            acc[i] = value.min(value.wrapping_sub(q));
        }
    }

    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn add_mul_u32<const OVERWRITE: bool>(
        modulus: BarrettModulus<u32>,
        acc: &mut [u32],
        lhs: &[u32],
        rhs: &[u32],
        addend: Option<&[u32]>,
    ) {
        debug_assert_eq!(acc.len(), lhs.len());
        debug_assert_eq!(acc.len(), rhs.len());
        // For k=bit_width(q)<=30, x=a*b+c<q^2. Truncated Barrett:
        // qhat = floor(floor(x/2^(k-1))*floor(2^(2k)/q)/2^(k+1)).
        // qhat underestimates floor(x/q) by at most two, so x-qhat*q
        // is in [0,3q). Both factors of the quotient product fit u32:
        // x/2^(k-1)<2^(k+1), and floor(2^(2k)/q)<=2^(k+1).
        // Derive its reciprocal from the existing 64-bit reciprocal;
        // no division, allocation or per-key precomputation is needed.
        unsafe {
            let q = _mm512_set1_epi64(modulus.value() as i64);
            let [low, high] = modulus.ratio();
            let k = u32::BITS - modulus.value().leading_zeros();
            let reciprocal = _mm512_set1_epi64(
                (((u64::from(high) << 32) | u64::from(low)) >> (64 - 2 * k)) as i64,
            );
            let pre_shift = _mm512_set1_epi64(i64::from(k - 1));
            let post_shift = _mm512_set1_epi64(i64::from(k + 1));
            let end = acc.len() / 8 * 8;
            for i in (0..end).step_by(8) {
                let a = load_u32(lhs.as_ptr().add(i));
                let b = load_u32(rhs.as_ptr().add(i));
                let c_ptr = if OVERWRITE {
                    addend.unwrap().as_ptr()
                } else {
                    acc.as_ptr()
                };
                let c = load_u32(c_ptr.add(i));
                let product = _mm512_add_epi64(_mm512_mul_epu32(a, b), c);
                let quotient = _mm512_srlv_epi64(
                    _mm512_mul_epu32(_mm512_srlv_epi64(product, pre_shift), reciprocal),
                    post_shift,
                );
                let value = normalize(
                    normalize(_mm512_sub_epi64(product, _mm512_mul_epu32(quotient, q)), q),
                    q,
                );
                store_u32(acc.as_mut_ptr().add(i), value);
            }
            for (i, ((c, &a), &b)) in acc[end..]
                .iter_mut()
                .zip(&lhs[end..])
                .zip(&rhs[end..])
                .enumerate()
            {
                let addend = if OVERWRITE {
                    addend.unwrap()[end + i]
                } else {
                    *c
                };
                *c = modulus.reduce_mul_add(a, b, addend);
            }
        }
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn normalize(value: __m512i, modulus: __m512i) -> __m512i {
        _mm512_min_epu64(value, _mm512_sub_epi64(value, modulus))
    }
    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn load_u32(ptr: *const u32) -> __m512i {
        unsafe { _mm512_cvtepu32_epi64(_mm256_loadu_si256(ptr.cast())) }
    }
    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn store_u32(ptr: *mut u32, value: __m512i) {
        unsafe {
            _mm256_storeu_si256(ptr.cast(), _mm512_cvtepi64_epi32(value));
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use primus_reduce::ReduceMulAddSlice;

    /// Native dispatch must validate all three sources before exposing a writable output.
    #[test]
    fn overwrite_dispatch_checks_each_input_length_before_writing() {
        macro_rules! check {
            ($t:ty, $q:expr, $available:expr) => {
                if $available {
                    let modulus = BarrettModulus::<$t>::new($q);
                    let values = [1; 32];
                    for short in 0..3 {
                        let mut inputs = [&values[..]; 3];
                        inputs[short] = &values[..31];
                        let mut output = [<$t>::MAX; 32];
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            modulus.reduce_mul_add_slice_to(
                                inputs[0],
                                inputs[1],
                                inputs[2],
                                &mut output,
                            );
                        }));
                        assert!(result.is_err());
                        assert_eq!(output, [<$t>::MAX; 32]);
                    }
                }
            };
        }
        check!(u32, 132_120_577, is_x86_feature_detected!("avx512f"));
        check!(
            u64,
            1_125_899_906_826_241,
            is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512dq")
        );
    }

    /// Direct calls compare every available kernel, including those bypassed by normal dispatch.
    #[test]
    fn native_barrett_kernels_match_wide_remainders() {
        macro_rules! check {
            ($t:ty, $qs:expr, [$(($kernel:ident, $available:expr, $valid:expr)),* $(,)?]) => {
                for q in $qs {
                    let modulus = BarrettModulus::<$t>::new(q);
                    type Kernel = unsafe fn(BarrettModulus<$t>, &mut [$t], &[$t], &[$t], Option<&[$t]>);
                    let mut kernels: Vec<(Kernel, Kernel)> = vec![(
                        |m, out, a, b, _| m.reduce_add_mul_slice_assign(out, a, b),
                        |m, out, a, b, c| m.reduce_mul_add_slice_to(a, b, c.unwrap(), out),
                    )];
                    $(if $available && ($valid)(q) {
                        kernels.push((avx512::$kernel::<false>, avx512::$kernel::<true>));
                    })*
                    // Cover empty/scalar, vector tails, and the 32-element dispatch boundary.
                    // Larger lengths repeat the same kernels; modulus bit boundaries below
                    // are retained because they change reciprocal shifts and corrections.
                    for len in [0, 1, 3, 4, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65] {
                        let mut state = 42u64;
                        let mut sample = || {
                            state ^= state << 13;
                            state ^= state >> 7;
                            state ^= state << 17;
                            (state % u64::from(q)) as $t
                        };
                        let lhs: Vec<_> = (0..len).map(|i| match i % 7 {
                            0 => q - 1, 1 => 0, 2 => 1, _ => sample(),
                        }).collect();
                        let rhs: Vec<_> = (0..len).map(|i| match i % 7 {
                            0 | 2 => q - 1, 1 => 1, _ => sample(),
                        }).collect();
                        let initial: Vec<_> = (0..len).map(|i| match i % 7 {
                            0 | 1 => q - 1, 2 => 0, _ => sample(),
                        }).collect();
                        for (assign, to) in &kernels {
                            // Offset storage exercises unaligned loads and guards both ends.
                            let mut actual = vec![<$t>::MAX; len + 2];
                            actual[1..len+1].copy_from_slice(&initial);
                            let mut output = vec![<$t>::MAX; len + 2];
                            let mut expected = initial.clone();
                            // Reuse the accumulator once to check canonical output feeds the next call.
                            for _ in 0..2 {
                                for ((c, &a), &b) in expected.iter_mut().zip(&lhs).zip(&rhs) {
                                    *c = ((u128::from(a) * u128::from(b) + u128::from(*c)) % u128::from(q)) as $t;
                                }
                                // SAFETY: CPU features verified above; canonical inputs and equal lengths.
                                unsafe {
                                    to(modulus, &mut output[1..len+1], &lhs, &rhs, Some(&actual[1..len+1]));
                                    assign(modulus, &mut actual[1..len+1], &lhs, &rhs, None);
                                }
                                assert_eq!(&actual[1..len+1], expected, "q={q}, len={len}");
                                assert_eq!(&output[1..len+1], expected, "to: q={q}, len={len}");
                                assert_eq!(actual[0], <$t>::MAX);
                                assert_eq!(actual[len+1], <$t>::MAX);
                                assert_eq!(output[0], <$t>::MAX);
                                assert_eq!(output[len+1], <$t>::MAX);
                                // Overwrite must not depend on the old output, even if noncanonical.
                                output[1..len+1].fill(<$t>::MAX);
                            }
                            // Shared read-only operands are allowed; output stays disjoint.
                            unsafe { to(modulus, &mut output[1..len+1], &lhs, &rhs, Some(&lhs)); }
                            for ((&a, &b), &value) in lhs.iter().zip(&rhs).zip(&output[1..len+1]) {
                                assert_eq!(u128::from(value), (u128::from(a) * u128::from(b) + u128::from(a)) % u128::from(q));
                            }
                        }
                    }
                }
            }
        }
        check!(
            u32,
            [2, 3, 97, 132_120_577, (1 << 30) - 1],
            [(add_mul_u32, is_x86_feature_detected!("avx512f"), |_| true)]
        );
        check!(
            u64,
            (2..=61)
                .flat_map(|bits| {
                    let power = 1u64 << bits;
                    [power - 1, power, power + 1]
                })
                .chain([
                    2,
                    97,
                    1_125_899_906_826_241,
                    1_152_921_504_606_830_593,
                    (1 << 62) - 1,
                ]),
            [
                (
                    add_mul_u64_dq,
                    is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512dq"),
                    |_| true
                ),
                (
                    add_mul_u64_ifma,
                    is_x86_feature_detected!("avx512f")
                        && is_x86_feature_detected!("avx512dq")
                        && is_x86_feature_detected!("avx512ifma"),
                    |q| q < avx512::IFMA_MODULUS_LIMIT
                ),
            ]
        );
    }
}
