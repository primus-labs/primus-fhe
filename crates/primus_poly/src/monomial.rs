mod lazy;

pub use lazy::{lazy_add_mul_monomial_assign, lazy_add_mul_monomial_pair_assign};

use primus_integer::FheUint;
use primus_reduce::{ReduceAdd, ReduceSub};

/// Accumulates `first * X^first_exponent + second * X^second_exponent` into
/// each polynomial of an initialized flat coefficient batch, modulo `X^N + 1`.
///
/// Both contributions share an output traversal, with canonical reduction after
/// each contribution. Rotation offsets are computed once for the batch; each
/// nonempty interval dispatches once across the batch for 64-bit words. Other
/// widths retain polynomial-major traversal. No allocation or scratch is required;
/// component order is preserved.
///
/// # Correctness
///
/// `N = poly_length` must be a nonzero power of two. All slices must have equal
/// lengths containing complete length-`N` polynomials in the same order; an empty
/// batch is allowed. Both exponents must be in `[0, 2N)`. Inputs and the initialized
/// accumulator must be canonical for `modulus`; output remains canonical.
///
/// # Panics
///
/// Panics if `poly_length` is zero. Debug builds also check lengths and exponent
/// ranges. Violating the contract can panic after partial writes in release builds.
#[inline]
pub fn add_mul_monomial_pair_assign<T, M>(
    acc: &mut [T],
    first: &[T],
    first_exponent: usize,
    second: &[T],
    second_exponent: usize,
    poly_length: usize,
    modulus: M,
) where
    T: FheUint,
    M: Copy + ReduceAdd<T, Output = T> + ReduceSub<T, Output = T>,
{
    let n = poly_length;
    assert_ne!(n, 0, "polynomial length must be nonzero");
    debug_assert!(n.is_power_of_two(), "invalid polynomial length");
    debug_assert_eq!(acc.len(), first.len(), "coefficient batch length mismatch");
    debug_assert_eq!(acc.len(), second.len(), "coefficient batch length mismatch");
    debug_assert_eq!(acc.len() & (n - 1), 0, "incomplete coefficient polynomial");
    debug_assert!(
        first_exponent < 2 * n && second_exponent < 2 * n,
        "monomial exponent must be less than 2N"
    );
    let shifts = [first_exponent & (n - 1), second_exponent & (n - 1)];
    let negatives = [first_exponent >= n, second_exponent >= n];
    // Interval-major traversal improved the measured u64 path but regressed
    // u32 sparse PBS. Keep polynomial locality for the other word widths.
    if T::BITS == 64 {
        add_pair_by_segments(acc, first, second, shifts, negatives, n, modulus);
    } else {
        for ((acc, a), b) in acc
            .chunks_exact_mut(n)
            .zip(first.chunks_exact(n))
            .zip(second.chunks_exact(n))
        {
            add_pair_by_segments(acc, a, b, shifts, negatives, n, modulus);
        }
    }
}

// Both shifts are reduced modulo N and their global signs are separate.
// Splitting at the wrap points makes source indices contiguous within a segment.
#[inline]
fn add_pair_by_segments<T, M>(
    acc: &mut [T],
    first: &[T],
    second: &[T],
    [a_shift, b_shift]: [usize; 2],
    [a_negative, b_negative]: [bool; 2],
    n: usize,
    modulus: M,
) where
    T: FheUint,
    M: Copy + ReduceAdd<T, Output = T> + ReduceSub<T, Output = T>,
{
    let mask = n - 1;
    let mut start = 0;
    // The two rotation points split the output into at most three intervals
    // with contiguous sources and fixed signs.
    for end in [a_shift.min(b_shift), a_shift.max(b_shift), n] {
        if start == end {
            continue;
        }
        // Source index is (start - shift) mod N; N is a power of two.
        let a_start = start.wrapping_sub(a_shift) & mask;
        let b_start = start.wrapping_sub(b_shift) & mask;
        let segment_len = end - start;
        let ranges = [
            start..end,
            a_start..a_start + segment_len,
            b_start..b_start + segment_len,
        ];
        let a_subtract = a_negative ^ (start < a_shift);
        let b_subtract = b_negative ^ (start < b_shift);
        // The same signs and source intervals apply to every component.
        // Dispatch once per nonempty interval, outside the polynomial loop.
        match (a_subtract, b_subtract) {
            (false, false) => {
                add_signed_segment::<_, _, false, false>(acc, first, second, &ranges, n, modulus)
            }
            (false, true) => {
                add_signed_segment::<_, _, false, true>(acc, first, second, &ranges, n, modulus)
            }
            (true, false) => {
                add_signed_segment::<_, _, true, false>(acc, first, second, &ranges, n, modulus)
            }
            (true, true) => {
                add_signed_segment::<_, _, true, true>(acc, first, second, &ranges, n, modulus)
            }
        }
        start = end;
    }
}

// The u64 caller supplies the complete polynomial batch; other widths supply
// one polynomial at a time. All three ranges describe the same interval length.
#[inline]
fn add_signed_segment<T, M, const A_NEG: bool, const B_NEG: bool>(
    acc: &mut [T],
    first: &[T],
    second: &[T],
    ranges: &[std::ops::Range<usize>; 3],
    n: usize,
    modulus: M,
) where
    T: FheUint,
    M: Copy + ReduceAdd<T, Output = T> + ReduceSub<T, Output = T>,
{
    if T::BITS != 64 {
        add_signed_coefficients::<_, _, A_NEG, B_NEG>(
            &mut acc[ranges[0].clone()],
            &first[ranges[1].clone()],
            &second[ranges[2].clone()],
            modulus,
        );
        return;
    }
    for ((acc, a), b) in acc
        .chunks_exact_mut(n)
        .zip(first.chunks_exact(n))
        .zip(second.chunks_exact(n))
    {
        add_signed_coefficients::<_, _, A_NEG, B_NEG>(
            &mut acc[ranges[0].clone()],
            &a[ranges[1].clone()],
            &b[ranges[2].clone()],
            modulus,
        );
    }
}

#[inline]
fn add_signed_coefficients<T, M, const A_NEG: bool, const B_NEG: bool>(
    acc: &mut [T],
    a: &[T],
    b: &[T],
    modulus: M,
) where
    T: FheUint,
    M: Copy + ReduceAdd<T, Output = T> + ReduceSub<T, Output = T>,
{
    for ((acc, &a), &b) in acc.iter_mut().zip(a).zip(b) {
        let value = if A_NEG {
            modulus.reduce_sub(*acc, a)
        } else {
            modulus.reduce_add(*acc, a)
        };
        *acc = if B_NEG {
            modulus.reduce_sub(value, b)
        } else {
            modulus.reduce_add(value, b)
        };
    }
}
