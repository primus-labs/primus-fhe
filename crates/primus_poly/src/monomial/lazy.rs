//! Monomial accumulation with a redundant Barrett residue range.

use primus_integer::FheUint;
use primus_modulus::BarrettModulus;

/// Adds two negacyclic rotations to every polynomial of a flat coefficient batch,
/// retaining residues in `[0, 2q)` for `q = modulus.value()`.
///
/// Each pair needs one conditional correction. Sources remain canonical; the
/// accumulator may stay lazy across calls. Before an operation that requires
/// canonical input, normalize it with
/// [`reduce_once_slice_assign`](primus_reduce::ReduceOnceSlice::reduce_once_slice_assign).
/// No allocation or scratch is required. Component order is preserved.
///
/// # Correctness
///
/// `N = poly_length` must be a nonzero power of two. All slices must have equal
/// lengths containing complete length-`N` polynomials; empty batches are allowed.
/// Both exponents must be in `[0, 2N)`. Sources must be in `[0, q)` and the
/// initialized accumulator in `[0, 2q)`. The Barrett modulus's two spare bits
/// bound all intermediate values below `4q`, including negative rotations.
///
/// # Panics
///
/// Panics if `poly_length` is zero. Debug builds also check layouts and exponent
/// ranges. Violating the contract can panic after partial writes in release builds.
#[inline]
pub fn lazy_add_mul_monomial_pair_assign<T: FheUint>(
    acc: &mut [T],
    first: &[T],
    first_exponent: usize,
    second: &[T],
    second_exponent: usize,
    poly_length: usize,
    modulus: BarrettModulus<T>,
) {
    let n = poly_length;
    let q = modulus.value();
    assert_ne!(n, 0, "polynomial length must be nonzero");
    debug_assert!(n.is_power_of_two(), "invalid polynomial length");
    debug_assert!(
        first_exponent < 2 * n && second_exponent < 2 * n,
        "monomial exponent must be less than 2N"
    );
    debug_assert_eq!(acc.len(), first.len(), "coefficient batch length mismatch");
    debug_assert_eq!(acc.len(), second.len(), "coefficient batch length mismatch");
    debug_assert_eq!(acc.len() & (n - 1), 0, "incomplete coefficient polynomial");
    let [a_shift, b_shift] = [first_exponent & (n - 1), second_exponent & (n - 1)];
    let [a_negative, b_negative] = [first_exponent >= n, second_exponent >= n];
    let mut start = 0;
    // Same intervals and traversal as the canonical u64 pair kernel.
    for end in [a_shift.min(b_shift), a_shift.max(b_shift), n] {
        if start == end {
            continue;
        }
        let a_start = start.wrapping_sub(a_shift) & (n - 1);
        let b_start = start.wrapping_sub(b_shift) & (n - 1);
        let ranges = [
            start..end,
            a_start..a_start + end - start,
            b_start..b_start + end - start,
        ];
        match (
            a_negative ^ (start < a_shift),
            b_negative ^ (start < b_shift),
        ) {
            (false, false) => add_segment::<_, false, false>(acc, first, second, &ranges, n, q),
            (false, true) => add_segment::<_, false, true>(acc, first, second, &ranges, n, q),
            (true, false) => add_segment::<_, true, false>(acc, first, second, &ranges, n, q),
            (true, true) => add_segment::<_, true, true>(acc, first, second, &ranges, n, q),
        }
        start = end;
    }
}

/// Signs and contiguous source intervals are fixed outside the coefficient loop.
/// Adding q for each negative source avoids underflow; every intermediate is
/// below 4q, so only one subtraction of 2q is needed after the pair.
#[inline]
fn add_segment<T: FheUint, const A_NEG: bool, const B_NEG: bool>(
    acc: &mut [T],
    first: &[T],
    second: &[T],
    ranges: &[std::ops::Range<usize>; 3],
    n: usize,
    q: T,
) {
    let two_q = q + q;
    let bias = (if A_NEG { q } else { T::ZERO }) + (if B_NEG { q } else { T::ZERO });
    // Keep the canonical pair kernel's slice traversal here: polynomial-view
    // iterators regressed measured u64 sparse PBS with otherwise identical work.
    for ((acc, a), b) in acc
        .chunks_exact_mut(n)
        .zip(first.chunks_exact(n))
        .zip(second.chunks_exact(n))
    {
        for ((acc, &a), &b) in acc[ranges[0].clone()]
            .iter_mut()
            .zip(&a[ranges[1].clone()])
            .zip(&b[ranges[2].clone()])
        {
            let value = *acc + bias;
            let value = if A_NEG { value - a } else { value + a };
            let value = if B_NEG { value - b } else { value + b };
            *acc = value.min(value.wrapping_sub(two_q));
        }
    }
}

/// Adds one negacyclic rotation to every polynomial of a flat coefficient batch,
/// retaining residues in `[0, 2q)` for `q = modulus.value()`.
///
/// This handles an odd tail after [`lazy_add_mul_monomial_pair_assign`] without
/// first normalizing the accumulator. No allocation or scratch is required.
///
/// # Correctness
///
/// `N = poly_length` must be a nonzero power of two. Both slices must have equal
/// lengths containing complete length-`N` polynomials; empty batches are allowed.
/// The exponent must be in `[0, 2N)`, source coefficients in `[0, q)`, and the
/// initialized accumulator in `[0, 2q)`. Normalize the output before passing it
/// to an operation that requires canonical coefficients.
///
/// # Panics
///
/// Panics if `poly_length` is zero. Debug builds also check layouts and exponent
/// range. Violating the contract can panic after partial writes in release builds.
#[inline]
pub fn lazy_add_mul_monomial_assign<T: FheUint>(
    acc: &mut [T],
    source: &[T],
    exponent: usize,
    poly_length: usize,
    modulus: BarrettModulus<T>,
) {
    let n = poly_length;
    let q = modulus.value();
    assert_ne!(n, 0, "polynomial length must be nonzero");
    debug_assert!(n.is_power_of_two(), "invalid polynomial length");
    debug_assert_eq!(acc.len(), source.len(), "coefficient batch length mismatch");
    debug_assert_eq!(acc.len() & (n - 1), 0, "incomplete coefficient polynomial");
    debug_assert!(exponent < 2 * n, "monomial exponent must be less than 2N");
    let shift = exponent & (n - 1);
    for (acc, source) in acc.chunks_exact_mut(n).zip(source.chunks_exact(n)) {
        let (prefix, suffix) = acc.split_at_mut(shift);
        let (source_prefix, source_suffix) = source.split_at(n - shift);
        if exponent < n {
            add_single_segment::<_, true>(prefix, source_suffix, q);
            add_single_segment::<_, false>(suffix, source_prefix, q);
        } else {
            add_single_segment::<_, false>(prefix, source_suffix, q);
            add_single_segment::<_, true>(suffix, source_prefix, q);
        }
    }
}

/// A single source leaves values below 3q before the same 2q correction.
#[inline]
fn add_single_segment<T: FheUint, const NEG: bool>(acc: &mut [T], source: &[T], q: T) {
    let two_q = q + q;
    for (acc, &source) in acc.iter_mut().zip(source) {
        let value = if NEG {
            *acc + q - source
        } else {
            *acc + source
        };
        *acc = value.min(value.wrapping_sub(two_q));
    }
}
