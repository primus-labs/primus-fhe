//! Validated coefficient-layout algorithms shared by the two NTRU backends.
//! Arithmetic and normalization remain explicit; automorphism closures allocate nothing.

use primus_integer::FheUint;
use primus_reduce::RingContext;

use crate::NtruCiphertext;

pub(super) fn check_count(n: usize, count: usize) -> usize {
    assert!(
        count.is_power_of_two() && count <= n,
        "coefficient count must be a power-of-two divisor of N"
    );
    (n.trailing_zeros() - count.trailing_zeros()) as usize
}

/// Keys are indexed by descending degree N+1,N/2+1,...,3. The caller has
/// validated both N-coefficient buffers and the number of available keys.
pub(super) fn trace_assign<T, M, H, F, const REVERSE: bool>(
    output: &mut [T],
    levels: usize,
    scratch: &mut [T],
    modulus: M,
    halve: H,
    mut auto: F,
) where
    T: FheUint,
    M: RingContext<T>,
    H: Fn(&mut [T]),
    F: FnMut(usize, &[T], &mut [T]),
{
    for step in 0..levels {
        let index = if REVERSE { levels - 1 - step } else { step };
        if REVERSE {
            halve(output);
        }
        auto(index, output, scratch);
        modulus.reduce_add_slice_assign(output, scratch);
    }
}

/// Expands a validated power-of-two count using output as the entire tree.
/// At depth j, live block i contains residue class i modulo 2^j shifted to zero.
/// The caller owns the target-message zero-tail condition for constant outputs.
pub(super) fn expand_to<T, M, H, F>(
    input: &[T],
    output: &mut [T],
    scratch: &mut [T],
    modulus: M,
    normalize: H,
    mut auto: F,
) where
    T: FheUint,
    M: RingContext<T>,
    H: Fn(&mut [T]),
    F: FnMut(usize, &[T], &mut [T]),
{
    let n = input.len();
    let count = output.len() / n;
    output[..n].copy_from_slice(input);
    // Normalize before key-switch errors enter the unscaled tree. Later
    // modular inverses would alter their error distribution.
    normalize(&mut output[..n]);
    for depth in 0..count.trailing_zeros() as usize {
        let live = 1 << depth;
        let (left, right) = output[..2 * live * n].split_at_mut(live * n);
        for (even, odd) in left.chunks_exact_mut(n).zip(right.chunks_exact_mut(n)) {
            auto(depth, even, scratch);
            odd.copy_from_slice(even);
            modulus.reduce_sub_slice_assign(odd, scratch);
            NtruCiphertext::new(odd).mul_monomial_assign(2 * n - live, modulus);
            modulus.reduce_add_slice_assign(even, scratch);
        }
    }
}
