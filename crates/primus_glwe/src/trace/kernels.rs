//! Coefficient-layout algorithms. Callers validate buffers and supply backend
//! automorphism and halving operations; neither closure allocates.

use primus_integer::FheUint;
use primus_lattice::{GlweSize, glwe::Glwe, lwe::Lwe};
use primus_reduce::RingContext;

pub(super) fn check_degree(n: usize, r: usize) -> usize {
    assert!(
        r.is_power_of_two() && r <= n,
        "coefficient count must be a power-of-two divisor of N"
    );
    (n / r).trailing_zeros() as usize
}

/// Keys are indexed in descending degree order N+1,...,3.
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

/// Packs bit-reversed leaves bottom-up using the paper's even/odd recursion.
/// At width p, output = U + Auto_(p+1)(U) + X^(N/p)*O,
/// where U = (E - X^(N/p)*O)/2. A final partial reverse trace removes
/// coefficients outside the p evenly spaced slots.
#[expect(
    clippy::too_many_arguments,
    reason = "explicit validated layout, buffers and backend kernels"
)]
pub(super) fn pack_to<T, M, H, F>(
    input: &[T],
    output: &mut [T],
    tree: &mut [T],
    scratch: &mut [T],
    size: GlweSize,
    modulus: M,
    halve: H,
    mut auto: F,
) where
    T: FheUint,
    M: RingContext<T>,
    H: Fn(&mut [T]),
    F: FnMut(usize, &[T], &mut [T]),
{
    let glwe_len = size.glwe_len();
    let poly_length = size.poly_length().get();
    let lwe_len = size.mask_len() + 1;
    let count = input.len() / lwe_len;
    let log_count = count.trailing_zeros();
    for (i, leaf) in tree.chunks_exact_mut(glwe_len).enumerate() {
        // A single leaf has no index bits; its full-width checked shift falls back to 0.
        let source = i
            .reverse_bits()
            .checked_shr(usize::BITS - log_count)
            .unwrap_or(0);
        Lwe::new(&input[source * lwe_len..(source + 1) * lwe_len]).inverse_extract_glwe_to(
            &mut Glwe::new(leaf),
            poly_length,
            modulus,
        );
    }
    let mut live = count;
    let mut width = 2;
    while live > 1 {
        let shift = poly_length / width;
        let index = shift.trailing_zeros() as usize;
        for i in 0..live / 2 {
            let start = i * 2 * glwe_len;
            let (even, odd) = tree[start..start + 2 * glwe_len].split_at_mut(glwe_len);
            Glwe::new(&mut *odd).mul_monomial_assign(shift, poly_length, modulus);
            modulus.reduce_sub_slice_assign(even, odd);
            halve(even);
            auto(index, even, scratch);
            modulus.reduce_add_slice_assign(even, scratch);
            modulus.reduce_add_slice_assign(even, odd);
            tree.copy_within(start..start + glwe_len, i * glwe_len);
        }
        live /= 2;
        width *= 2;
    }
    output.copy_from_slice(&tree[..glwe_len]);
    trace_assign::<_, _, _, _, true>(
        output,
        (poly_length / count).trailing_zeros() as usize,
        scratch,
        modulus,
        halve,
        auto,
    );
}

/// Even/odd expansion with input normalization before the tree. At depth j,
/// each live ciphertext contains
/// coefficients in one residue class modulo 2^j, shifted to coefficient zero.
/// Output storage is also the tree; the second half of each butterfly is written
/// directly into its final residue-class block. Output contains count complete
/// GLWEs, where count is a validated power of two in 1..=N. Normalization is by
/// count and only log2(count) levels are evaluated. The caller owns the zero-tail
/// target-message requirement for constant outputs when count < N.
pub(super) fn expand_to<T, M, H, F>(
    input: &[T],
    output: &mut [T],
    scratch: &mut [T],
    size: GlweSize,
    modulus: M,
    normalize: H,
    mut auto: F,
) where
    T: FheUint,
    M: RingContext<T>,
    H: Fn(&mut [T]),
    F: FnMut(usize, &[T], &mut [T]),
{
    let glwe_len = size.glwe_len();
    let poly_length = size.poly_length().get();
    output[..glwe_len].copy_from_slice(input);
    // Normalize before evaluation-key error enters the tree. In the NTT path,
    // this avoids multiplying intermediate key-switch error by modular inverses.
    normalize(&mut output[..glwe_len]);
    let count = output.len() / glwe_len;
    for depth in 0..count.trailing_zeros() as usize {
        let live = 1 << depth;
        let (left, right) = output[..2 * live * glwe_len].split_at_mut(live * glwe_len);
        for (even, odd) in left
            .chunks_exact_mut(glwe_len)
            .zip(right.chunks_exact_mut(glwe_len))
        {
            auto(depth, even, scratch);
            odd.copy_from_slice(even);
            modulus.reduce_sub_slice_assign(odd, scratch);
            Glwe::new(odd).mul_monomial_assign(2 * poly_length - live, poly_length, modulus);
            modulus.reduce_add_slice_assign(even, scratch);
        }
    }
}

/// Monomial projection is shared by ordinary and split trace. The owning
/// boundary has checked indices and exact layouts; each trace overwrites in place.
#[cfg(feature = "fourier")]
pub(super) fn project_to<T: FheUint, M: RingContext<T>>(
    input: Glwe<&[T]>,
    indices: impl Iterator<Item = usize>,
    output: &mut [T],
    size: GlweSize,
    modulus: M,
    mut trace: impl FnMut(&mut [T]),
) {
    let n = size.poly_length().get();
    for (index, mut out) in indices.zip(primus_lattice::glwe::GlweIterMut::new(
        output,
        size.glwe_len(),
    )) {
        input.mul_monomial_to((2 * n - index) & (2 * n - 1), &mut out, n, modulus);
        trace(out.as_mut());
    }
}
