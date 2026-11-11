//! Four native-modulus rotations sharing one aggregate traversal.

use primus_fft::TorusFftValue;

/// Adds four controls in the coefficient domain. The caller establishes equal
/// polynomial-aligned lengths, power-of-two n and exponents in [0,2n). Source
/// order and wrapping native arithmetic match two consecutive pair updates.
#[inline]
pub(super) fn add_four_rotations_assign<T: TorusFftValue>(
    acc: &mut [T],
    sources: [&[T]; 4],
    exponents: [usize; 4],
    n: usize,
) {
    debug_assert!(n.is_power_of_two());
    debug_assert_eq!(acc.len() & (n - 1), 0);
    debug_assert!(sources.iter().all(|s| s.len() == acc.len()));
    debug_assert!(exponents.iter().all(|&e| e < 2 * n));
    let shifts = exponents.map(|e| e & (n - 1));
    let mut boundaries = shifts;
    boundaries.sort_unstable();
    let mut start = 0;
    // Four wrap points divide each polynomial into at most five contiguous
    // intervals. Signs are constant within an interval, shared by all levels.
    for end in boundaries.into_iter().chain([n]) {
        if start == end {
            continue;
        }
        let offsets = shifts.map(|shift| start.wrapping_sub(shift) & (n - 1));
        let mut negatives = 0u8;
        for i in 0..4 {
            negatives |= u8::from((exponents[i] >= n) ^ (start < shifts[i])) << i;
        }
        // Specialize signs before the coefficient loop, as in the pair kernel.
        match negatives {
            0 => add_segment::<T, 0>(acc, sources, offsets, start..end, n),
            1 => add_segment::<T, 1>(acc, sources, offsets, start..end, n),
            2 => add_segment::<T, 2>(acc, sources, offsets, start..end, n),
            3 => add_segment::<T, 3>(acc, sources, offsets, start..end, n),
            4 => add_segment::<T, 4>(acc, sources, offsets, start..end, n),
            5 => add_segment::<T, 5>(acc, sources, offsets, start..end, n),
            6 => add_segment::<T, 6>(acc, sources, offsets, start..end, n),
            7 => add_segment::<T, 7>(acc, sources, offsets, start..end, n),
            8 => add_segment::<T, 8>(acc, sources, offsets, start..end, n),
            9 => add_segment::<T, 9>(acc, sources, offsets, start..end, n),
            10 => add_segment::<T, 10>(acc, sources, offsets, start..end, n),
            11 => add_segment::<T, 11>(acc, sources, offsets, start..end, n),
            12 => add_segment::<T, 12>(acc, sources, offsets, start..end, n),
            13 => add_segment::<T, 13>(acc, sources, offsets, start..end, n),
            14 => add_segment::<T, 14>(acc, sources, offsets, start..end, n),
            _ => add_segment::<T, 15>(acc, sources, offsets, start..end, n),
        }
        start = end;
    }
}

/// All five streams are contiguous inside each interval; each accumulator
/// coefficient is loaded/stored once, with contributions in their original order.
#[inline]
fn add_segment<T: TorusFftValue, const NEGATIVES: u8>(
    acc: &mut [T],
    sources: [&[T]; 4],
    offsets: [usize; 4],
    range: std::ops::Range<usize>,
    n: usize,
) {
    let [a, b, c, d] = sources;
    let length = range.len();
    for ((((acc, a), b), c), d) in acc
        .chunks_exact_mut(n)
        .zip(a.chunks_exact(n))
        .zip(b.chunks_exact(n))
        .zip(c.chunks_exact(n))
        .zip(d.chunks_exact(n))
    {
        let a = &a[offsets[0]..offsets[0] + length];
        let b = &b[offsets[1]..offsets[1] + length];
        let c = &c[offsets[2]..offsets[2] + length];
        let d = &d[offsets[3]..offsets[3] + length];
        for ((((acc, &a), &b), &c), &d) in acc[range.clone()].iter_mut().zip(a).zip(b).zip(c).zip(d)
        {
            let value = if NEGATIVES & 1 == 0 {
                acc.wrapping_add(a)
            } else {
                acc.wrapping_sub(a)
            };
            let value = if NEGATIVES & 2 == 0 {
                value.wrapping_add(b)
            } else {
                value.wrapping_sub(b)
            };
            let value = if NEGATIVES & 4 == 0 {
                value.wrapping_add(c)
            } else {
                value.wrapping_sub(c)
            };
            *acc = if NEGATIVES & 8 == 0 {
                value.wrapping_add(d)
            } else {
                value.wrapping_sub(d)
            };
        }
    }
}
