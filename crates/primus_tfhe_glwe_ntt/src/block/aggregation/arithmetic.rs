//! Bounded unreduced accumulation of rotated Block selectors.

use primus_integer::FheUint;
use primus_lattice::GadgetSize;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_poly::Polynomial;
use primus_reduce::Reduce;

/// Coefficient count for a 16 KiB tile, rounded to whole polynomials (at least one).
/// Workspace allocation and aggregation must agree on whether a GGSW needs reuse.
#[inline]
pub(super) fn tile_len<T>(poly_length: usize) -> usize {
    (16 * 1024 / size_of::<T>() / poly_length).max(1) * poly_length
}

/// Largest group satisfying (2m+1)q <= T::MAX. The caller selects a complete
/// group or bounded batches according to the coefficient word width.
#[inline]
pub(super) fn max_group_len<T: FheUint>(q: T) -> usize {
    let count: u128 = ((T::MAX / q - T::ONE) / T::TWO).as_into();
    count.min(usize::MAX as u128) as usize
}

/// Disjoint mutable aggregate and immutable exponents for one input. A view can
/// cover a whole GGSW or one polynomial-aligned tile; it owns no allocation.
pub(super) struct AggregationLane<'a, T> {
    /// u64 rotation descriptors in the aggregation call's four-index group order.
    /// Each entry must match this lane's exponents, the current control group and
    /// polynomial length; reuse is limited to that group's tiles.
    /// A partial prefix is valid: remaining groups use on-demand addressing.
    /// u32 always passes an empty slice.
    pub(super) prepared: &'a [FourRotations],
    pub(super) exponents: &'a [usize],
    pub(super) coefficients: &'a mut [T],
}

/// Visit each source tile across all lanes before advancing through the key.
/// Each coordinate corresponds to a selector in the supplied group.
/// Batch scheduling reuses the single-input arithmetic and reduction boundaries:
/// bounded batches for u32, a whole-group bias or lazy pairs for u64.
pub(super) fn aggregate_controls_many_assign<T: FheUint, const LANES: usize>(
    indices: impl ExactSizeIterator<Item = usize> + Clone,
    selections: &[T],
    lanes: &mut [AggregationLane<'_, T>; LANES],
    size: GadgetSize,
    modulus: BarrettModulus<T>,
) {
    if T::BITS == 64 {
        aggregate_controls_u64_many_assign(indices, selections, lanes, size, modulus);
        return;
    }
    let count = indices.len();
    let n = size.glwe_size().poly_length().get();
    let control_len = size.ggsw_len();
    // Bound the working set to whole polynomials; each lane has its own tile.
    let tile_len = tile_len::<T>(n);
    let capacity = max_group_len(modulus.value());
    let u32_batch_len = capacity.min(28) & !3;
    for start in (0..control_len).step_by(tile_len) {
        let end = (start + tile_len).min(control_len);
        let mut tiles = lanes.each_mut().map(|lane| AggregationLane {
            prepared: &[],
            exponents: lane.exponents,
            coefficients: &mut lane.coefficients[start..end],
        });
        let mut indices = indices.clone();
        if count >= 4 && u32_batch_len != 0 {
            // Canonical in/out for every bounded batch, including its short tail.
            for selections in selections.chunks(u32_batch_len * control_len) {
                let count = selections.len() / control_len;
                add_rotated_group_many_assign(
                    indices.by_ref().take(count),
                    selections,
                    &mut tiles,
                    start,
                    size,
                    modulus,
                );
            }
        } else {
            // Short groups and moduli without four-source headroom stay canonical.
            for (index, source) in indices.zip(selections.chunks_exact(control_len)) {
                for lane in &mut tiles {
                    for (acc, source) in lane
                        .coefficients
                        .chunks_exact_mut(n)
                        .zip(source[start..end].chunks_exact(n))
                    {
                        Polynomial(acc).add_mul_monomial_assign(
                            &Polynomial(source),
                            lane.exponents[index],
                            modulus,
                        );
                    }
                }
            }
        }
    }
}

/// Adds a bounded group to canonical tiles, restoring canonical residues at the
/// end. The key/workspace establish layouts and indices.len() <= max_group_len(q).
/// An m*q bias keeps every intermediate in [0,(2m+1)q); the proof applies per lane.
#[inline]
fn add_rotated_group_many_assign<T: FheUint, const LANES: usize>(
    indices: impl ExactSizeIterator<Item = usize>,
    selections: &[T],
    lanes: &mut [AggregationLane<'_, T>; LANES],
    tile_start: usize,
    size: GadgetSize,
    modulus: BarrettModulus<T>,
) {
    debug_assert!(indices.len() <= max_group_len(modulus.value()));
    let n = size.glwe_size().poly_length().get();
    let control_len = size.ggsw_len();
    let tile_end = tile_start + lanes[0].coefficients.len();
    let bias = T::as_from(indices.len()) * modulus.value();
    for lane in lanes.iter_mut() {
        for value in lane.coefficients.iter_mut() {
            *value += bias;
        }
    }
    // Native kernels need no q correction: the group bound prevents actual wrapping.
    // Share each four-source key tile across lanes; their rotation exponents differ.
    let mut indices = indices;
    let mut selection_groups = selections.chunks_exact(4 * control_len);
    for group in selection_groups.by_ref() {
        let indices: [usize; 4] = std::array::from_fn(|_| indices.next().expect("control index"));
        let sources = std::array::from_fn(|i| {
            &group[i * control_len + tile_start..i * control_len + tile_end]
        });
        for lane in lanes.iter_mut() {
            add_four_rotations_assign(
                lane.coefficients,
                sources,
                indices.map(|i| lane.exponents[i]),
                n,
            );
        }
    }
    let mut selection_pairs = selection_groups.remainder().chunks_exact(2 * control_len);
    for pair in selection_pairs.by_ref() {
        let indices: [usize; 2] = std::array::from_fn(|_| indices.next().expect("control index"));
        let (a, b) = pair.split_at(control_len);
        for lane in lanes.iter_mut() {
            primus_poly::add_mul_monomial_pair_assign(
                lane.coefficients,
                &a[tile_start..tile_end],
                lane.exponents[indices[0]],
                &b[tile_start..tile_end],
                lane.exponents[indices[1]],
                n,
                NativeModulus::new(),
            );
        }
    }
    if let Some(index) = indices.next() {
        let source = &selection_pairs.remainder()[tile_start..tile_end];
        for lane in lanes.iter_mut() {
            for (acc, source) in lane
                .coefficients
                .chunks_exact_mut(n)
                .zip(source.chunks_exact(n))
            {
                Polynomial(acc).add_mul_monomial_assign(
                    &Polynomial(source),
                    lane.exponents[index],
                    NativeModulus::new(),
                );
            }
        }
    }
    for lane in lanes {
        reduce_group_assign(lane.coefficients, modulus);
    }
}

/// Aggregates one already initialized control ciphertext using the single-input
/// tile schedule. The caller supplies exponents in selector order.
#[inline]
pub(crate) fn aggregate_controls_assign<T: FheUint>(
    exponents: impl ExactSizeIterator<Item = usize> + Clone,
    selections: &[T],
    rotation_groups: &mut [FourRotations],
    aggregate: &mut [T],
    size: GadgetSize,
    modulus: BarrettModulus<T>,
) {
    let count = exponents.len();
    let n = size.glwe_size().poly_length().get();
    let control_len = size.ggsw_len();
    let tile_length = tile_len::<T>(n);
    let group_capacity = max_group_len(modulus.value());
    let u32_batch_len = group_capacity.min(28) & !3;
    let use_groups = T::BITS == 64 && count >= 4 && count <= group_capacity;
    let prepared_count = if use_groups {
        rotation_groups.len().min(count / 4)
    } else {
        0
    };
    let prepared = &mut rotation_groups[..prepared_count];
    let mut group_exponents = exponents.clone();
    for plan in prepared.iter_mut() {
        *plan = FourRotations::new(
            std::array::from_fn(|_| group_exponents.next().expect("control exponent")),
            n,
        );
    }
    for (tile_index, tile) in aggregate.chunks_mut(tile_length).enumerate() {
        let start = tile_index * tile_length;
        let end = start + tile.len();
        let mut tile_exponents = exponents.clone();
        if T::BITS == 32 && count >= 4 && u32_batch_len != 0 {
            // Each batch begins and ends canonical, including the final tail.
            for selections in selections.chunks(u32_batch_len * control_len) {
                let count = selections.len() / control_len;
                add_rotated_group_assign(
                    tile_exponents.by_ref().take(count),
                    selections,
                    &[],
                    tile,
                    start,
                    size,
                    modulus,
                );
            }
        } else if T::BITS != 64 {
            for (exponent, selection) in tile_exponents.zip(selections.chunks_exact(control_len)) {
                for (acc, source) in tile
                    .chunks_exact_mut(n)
                    .zip(selection[start..end].chunks_exact(n))
                {
                    Polynomial(acc).add_mul_monomial_assign(&Polynomial(source), exponent, modulus);
                }
            }
        } else if use_groups {
            add_rotated_group_assign(
                tile_exponents,
                selections,
                prepared,
                tile,
                start,
                size,
                modulus,
            );
        } else {
            // Retain the original [0,2q) lazy pair/single fallback. Ordinary NTT
            // receives canonical residues only after the complete control sum.
            let mut pairs = selections.chunks_exact(2 * control_len);
            for pair in pairs.by_ref() {
                let (a, b) = pair.split_at(control_len);
                primus_poly::lazy_add_mul_monomial_pair_assign(
                    tile,
                    &a[start..end],
                    tile_exponents.next().expect("control exponent"),
                    &b[start..end],
                    tile_exponents.next().expect("control exponent"),
                    n,
                    modulus,
                );
            }
            if let Some(exponent) = tile_exponents.next() {
                primus_poly::lazy_add_mul_monomial_assign(
                    tile,
                    &pairs.remainder()[start..end],
                    exponent,
                    n,
                    modulus,
                );
            }
        }
    }
    if T::BITS == 64 && !use_groups {
        use primus_reduce::ReduceOnceSlice;
        modulus.reduce_once_slice_assign(aggregate);
    }
}

/// Consumes actual exponents in selector order.
/// The exact-size iterator and selections have one entry per control. Dispatch
/// and address preparation remain outside the coefficient loops.
///
/// The caller establishes matching layouts and m <= max_group_len(q). Starting
/// from canonical residues, an m*q bias bounds every prefix by [0,(2m+1)q),
/// including negative rotations; one final reduction restores canonical output.
/// Nonempty u64 plans match the same exponents, in complete four-control groups,
/// and are reused only across this sum's tiles. u32 passes no plans.
#[inline]
fn add_rotated_group_assign<T: FheUint>(
    exponents: impl ExactSizeIterator<Item = usize>,
    selections: &[T],
    prepared: &[FourRotations],
    acc: &mut [T],
    tile_start: usize,
    size: GadgetSize,
    modulus: BarrettModulus<T>,
) {
    let count = exponents.len();
    debug_assert!(count <= max_group_len(modulus.value()));
    let n = size.glwe_size().poly_length().get();
    let control_len = size.ggsw_len();
    let tile_end = tile_start + acc.len();
    let bias = T::as_from(count) * modulus.value();
    for value in acc.iter_mut() {
        *value += bias;
    }

    // Native kernels provide word addition/subtraction with no q correction.
    // The proven bound prevents actual wrapping; final reduction is modulo q.
    // Prepared groups need no repeated exponent lookup. Skip their prefix once
    // so only immediate groups and the pair/single tail consume the iterator.
    let prepared_count = if T::BITS == 64 {
        prepared.len().min(count / 4)
    } else {
        0
    };
    let mut exponents = exponents.skip(4 * prepared_count);
    let mut selection_groups = selections.chunks_exact(4 * control_len);
    for (group_index, group) in selection_groups.by_ref().enumerate() {
        let sources = std::array::from_fn(|i| {
            &group[i * control_len + tile_start..i * control_len + tile_end]
        });
        if T::BITS == 64 {
            // Single-tile u64 needs no group-wide preparation or retained plans.
            // Build only the current group's addressing and consume it immediately;
            // both u64 cases then use one shared coefficient loop.
            let immediate;
            let rotations = if let Some(rotations) = prepared.get(group_index) {
                rotations
            } else {
                immediate = FourRotations::new(
                    std::array::from_fn(|_| exponents.next().expect("control exponent")),
                    n,
                );
                &immediate
            };
            rotations.add_assign(acc, sources, n);
        } else {
            add_four_rotations_assign(
                acc,
                sources,
                std::array::from_fn(|_| exponents.next().expect("control exponent")),
                n,
            );
        }
    }
    let mut selection_pairs = selection_groups.remainder().chunks_exact(2 * control_len);
    for pair in selection_pairs.by_ref() {
        let first_exponent = exponents.next().expect("control exponent");
        let second_exponent = exponents.next().expect("control exponent");
        let (a, b) = pair.split_at(control_len);
        primus_poly::add_mul_monomial_pair_assign(
            acc,
            &a[tile_start..tile_end],
            first_exponent,
            &b[tile_start..tile_end],
            second_exponent,
            n,
            NativeModulus::new(),
        );
    }
    if let Some(exponent) = exponents.next() {
        let source = &selection_pairs.remainder()[tile_start..tile_end];
        for (acc, source) in acc.chunks_exact_mut(n).zip(source.chunks_exact(n)) {
            Polynomial(acc).add_mul_monomial_assign(
                &Polynomial(source),
                exponent,
                NativeModulus::new(),
            );
        }
    }
    reduce_group_assign(acc, modulus);
}

/// Canonicalizes a bounded group before its next batch or the ordinary NTT entry.
/// u64 uses the measured reciprocal kernel where its instruction set is available;
/// other cases use Barrett reduction.
#[inline]
fn reduce_group_assign<T: FheUint>(values: &mut [T], modulus: BarrettModulus<T>) {
    #[cfg(target_arch = "x86_64")]
    if T::BITS == 64
        && std::is_x86_feature_detected!("avx512f")
        && std::is_x86_feature_detected!("avx512dq")
    {
        // SAFETY: the required CPU features were checked. The kernel uses safe
        // slice iteration; the caller established a 64-bit coefficient type.
        unsafe { reduce_group_u64_assign(values, modulus) };
        return;
    }
    for value in values {
        *value = modulus.reduce(*value);
    }
}

/// For `B=2^64`, `ratio[1]=floor(B/q)`. Its high product estimates `floor(x/q)`
/// from below with error at most one. Omitting the low-low 32-bit product loses
/// at most one more, so x-estimate*q is in [0,3q). Two corrections suffice.
/// The partial-product sum fits u64, and Barrett's q<B/4 keeps 3q below B.
/// Expressing the three 32-bit products directly lets LLVM vectorize the loop.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512dq")]
unsafe fn reduce_group_u64_assign<T: FheUint>(values: &mut [T], modulus: BarrettModulus<T>) {
    debug_assert_eq!(T::BITS, 64);
    let q: u64 = modulus.value().as_into();
    let reciprocal: u64 = modulus.ratio()[1].as_into();
    for value in values {
        let x: u64 = (*value).as_into();
        let low_high = (x & 0xffff_ffff) * (reciprocal >> 32);
        let high_low = (x >> 32) * (reciprocal & 0xffff_ffff);
        let high_high = (x >> 32) * (reciprocal >> 32);
        let quotient = high_high + (low_high >> 32) + (((low_high & 0xffff_ffff) + high_low) >> 32);
        let remainder = x - quotient * q;
        let remainder = remainder.min(remainder.wrapping_sub(2 * q));
        *value = T::as_from(remainder.min(remainder.wrapping_sub(q)));
    }
}

/// Adds four controls in the coefficient domain. The caller establishes equal
/// polynomial-aligned lengths, power-of-two n and exponents in [0,2n). Source
/// order matches two consecutive pair updates. The group bias bounds
/// every prefix, so the wrapping operations below do not actually wrap.
#[inline]
fn add_four_rotations_assign<T: FheUint>(
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

/// One interval in which all four rotated source streams are contiguous and
/// have constant signs. The coefficient arithmetic is shared with the on-demand path.
#[derive(Clone, Copy, Default)]
struct RotationSegment {
    offsets: [usize; 4],
    start: usize,
    end: usize,
    negatives: u8,
}

/// Input-dependent addressing for four controls, reused across a group's tiles.
/// Empty trailing segments represent coincident wrap points, including shift zero.
#[derive(Clone, Default)]
pub(crate) struct FourRotations {
    segments: [RotationSegment; 5],
}

impl FourRotations {
    pub(super) fn new(exponents: [usize; 4], n: usize) -> Self {
        let mut segments = rotation_segments(exponents, n);
        Self {
            segments: std::array::from_fn(|_| segments.next().unwrap_or_default()),
        }
    }

    #[inline]
    fn add_assign<T: FheUint>(&self, acc: &mut [T], sources: [&[T]; 4], n: usize) {
        for &segment in &self.segments {
            if segment.start != segment.end {
                add_rotation_segment(acc, sources, segment, n);
            }
        }
    }
}

/// Four wrap points split a polynomial into at most five nonempty intervals.
/// Prepared once per group; the original on-demand kernel retains its code shape.
#[inline]
fn rotation_segments(exponents: [usize; 4], n: usize) -> impl Iterator<Item = RotationSegment> {
    let shifts = exponents.map(|e| e & (n - 1));
    let mut boundaries = shifts;
    boundaries.sort_unstable();
    let mut start = 0;
    boundaries.into_iter().chain([n]).filter_map(move |end| {
        if start == end {
            return None;
        }
        let offsets = shifts.map(|shift| start.wrapping_sub(shift) & (n - 1));
        let mut negatives = 0u8;
        for i in 0..4 {
            negatives |= u8::from((exponents[i] >= n) ^ (start < shifts[i])) << i;
        }
        let segment = RotationSegment {
            offsets,
            start,
            end,
            negatives,
        };
        start = end;
        Some(segment)
    })
}

/// Select signs outside the coefficient loop; both addressing paths use exactly
/// the same four-source arithmetic and polynomial traversal.
#[inline]
fn add_rotation_segment<T: FheUint>(
    acc: &mut [T],
    sources: [&[T]; 4],
    segment: RotationSegment,
    n: usize,
) {
    match segment.negatives {
        0 => add_segment::<T, 0>(acc, sources, segment.offsets, segment.start..segment.end, n),
        1 => add_segment::<T, 1>(acc, sources, segment.offsets, segment.start..segment.end, n),
        2 => add_segment::<T, 2>(acc, sources, segment.offsets, segment.start..segment.end, n),
        3 => add_segment::<T, 3>(acc, sources, segment.offsets, segment.start..segment.end, n),
        4 => add_segment::<T, 4>(acc, sources, segment.offsets, segment.start..segment.end, n),
        5 => add_segment::<T, 5>(acc, sources, segment.offsets, segment.start..segment.end, n),
        6 => add_segment::<T, 6>(acc, sources, segment.offsets, segment.start..segment.end, n),
        7 => add_segment::<T, 7>(acc, sources, segment.offsets, segment.start..segment.end, n),
        8 => add_segment::<T, 8>(acc, sources, segment.offsets, segment.start..segment.end, n),
        9 => add_segment::<T, 9>(acc, sources, segment.offsets, segment.start..segment.end, n),
        10 => add_segment::<T, 10>(acc, sources, segment.offsets, segment.start..segment.end, n),
        11 => add_segment::<T, 11>(acc, sources, segment.offsets, segment.start..segment.end, n),
        12 => add_segment::<T, 12>(acc, sources, segment.offsets, segment.start..segment.end, n),
        13 => add_segment::<T, 13>(acc, sources, segment.offsets, segment.start..segment.end, n),
        14 => add_segment::<T, 14>(acc, sources, segment.offsets, segment.start..segment.end, n),
        _ => add_segment::<T, 15>(acc, sources, segment.offsets, segment.start..segment.end, n),
    }
}

/// All five streams are contiguous inside each interval; each accumulator
/// coefficient is loaded/stored once, with contributions in their original order.
#[inline]
fn add_segment<T: FheUint, const NEGATIVES: u8>(
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

/// u64 tile traversal preserving the single-input whole-group bias/reduction
/// boundary, or its original lazy-pair fallback. Only the
/// order of independent lane operations changes: tile -> source group -> lane.
/// Key coefficients stay canonical and are read through borrowed tile slices.
fn aggregate_controls_u64_many_assign<T: FheUint, const LANES: usize>(
    indices: impl ExactSizeIterator<Item = usize> + Clone,
    selections: &[T],
    lanes: &mut [AggregationLane<'_, T>; LANES],
    size: GadgetSize,
    modulus: BarrettModulus<T>,
) {
    debug_assert_eq!(T::BITS, 64);
    let n = size.glwe_size().poly_length().get();
    let control_len = size.ggsw_len();
    let count = indices.len();
    let use_groups = count >= 4 && count <= max_group_len(modulus.value());
    for start in (0..control_len).step_by(tile_len::<T>(n)) {
        let end = (start + tile_len::<T>(n)).min(control_len);
        let mut indices = indices.clone();
        if use_groups {
            // Same m*q bound as add_rotated_group_assign, independently per lane.
            let bias = T::as_from(count) * modulus.value();
            for lane in lanes.iter_mut() {
                for value in &mut lane.coefficients[start..end] {
                    *value += bias;
                }
            }
            let mut selection_groups = selections.chunks_exact(4 * control_len);
            for (group_index, group) in selection_groups.by_ref().enumerate() {
                let indices: [usize; 4] =
                    std::array::from_fn(|_| indices.next().expect("control index"));
                let sources =
                    std::array::from_fn(|i| &group[i * control_len + start..i * control_len + end]);
                // Borrow one source tile, consume it for all lanes before moving
                // forward. Descriptors/signs and accumulator writes remain private.
                for lane in lanes.iter_mut() {
                    let immediate;
                    let rotations = if let Some(plan) = lane.prepared.get(group_index) {
                        plan
                    } else {
                        immediate = FourRotations::new(indices.map(|i| lane.exponents[i]), n);
                        &immediate
                    };
                    rotations.add_assign(&mut lane.coefficients[start..end], sources, n);
                }
            }
            let mut selection_pairs = selection_groups.remainder().chunks_exact(2 * control_len);
            for pair in selection_pairs.by_ref() {
                let indices: [usize; 2] =
                    std::array::from_fn(|_| indices.next().expect("control index"));
                let (a, b) = pair.split_at(control_len);
                for lane in lanes.iter_mut() {
                    primus_poly::add_mul_monomial_pair_assign(
                        &mut lane.coefficients[start..end],
                        &a[start..end],
                        lane.exponents[indices[0]],
                        &b[start..end],
                        lane.exponents[indices[1]],
                        n,
                        NativeModulus::new(),
                    );
                }
            }
            if let Some(index) = indices.next() {
                let source = &selection_pairs.remainder()[start..end];
                for lane in lanes.iter_mut() {
                    for (acc, source) in lane.coefficients[start..end]
                        .chunks_exact_mut(n)
                        .zip(source.chunks_exact(n))
                    {
                        Polynomial(acc).add_mul_monomial_assign(
                            &Polynomial(source),
                            lane.exponents[index],
                            NativeModulus::new(),
                        );
                    }
                }
            }
            for lane in lanes.iter_mut() {
                reduce_group_assign(&mut lane.coefficients[start..end], modulus);
            }
        } else {
            // Do not replace the single-input fallback by a differently grouped
            // sum. Keep its [0,2q) pair/single arithmetic and final one correction.
            let mut selection_pairs = selections.chunks_exact(2 * control_len);
            for pair in selection_pairs.by_ref() {
                let indices: [usize; 2] =
                    std::array::from_fn(|_| indices.next().expect("control index"));
                let (a, b) = pair.split_at(control_len);
                for lane in lanes.iter_mut() {
                    primus_poly::lazy_add_mul_monomial_pair_assign(
                        &mut lane.coefficients[start..end],
                        &a[start..end],
                        lane.exponents[indices[0]],
                        &b[start..end],
                        lane.exponents[indices[1]],
                        n,
                        modulus,
                    );
                }
            }
            if let Some(index) = indices.next() {
                let source = &selection_pairs.remainder()[start..end];
                for lane in lanes.iter_mut() {
                    primus_poly::lazy_add_mul_monomial_assign(
                        &mut lane.coefficients[start..end],
                        source,
                        lane.exponents[index],
                        n,
                        modulus,
                    );
                }
            }
        }
    }
    if !use_groups {
        use primus_reduce::ReduceOnceSlice;
        for lane in lanes {
            modulus.reduce_once_slice_assign(lane.coefficients);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primus_decompose::DecompositionLevelCount;
    use primus_lattice::{GlweDimension, GlweSize};
    use primus_shape::PolyLength;

    // Independent signed-integer rotation covers sign intervals, repeated wrap
    // points, four/pair/single tails, nonzero tile starts and near-capacity sums.
    #[test]
    fn rotated_groups_match_integer_oracle() {
        for q in [
            65537u64,
            (1 << 30) - 35,
            1_125_899_906_826_241,
            (1 << 60) - 93,
            u64::MAX / 9,
        ] {
            check_rotations(q, false);
        }
    }

    #[test]
    fn u32_batches_match_integer_oracle() {
        for q in [
            65_537u32,
            67_104_769,
            134_215_681,
            (1 << 28) - 57,
            u32::MAX / 9,
        ] {
            check_rotations(q, true);
        }
    }

    // Independent lane/sign oracle for the new schedule, including multiple
    // tiles, immediate/prepared descriptors and moduli without four-source headroom.
    #[test]
    fn lane_tile_schedules_match_integer_oracle() {
        for q in [1_125_899_906_826_241u64, u64::MAX / 9] {
            check_lane_tile_schedules(q);
        }
        for q in [67_104_769u32, 134_215_681, u32::MAX / 9] {
            check_lane_tile_schedules(q);
        }
    }

    fn check_lane_tile_schedules<T: FheUint>(q: T) {
        let modulus = BarrettModulus::new(q);
        let q: u64 = q.as_into();
        for n in [32, 512] {
            let size = GadgetSize::new(
                GlweSize::new(GlweDimension::new(1), PolyLength::new(n)),
                DecompositionLevelCount::new(2),
            );
            let len = size.ggsw_len();
            for m in [0, 1, 3, 4, 7, 9, 29] {
                let indices: Vec<_> = (0..m).rev().collect();
                let exponents: [Vec<_>; 4] = std::array::from_fn(|lane| {
                    (0..m)
                        .map(|i| (i * 17 + lane * (n - 1)) & (2 * n - 1))
                        .collect()
                });
                let sources: Vec<_> = (0..m * len)
                    .map(|i| match i % 3 {
                        0 => 0,
                        1 => q - 1,
                        _ => (i as u64).wrapping_mul(0x9e3779b97f4a7c15) % q,
                    })
                    .collect();
                let initial: Vec<_> = (0..len)
                    .map(|i| if i & 1 == 0 { 0 } else { q - 1 })
                    .collect();
                let expected: [Vec<_>; 4] = exponents.each_ref().map(|exponents| {
                    let mut result: Vec<_> = initial.iter().map(|&x| i128::from(x)).collect();
                    for (&index, source) in indices.iter().zip(sources.chunks_exact(len)) {
                        for (out, poly) in result.chunks_exact_mut(n).zip(source.chunks_exact(n)) {
                            for (i, &x) in poly.iter().enumerate() {
                                let dest = i + exponents[index];
                                out[dest & (n - 1)] += if dest & n == 0 {
                                    i128::from(x)
                                } else {
                                    -i128::from(x)
                                };
                            }
                        }
                    }
                    result
                        .into_iter()
                        .map(|x| x.rem_euclid(i128::from(q)) as u64)
                        .collect()
                });
                let sources: Vec<T> = sources.into_iter().map(T::as_from).collect();
                let initial: Vec<T> = initial.into_iter().map(T::as_from).collect();
                let expected: [Vec<T>; 4] =
                    expected.map(|values| values.into_iter().map(T::as_from).collect());
                let prepared_counts: &[usize] = if T::BITS == 64 {
                    &[0, 1, usize::MAX]
                } else {
                    &[0]
                };
                for &prepared_count in prepared_counts {
                    let plans: [Vec<_>; 4] = exponents.each_ref().map(|exponents| {
                        if prepared_count != 0 {
                            indices
                                .as_chunks::<4>()
                                .0
                                .iter()
                                .take(prepared_count)
                                .map(|group| FourRotations::new(group.map(|i| exponents[i]), n))
                                .collect()
                        } else {
                            Vec::new()
                        }
                    });
                    let mut actual: [_; 4] = std::array::from_fn(|_| initial.clone());
                    let mut lane_index = 0;
                    let mut lanes = actual.each_mut().map(|coefficients| {
                        let lane = lane_index;
                        lane_index += 1;
                        AggregationLane {
                            prepared: &plans[lane],
                            exponents: &exponents[lane],
                            coefficients,
                        }
                    });
                    aggregate_controls_many_assign(
                        indices.iter().copied(),
                        &sources,
                        &mut lanes,
                        size,
                        modulus,
                    );
                    assert_eq!(actual, expected, "q={q} n={n} m={m} plans={prepared_count}");
                }
            }
        }
    }

    fn check_rotations<T: FheUint>(q: T, batches: bool) {
        let modulus = BarrettModulus::new(q);
        let capacity = if batches { 67 } else { max_group_len(q) };
        let batch_len = if batches {
            max_group_len(q).min(28) & !3
        } else {
            capacity
        };
        let q: u64 = q.as_into();
        for n in [32usize, 64] {
            let size = GadgetSize::new(
                GlweSize::new(GlweDimension::new(1), PolyLength::new(n)),
                DecompositionLevelCount::new(2),
            );
            let len = size.ggsw_len();
            // Capacity boundaries, all four-source tails, and repeated batches.
            for m in (0..=17)
                .chain([27, 28, 29, 30, 31, 32, 55, 56, 57, 58, 59, 67])
                .filter(|&m| m <= capacity)
            {
                // The last two patterns hit the largest positive/negative
                // prefixes with q-1 at every source coefficient.
                for pattern in 0..18 {
                    let indices: Vec<_> = (0..m).rev().collect();
                    let exponents: Vec<_> = (0..m)
                        .map(|i| {
                            if pattern >= 16 {
                                return (pattern - 16) * n;
                            }
                            let shift = match (i + pattern) % 5 {
                                0 => 0,
                                1 => 1,
                                2 => n - 1,
                                3 => n / 2,
                                _ => n / 2,
                            };
                            shift + if (pattern >> (i & 3)) & 1 != 0 { n } else { 0 }
                        })
                        .collect();
                    let sources: Vec<_> = (0..m * len)
                        .map(|i| match if pattern >= 16 { 1 } else { i % 4 } {
                            0 => 0,
                            1 => q - 1,
                            2 => q / 2,
                            _ => (i as u64).wrapping_mul(0x9e3779b97f4a7c15) % q,
                        })
                        .collect();
                    let initial: Vec<_> = (0..len)
                        .map(|i| if i & 1 == 0 { 0 } else { q - 1 })
                        .collect();
                    let mut expected: Vec<i128> = initial.iter().map(|&x| i128::from(x)).collect();
                    for (&index, src) in indices.iter().zip(sources.chunks_exact(len)) {
                        let exponent = exponents[index];
                        for (out, poly) in expected.chunks_exact_mut(n).zip(src.chunks_exact(n)) {
                            for (i, &x) in poly.iter().enumerate() {
                                let dest = i + exponent;
                                out[dest % n] += if (dest / n) & 1 == 0 {
                                    i128::from(x)
                                } else {
                                    -i128::from(x)
                                };
                            }
                        }
                    }
                    let expected: Vec<_> = expected
                        .into_iter()
                        .map(|x| x.rem_euclid(i128::from(q)) as u64)
                        .collect();
                    let sources: Vec<T> = sources.into_iter().map(T::as_from).collect();
                    let mut candidate: Vec<T> = initial.into_iter().map(T::as_from).collect();
                    for tile_start in (0..len).step_by(2 * n) {
                        let range = tile_start..tile_start + 2 * n;
                        let group_len = batch_len.min(m.max(1));
                        for (indices, sources) in indices
                            .chunks(group_len)
                            .zip(sources.chunks(group_len * len))
                        {
                            add_rotated_group_assign(
                                indices.iter().map(|&index| exponents[index]),
                                sources,
                                &[],
                                &mut candidate[range.clone()],
                                tile_start,
                                size,
                                modulus,
                            );
                        }
                    }
                    if !batches {
                        let prepared: Vec<_> = indices
                            .as_chunks::<4>()
                            .0
                            .iter()
                            .map(|indices| FourRotations::new(indices.map(|i| exponents[i]), n))
                            .collect();
                        // A reused workspace may retain fewer plans than the
                        // current block; the remaining groups are prepared on demand.
                        for prepared in [&prepared[..prepared.len().min(1)], &prepared[..]] {
                            let mut reused: Vec<T> = (0..len)
                                .map(|i| T::as_from(if i & 1 == 0 { 0 } else { q - 1 }))
                                .collect();
                            for tile_start in (0..len).step_by(2 * n) {
                                add_rotated_group_assign(
                                    indices.iter().map(|&index| exponents[index]),
                                    &sources,
                                    prepared,
                                    &mut reused[tile_start..tile_start + 2 * n],
                                    tile_start,
                                    size,
                                    modulus,
                                );
                            }
                            assert_eq!(
                                reused,
                                candidate,
                                "prepared addressing q={q} n={n} m={m} pattern={pattern} plans={}",
                                prepared.len()
                            );
                        }
                    }
                    let candidate: Vec<u64> = candidate.into_iter().map(|x| x.as_into()).collect();
                    assert_eq!(
                        candidate, expected,
                        "oracle q={q} n={n} m={m} pattern={pattern}"
                    );
                }
            }
        }
    }
}
