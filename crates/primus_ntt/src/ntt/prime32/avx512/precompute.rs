use aligned_vec::AVec;

fn extend_t8_roots(out: &mut AVec<u32>, roots: &[u32]) {
    for &root in roots {
        out.extend_from_slice(&[root; 8]);
    }
}

fn extend_t4_roots(out: &mut AVec<u32>, roots: &[u32]) {
    for &root in roots {
        out.extend_from_slice(&[root; 4]);
    }
}

fn extend_t2_roots(out: &mut AVec<u32>, roots: &[u32]) {
    let (root_octets, remainder) = roots.as_chunks::<8>();
    debug_assert!(remainder.is_empty());
    for root_octet in root_octets {
        let (low, high) = root_octet.split_at(4);
        for (&low_root, &high_root) in low.iter().zip(high) {
            out.extend_from_slice(&[low_root; 2]);
            out.extend_from_slice(&[high_root; 2]);
        }
    }
}

fn extend_t1_roots(out: &mut AVec<u32>, roots: &[u32]) {
    let (root_blocks, remainder) = roots.as_chunks::<16>();
    debug_assert!(remainder.is_empty());
    for root_block in root_blocks {
        let (low, high) = root_block.split_at(8);
        let (low_pairs, _) = low.as_chunks::<2>();
        let (high_pairs, _) = high.as_chunks::<2>();
        for (low_pair, high_pair) in low_pairs.iter().zip(high_pairs) {
            out.extend_from_slice(low_pair);
            out.extend_from_slice(high_pair);
        }
    }
}

/// Build pre-expanded root vectors for AVX-512 T8/T4/T2/T1 stages.
///
/// Forward roots start at the canonical T8 region (`n / 16`) and use stage
/// order T8/T4/T2/T1. Inverse roots start at index 1 and use T1/T2/T4/T8.
pub(in crate::ntt::prime32) fn build_avx512_roots_u32(
    n: usize,
    roots: &[u32],
    inverse: bool,
) -> AVec<u32> {
    // The caller derives n from the shared checked polynomial length.
    debug_assert!(n >= 32);
    debug_assert_eq!(roots.len(), n);

    let mut out = AVec::with_capacity(64, 2 * n);

    if inverse {
        let (t1_roots, roots) = roots[1..].split_at(n / 2);
        let (t2_roots, roots) = roots.split_at(n / 4);
        let (t4_roots, roots) = roots.split_at(n / 8);
        let (t8_roots, _) = roots.split_at(n / 16);
        extend_t1_roots(&mut out, t1_roots);
        extend_t2_roots(&mut out, t2_roots);
        extend_t4_roots(&mut out, t4_roots);
        extend_t8_roots(&mut out, t8_roots);
    } else {
        let (t8_roots, roots) = roots[n / 16..].split_at(n / 16);
        let (t4_roots, roots) = roots.split_at(n / 8);
        let (t2_roots, t1_roots) = roots.split_at(n / 4);
        extend_t8_roots(&mut out, t8_roots);
        extend_t4_roots(&mut out, t4_roots);
        extend_t2_roots(&mut out, t2_roots);
        extend_t1_roots(&mut out, t1_roots);
    }
    out
}
