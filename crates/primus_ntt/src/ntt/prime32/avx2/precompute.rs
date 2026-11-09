use aligned_vec::AVec;

fn extend_t4_roots(out: &mut AVec<u32>, roots: &[u32]) {
    for &root in roots {
        out.extend_from_slice(&[root; 4]);
    }
}

fn extend_t2_roots(out: &mut AVec<u32>, roots: &[u32]) {
    let (root_quads, remainder) = roots.as_chunks::<4>();
    debug_assert!(remainder.is_empty());
    for &[w0, w1, w2, w3] in root_quads {
        out.extend_from_slice(&[w0, w0, w2, w2, w1, w1, w3, w3]);
    }
}

fn extend_t1_roots(out: &mut AVec<u32>, roots: &[u32]) {
    let (root_octets, remainder) = roots.as_chunks::<8>();
    debug_assert!(remainder.is_empty());
    for &[w0, w1, w2, w3, w4, w5, w6, w7] in root_octets {
        out.extend_from_slice(&[w0, w1, w4, w5, w2, w3, w6, w7]);
    }
}

/// Build pre-expanded root vectors for AVX2 T4/T2/T1 stages.
///
/// Forward roots start at the canonical T4 region (`n / 8`) and use stage
/// order T4/T2/T1. Inverse roots start at index 1 and use T1/T2/T4.
pub(in crate::ntt::prime32) fn build_avx2_roots_u32(
    n: usize,
    roots: &[u32],
    inverse: bool,
) -> AVec<u32> {
    // The caller derives n from the shared checked polynomial length.
    debug_assert!(n >= 32);
    debug_assert_eq!(roots.len(), n);

    let mut out = AVec::with_capacity(32, 3 * n / 2);

    if inverse {
        let (t1_roots, roots) = roots[1..].split_at(n / 2);
        let (t2_roots, roots) = roots.split_at(n / 4);
        let (t4_roots, _) = roots.split_at(n / 8);
        extend_t1_roots(&mut out, t1_roots);
        extend_t2_roots(&mut out, t2_roots);
        extend_t4_roots(&mut out, t4_roots);
    } else {
        let (t4_roots, roots) = roots[n / 8..].split_at(n / 8);
        let (t2_roots, t1_roots) = roots.split_at(n / 4);
        extend_t4_roots(&mut out, t4_roots);
        extend_t2_roots(&mut out, t2_roots);
        extend_t1_roots(&mut out, t1_roots);
    }
    out
}
