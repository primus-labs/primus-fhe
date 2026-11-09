use aligned_vec::AVec;

fn extend_t2_roots(out: &mut AVec<u64>, roots: &[u64]) {
    for &root in roots {
        out.extend_from_slice(&[root; 2]);
    }
}

fn extend_t1_roots(out: &mut AVec<u64>, roots: &[u64]) {
    let (root_quads, remainder) = roots.as_chunks::<4>();
    debug_assert!(remainder.is_empty());
    for root_quad in root_quads {
        for &root in root_quad.iter().rev() {
            out.push(root);
        }
    }
}

/// Build pre-expanded root vectors for AVX2 T2/T1 stages (u64 lanes).
///
/// Forward roots start at the canonical T2 region (`n / 4`) and use stage
/// order T2/T1. Inverse roots start at index 1 and use T1/T2.
pub(in crate::ntt::prime64) fn build_avx2_roots_u64(
    n: usize,
    roots: &[u64],
    inverse: bool,
) -> AVec<u64> {
    if n < 16 {
        return AVec::with_capacity(64, 0);
    }
    debug_assert_eq!(roots.len(), n);

    let mut out = AVec::with_capacity(64, n);

    if inverse {
        let (t1_roots, roots) = roots[1..].split_at(n / 2);
        let (t2_roots, _) = roots.split_at(n / 4);
        extend_t1_roots(&mut out, t1_roots);
        extend_t2_roots(&mut out, t2_roots);
    } else {
        let (t2_roots, t1_roots) = roots[n / 4..].split_at(n / 4);
        extend_t2_roots(&mut out, t2_roots);
        extend_t1_roots(&mut out, t1_roots);
    }
    out
}
