use aligned_vec::AVec;

/// Build pre-expanded root vectors for AVX-512 T8/T4/T2/T1 stages.
///
/// `inverse` controls traversal direction (see the AVX2 precompute layout).
pub(in crate::ntt::prime32) fn build_avx512_roots_u32(
    n: usize,
    roots: &[u32],
    inverse: bool,
) -> AVec<u32> {
    // n < 64 -> scalar fallback, no pre-expanded data needed.
    if n < 64 {
        return AVec::with_capacity(64, 0);
    }
    let mut out = AVec::with_capacity(64, (n / 8) * 16);
    let mut ri = 1usize;
    let (mut t, mut m) = if inverse {
        (1usize, n >> 1)
    } else {
        (n >> 1, 1usize)
    };
    loop {
        if t >= 16 {
            ri += n / (2 * t); // T16: broadcast, skip
        } else if t == 8 {
            for _ in 0..(n / 32) {
                let w0 = roots[ri];
                let w1 = roots[ri + 1];
                ri += 2;
                for _ in 0..8 {
                    out.push(w0);
                }
                for _ in 0..8 {
                    out.push(w1);
                }
            }
        } else if t == 4 {
            for _ in 0..(n / 32) {
                for j in 0..4 {
                    let w = roots[ri + j];
                    for _ in 0..4 {
                        out.push(w);
                    }
                }
                ri += 4;
            }
        } else if t == 2 {
            const T2_ROOT_ORDER: [usize; 8] = [0, 4, 1, 5, 2, 6, 3, 7];
            for _ in 0..(n / 32) {
                for j in T2_ROOT_ORDER {
                    let w = roots[ri + j];
                    out.push(w);
                    out.push(w);
                }
                ri += 8;
            }
        } else {
            debug_assert_eq!(t, 1);
            const T1_ROOT_ORDER: [usize; 16] =
                [0, 1, 8, 9, 2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15];
            for _ in 0..(n / 32) {
                for j in T1_ROOT_ORDER {
                    out.push(roots[ri + j]);
                }
                ri += 16;
            }
        }
        if inverse {
            t <<= 1;
            m >>= 1;
        } else {
            t >>= 1;
            m <<= 1;
        }
        if inverse {
            if m < 1 {
                break;
            }
        } else if m >= n {
            break;
        }
    }
    out
}
