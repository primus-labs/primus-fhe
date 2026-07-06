use aligned_vec::AVec;

/// Build pre-expanded root vectors for AVX2 T2/T1 stages (u64 lanes).
///
/// `inverse` controls traversal direction.
pub(in crate::ntt::prime64) fn build_avx2_roots_u64(
    n: usize,
    roots: &[u64],
    inverse: bool,
) -> AVec<u64> {
    // n < 16 -> scalar fallback, no pre-expanded data needed.
    if n < 16 {
        return AVec::with_capacity(64, 0);
    }
    let mut out = AVec::with_capacity(64, (n / 4) * 4);
    let mut ri = 1usize;
    let (mut t, mut m) = if inverse {
        (1usize, n >> 1)
    } else {
        (n >> 1, 1usize)
    };
    loop {
        if t >= 4 {
            ri += n / (2 * t); // T4: broadcast, skip
        } else {
            match t {
                2 => {
                    for _ in 0..(n / 8) {
                        let w_a = roots[ri];
                        let w_b = roots[ri + 1];
                        ri += 2;
                        out.push(w_a);
                        out.push(w_a);
                        out.push(w_b);
                        out.push(w_b);
                    }
                }
                1 => {
                    for _ in 0..(n / 8) {
                        let w0 = roots[ri];
                        let w1 = roots[ri + 1];
                        let w2 = roots[ri + 2];
                        let w3 = roots[ri + 3];
                        ri += 4;
                        out.push(w3);
                        out.push(w2);
                        out.push(w1);
                        out.push(w0);
                    }
                }
                _ => unreachable!(),
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
