use aligned_vec::AVec;

/// Build pre-expanded root vectors for AVX2 T4/T2/T1 stages.
///
/// `inverse` controls traversal direction:
/// - `false` (forward): t decreases from `n/2` down to 1.
/// - `true`  (inverse): t increases from 1 up to `n/2`.
pub(in crate::ntt::prime32) fn build_avx2_roots_u32(
    n: usize,
    roots: &[u32],
    inverse: bool,
) -> AVec<u32> {
    // n < 32 -> scalar fallback, no pre-expanded data needed.
    if n < 32 {
        return AVec::with_capacity(32, 0);
    }
    let mut out = AVec::with_capacity(32, (n / 16) * 24);
    let mut ri = 1usize;
    let (mut t, mut m) = if inverse {
        (1usize, n >> 1)
    } else {
        (n >> 1, 1usize)
    };
    loop {
        if t >= 8 {
            ri += n / (2 * t); // T8: broadcast, skip
        } else {
            match t {
                4 => {
                    for _ in 0..(n / 16) {
                        let w0 = roots[ri];
                        let w1 = roots[ri + 1];
                        ri += 2;
                        for _ in 0..4 {
                            out.push(w0);
                        }
                        for _ in 0..4 {
                            out.push(w1);
                        }
                    }
                }
                2 => {
                    for _ in 0..(n / 16) {
                        let w0 = roots[ri];
                        let w1 = roots[ri + 1];
                        let w2 = roots[ri + 2];
                        let w3 = roots[ri + 3];
                        ri += 4;
                        out.push(w0);
                        out.push(w0);
                        out.push(w2);
                        out.push(w2);
                        out.push(w1);
                        out.push(w1);
                        out.push(w3);
                        out.push(w3);
                    }
                }
                1 => {
                    for _ in 0..(n / 16) {
                        let w0 = roots[ri];
                        let w1 = roots[ri + 1];
                        let w2 = roots[ri + 2];
                        let w3 = roots[ri + 3];
                        let w4 = roots[ri + 4];
                        let w5 = roots[ri + 5];
                        let w6 = roots[ri + 6];
                        let w7 = roots[ri + 7];
                        ri += 8;
                        out.push(w0);
                        out.push(w1);
                        out.push(w4);
                        out.push(w5);
                        out.push(w2);
                        out.push(w3);
                        out.push(w6);
                        out.push(w7);
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
