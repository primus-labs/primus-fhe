/// Returns `x mod q`, assuming `x < 2 * q`.
#[inline(always)]
pub(in crate::ntt::prime64) fn reduce_once(x: u64, q: u64) -> u64 {
    x.min(x.wrapping_sub(q))
}

/// Returns `x mod q`, assuming `x < 4 * q`.
/// `two_q` must equal `2 * q`.
#[inline(always)]
pub(in crate::ntt::prime64) fn reduce_twice(x: u64, q: u64, two_q: u64) -> u64 {
    reduce_once(reduce_once(x, two_q), q)
}

// ── Barrett lazy multiplies ────────────────────────────────────────────────

/// Barrett-32 lazy multiply for `q < 2^30`.
///
/// Exactly mirrors the u32 scalar version: widen to 64 bits for the high-half
/// multiply, then use native 32-bit wrapping arithmetic for the subtraction.
/// Because `q < 2^30` ⇒ the true result always lies in `[0, 2q) ⊂ [0, 2^32)`,
/// the wrapping subtraction never actually wraps.
#[inline(always)]
pub(in crate::ntt::prime64) fn mul_mod_lazy32(y: u64, w: u64, w_precon32: u64, q: u64) -> u64 {
    let qhat = (y.wrapping_mul(w_precon32) >> 32) as u32;
    (w as u32)
        .wrapping_mul(y as u32)
        .wrapping_sub((q as u32).wrapping_mul(qhat)) as u64
}

/// Barrett-64 lazy multiply for `q < 2^62`.
#[inline(always)]
pub(in crate::ntt::prime64) fn mul_mod_lazy(y: u64, w: u64, w_precon: u64, q: u64) -> u64 {
    let qhat = ((y as u128).wrapping_mul(w_precon as u128) >> 64) as u64;
    w.wrapping_mul(y).wrapping_sub(q.wrapping_mul(qhat))
}

// ── Harvey butterflies ─────────────────────────────────────────────────────

/// Harvey forward butterfly (radix-2).
///
/// `BIT_SHIFT` selects the Barrett width: 32 for `q < 2^30`, 64 otherwise.
#[inline(always)]
pub(in crate::ntt::prime64) fn fwd_butterfly<const BIT_SHIFT: u32>(
    x: &mut u64,
    y: &mut u64,
    w: u64,
    w_precon: u64,
    q: u64,
    two_q: u64,
) {
    let tx = reduce_once(*x, two_q);
    let t = if BIT_SHIFT == 32 {
        mul_mod_lazy32(*y, w, w_precon, q)
    } else {
        mul_mod_lazy(*y, w, w_precon, q)
    };
    *x = tx + t;
    *y = tx + two_q - t;
}

/// Harvey inverse butterfly (radix-2).
#[inline(always)]
pub(in crate::ntt::prime64) fn inv_butterfly<const BIT_SHIFT: u32>(
    x: &mut u64,
    y: &mut u64,
    w: u64,
    w_precon: u64,
    q: u64,
    two_q: u64,
) {
    let tx = *x + *y;
    let y_red = *x + two_q - *y;
    *x = reduce_once(tx, two_q);
    *y = if BIT_SHIFT == 32 {
        mul_mod_lazy32(y_red, w, w_precon, q)
    } else {
        mul_mod_lazy(y_red, w, w_precon, q)
    };
}
