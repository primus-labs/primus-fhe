/// Returns `x mod q`, assuming `x < 2 * q`.
#[inline(always)]
pub(in crate::ntt::prime32) fn reduce_once(x: u32, q: u32) -> u32 {
    x.min(x.wrapping_sub(q))
}

/// Returns `x mod q`, assuming `x < 4 * q`.
/// `two_q` must equal `2 * q`.
#[inline(always)]
pub(in crate::ntt::prime32) fn reduce_twice(x: u32, q: u32, two_q: u32) -> u32 {
    reduce_once(reduce_once(x, two_q), q)
}

/// Plain Barrett lazy multiply for u32 with 32-bit shift.
#[inline(always)]
pub(in crate::ntt::prime32) fn mul_mod_lazy(y: u32, w: u32, w_precon: u32, q: u32) -> u32 {
    let qhat = ((y as u64).wrapping_mul(w_precon as u64) >> 32) as u32;
    w.wrapping_mul(y).wrapping_sub(q.wrapping_mul(qhat))
}

/// Plain Harvey forward butterfly
#[inline(always)]
pub(in crate::ntt::prime32) fn fwd_butterfly(
    x: &mut u32,
    y: &mut u32,
    w: u32,
    wp: u32,
    q: u32,
    two_q: u32,
) {
    let tx = reduce_once(*x, two_q);
    let ty = mul_mod_lazy(*y, w, wp, q);
    *x = tx + ty;
    *y = tx + two_q - ty;
}

/// Plain Harvey inverse butterfly
#[inline(always)]
pub(in crate::ntt::prime32) fn inv_butterfly(
    x: &mut u32,
    y: &mut u32,
    w: u32,
    wp: u32,
    q: u32,
    two_q: u32,
) {
    let tx = *x + *y;
    let ty = *x + two_q - *y;
    *x = reduce_once(tx, two_q);
    *y = mul_mod_lazy(ty, w, wp, q);
}
