use algebra::Ring;

/// dot product for two vectors
#[inline]
pub fn dot_product<R: Ring>(u: &[R], v: &[R]) -> R {
    debug_assert_eq!(u.len(), v.len());
    u.iter()
        .zip(v.iter())
        .fold(R::zero(), |acc, (&x, &y)| acc + x * y)
}
