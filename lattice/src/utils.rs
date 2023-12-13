use algebra::ring::Ring;

/// dot product for two vectors
#[inline]
pub fn dot_product<R: Ring>(u: &[R], v: &[R]) -> R {
    u.iter()
        .zip(v.iter())
        .fold(R::zero(), |acc, (&x, &y)| acc + x * y)
}
