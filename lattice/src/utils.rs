use algebra::Ring;

/// Performs dot product for two slices
#[inline]
pub fn dot_product<R: Ring>(u: &[R], v: &[R]) -> R {
    debug_assert_eq!(u.len(), v.len());
    u.iter().zip(v).fold(R::ZERO, |acc, (&x, y)| acc + x * y)
}
