use algebra::Field;

mod sample;
mod space;

pub use sample::*;
pub use space::*;

/// Performs dot product for two slices
#[inline]
pub fn dot_product<F: Field>(u: &[F], v: &[F]) -> F {
    debug_assert_eq!(u.len(), v.len());
    u.iter()
        .zip(v)
        .fold(F::ZERO, |acc, (&x, &y)| acc.add_mul(x, y))
}
