use algebra::{FheField, Field};

mod decompose_basis;
mod sample;
mod space;

pub use decompose_basis::{decompose_lsb_bits_inplace, Basis};
pub use sample::*;
pub use space::*;

/// Performs dot product for two slices
#[inline]
pub fn dot_product<F: Field>(u: &[F], v: &[F]) -> F {
    debug_assert_eq!(u.len(), v.len());
    u.iter().zip(v).fold(F::zero(), |acc, (&x, &y)| acc + x * y)
}

/// Performs dot product for two slices, optimized for FheField
#[inline]
pub fn doc_product<F: FheField>(u: &[F], v: &[F]) -> F {
    debug_assert_eq!(u.len(), v.len());
    u.iter()
        .zip(v)
        .fold(F::zero(), |acc, (&x, &y)| acc.add_mul(x, y))
}
