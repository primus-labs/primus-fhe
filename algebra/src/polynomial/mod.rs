//! Definition and implementation of polynomials.

mod native_polynomial;
mod ntt_polynomial;
pub mod multivariate;

pub use native_polynomial::Polynomial;
pub use ntt_polynomial::{
    ntt_add_mul_assign, ntt_add_mul_assign_ref, ntt_mul_assign, ntt_mul_assign_ref, NTTPolynomial,
};