//! Definition and implementation of polynomials.

mod native_polynomial;
mod ntt_polynomial;

pub use native_polynomial::Polynomial;
pub use ntt_polynomial::{
    ntt_add_mul_assign, ntt_add_mul_assign_ref, ntt_add_mul_assign_ref_fast, ntt_mul_assign,
    ntt_mul_assign_fast, ntt_mul_assign_ref, ntt_mul_assign_ref_fast, NTTPolynomial,
};
