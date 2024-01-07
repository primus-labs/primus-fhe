//! Definition and implementation of polynomials.

mod native_polynomial;
mod ntt_polynomial;

pub use native_polynomial::Polynomial;
pub use ntt_polynomial::NTTPolynomial;
