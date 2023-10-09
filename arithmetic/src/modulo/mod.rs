//! This module implements some functions and methods for
//! modular arithmetic based on barrett reduction.
//!
//! Barrett reduction computes `r ≡ x mod m` given `x` and `m`
//! and return `r`.
//!
//! Fisrt, we need decide the radix `b`, which is chosen to be close to
//! the word-size of the processor. Here, `b` = 2^64.
//!
//! The algorithm then precomputes a quantity ratio `µ = ⌊b^(2k)/m⌋`,
//! where `k` is the length of `m` based on radix `b`.
//!
//! For example, we denote `x` = (x_(2k-1) ... x_1 x_0)
//! and `m` = (m_(k-1) ... m_1 m_0) (m_(k-1) ≠ 0) based on radix `b`.
//!
//! Then, the algorithm will output `r ≡ x mod m` with the below procedures:
//!
//! 1. `q1 ← ⌊x/b^(k−1)⌋`, `q2 ← q1 · µ`, `q3 ← ⌊q2/b^(k+1)⌋`.
//! 2. `r1 ← x mod b^(k+1)`, `r2 ← (q3 · m) mod b^(k+1)`, `r ← r1 − r2`.
//! 3. If `r ≥ m` do: `r ← r − m`.
//! 4. Return(`r`).

// pub mod prelude;

mod traits;

mod modulus;
mod prime_modulus;

// mod multiply;
mod pow;

pub use traits::*;

pub use modulus::Modulus;
pub use prime_modulus::PrimeModulus;


