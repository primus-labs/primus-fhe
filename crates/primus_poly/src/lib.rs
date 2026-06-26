//! Polynomial types and operations for fully homomorphic encryption.
//!
//! This crate provides several polynomial representations used in FHE schemes:
//! - [`Polynomial`]: standard coefficient-form polynomial (single modulus).
//! - [`NttPolynomial`]: polynomial in NTT domain (single modulus).
//! - [`ArrayBase`]: flat array with element-wise arithmetic.
//! - [`BigUintPolynomial`]: polynomial with big integer coefficients.
//! - [`CrtPolynomial`]: polynomial under Chinese Remainder Theorem decomposition.
//! - [`DcrtPolynomial`]: double-CRT polynomial (CRT + NTT).

#![deny(missing_docs)]

#[macro_use]
mod macros;

mod array;

mod big_uint_poly;
mod crt;
mod dcrt;
mod ntt;
mod poly;

pub use array::{Array, ArrayBase, ArrayMut, ArrayRef};

pub use big_uint_poly::{BigUintPolynomial, BigUintPolynomialIter, BigUintPolynomialIterMut};

pub use crt::{CrtPolynomial, CrtPolynomialIter, CrtPolynomialIterMut};
pub use dcrt::{DcrtPolynomial, DcrtPolynomialIter, DcrtPolynomialIterMut};

pub use ntt::{
    NttPolynomial, NttPolynomialIter, NttPolynomialIterMut, NttPolynomialMut, NttPolynomialOwned,
    NttPolynomialRef,
};
pub use poly::{
    Polynomial, PolynomialIter, PolynomialIterMut, PolynomialMut, PolynomialOwned, PolynomialRef,
};
