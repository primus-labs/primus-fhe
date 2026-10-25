//! Polynomial types and operations for fully homomorphic encryption.
//!
//! This crate provides several polynomial representations used in FHE schemes:
//! - [`Polynomial`]: standard coefficient-form polynomial (single modulus).
//! - [`NttPolynomial`]: polynomial in NTT domain (single modulus).
//! - [`BigUintPolynomial`]: polynomial with big integer coefficients.
//! - [`CrtPolynomial`]: polynomial under Chinese Remainder Theorem decomposition.
//! - [`DcrtPolynomial`]: double-CRT polynomial (CRT + NTT).
//! - [`FourierPolynomial`]: polynomial in the Fourier domain (complex values).
//!
//! Flat scalar buffers use slices and the `Reduce*Slice` traits in [`primus_reduce`].
//! The polynomial wrappers are generic over their backing storage. Methods that
//! take `self` consume the wrapper and return it after updating its storage. If
//! the storage is a mutable borrow, the caller's backing slice is updated as
//! well; use the corresponding `*_assign` method when that side effect should
//! be explicit.

#![deny(missing_docs)]

#[macro_use]
mod macros;

mod automorphism;

mod big_uint_poly;
mod crt;
mod dcrt;
mod fourier;
mod monomial;
mod ntt;
mod poly;

pub use automorphism::CoeffAutomorphismPermutation;
pub use monomial::{
    add_mul_monomial_pair_assign, lazy_add_mul_monomial_assign, lazy_add_mul_monomial_pair_assign,
};

pub use big_uint_poly::{BigUintPolynomial, BigUintPolynomialIter, BigUintPolynomialIterMut};

pub use crt::{CrtPolynomial, CrtPolynomialIter, CrtPolynomialIterMut};
pub use dcrt::{DcrtPolynomial, DcrtPolynomialIter, DcrtPolynomialIterMut};

pub use fourier::{
    FourierPolynomial, FourierPolynomialIter, FourierPolynomialIterMut, FourierPolynomialMut,
    FourierPolynomialOwned, FourierPolynomialRef,
};

pub use ntt::{
    NttPolynomial, NttPolynomialIter, NttPolynomialIterMut, NttPolynomialMut, NttPolynomialOwned,
    NttPolynomialRef,
};
pub use poly::{
    Polynomial, PolynomialIter, PolynomialIterMut, PolynomialMut, PolynomialOwned, PolynomialRef,
};
