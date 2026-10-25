#![deny(missing_docs)]

//! Sampling distributions and secret-key distribution parameters for FHE.
//!
//! This crate provides samplers for discrete probability distributions used
//! in fully homomorphic encryption (FHE) schemes:
//!
//! - **Binary** ([`BinaryDistr`]) — uniform over {0, 1}.
//! - **Sparse ternary** ([`SparseTernaryDistr`]) — {0, 1, -1} with
//!   probabilities 0.5, 0.25, 0.25.
//! - **Discrete Gaussian** ([`DiscreteGaussian`]) — centered discrete Gaussian
//!   with support on unsigned integers, wrapping negative samples modulo the
//!   modulus.
//! - **Signed discrete Gaussian** ([`SignedDiscreteGaussian`]) — centered
//!   discrete Gaussian with support on signed integers.
//!
//! [`SecretKeyDistr`] describes secret-coefficient distributions and validates
//! probabilities and fixed weights. Cryptosystems select supported variants;
//! Gaussian sampler constructors validate Gaussian parameters.
//! [`SecretKeySampler`] prepares reusable
//! whole-key sampling, including Gaussian tables and fixed-weight validation.
//!
//! # Sampler selection
//!
//! The Gaussian samplers internally choose between a CDT sampler
//! ([`CDTSampler`]) and a Ziggurat sampler ([`DiscreteZiggurat`]) based on
//! whether the truncated support fits the CDT table.
//! With the `high_precision` feature, portable 256-bit CDT samplers
//! (`PreciseCDTSampler` and `SignedPreciseCDTSampler`) are also
//! available.
//!
//! # Batch sampling
//!
//! Utility functions support efficient batch generation of vectors,
//! including modulus-major CRT (Chinese remainder theorem) layouts where each
//! logical value is encoded under every component modulus.

mod error;
mod gaussian_core;

mod utils;

mod common;

mod binary;
mod ternary;

mod discrete_gaussian;
mod signed_discrete_gaussian;

pub mod stats;

pub use error::{GaussianError, SecretKeySamplerError};

/// Smallest standard deviation supported by the discrete Gaussian samplers.
///
/// This is an implementation-support threshold rather than a mathematical or
/// cryptographic security bound. Below it, lattice discretization makes the
/// measured standard deviation diverge increasingly from the scale parameter.
pub const MIN_STANDARD_DEVIATION: f64 = 0.7;

pub use common::*;

pub use binary::BinaryDistr;
pub use ternary::SparseTernaryDistr;

#[cfg(feature = "high_precision")]
pub use discrete_gaussian::PreciseCDTSampler;
pub use discrete_gaussian::{CDTSampler, DiscreteGaussian, DiscreteZiggurat};
#[cfg(feature = "high_precision")]
pub use signed_discrete_gaussian::SignedPreciseCDTSampler;
pub use signed_discrete_gaussian::{
    SignedCDTSampler, SignedDiscreteGaussian, SignedDiscreteZiggurat,
};

mod secret_key_distr;
pub use secret_key_distr::SecretKeyDistr;

mod secret_key_sampler;
pub use secret_key_sampler::SecretKeySampler;
