//! This module defines some errors that
//! may occur during the execution of the library.

use thiserror::Error;

use crate::constants::{COEFF_MOD_COUNT_MAX, POLY_MODULUS_DEGREE_MAX, POLY_MODULUS_DEGREE_MIN};

/// Errors that may occur when it comes to Modular operations.
#[derive(Error, Debug)]
pub enum ModuloError {
    /// Error that occurs when the given value has no inverse element with the given modulus.
    #[error("Value {value} has no inverse element with the modulus {modulus}!")]
    NoModuloInverse { value: String, modulus: String },
    /// Error that occurs when the given modulus has no primitive root with the given degree.
    #[error("There is no primitive root with the degree {degree} and the modulus {modulus}!")]
    NoPrimitiveRoot { degree: u64, modulus: u64 },
    /// Error that occurs when crate fails to find enough qualifying primes.
    #[error("Failed to find enough qualifying primes")]
    NoEnoughModulus,
    /// Error that occurs when `poly_modulus_degree` is not a power of 2.
    #[error("Poly modulus degree {poly_modulus_degree} is not a power of 2")]
    IsNotPowerOf2 { poly_modulus_degree: usize },
    /// Error that occurs when `poly_modulus_degree` is not in ([`POLY_MODULUS_DEGREE_MIN`]..=[`POLY_MODULUS_DEGREE_MAX`]).
    #[error(
        "Poly modulus degree {poly_modulus_degree} is not in ({}..={})",
        POLY_MODULUS_DEGREE_MIN,
        POLY_MODULUS_DEGREE_MAX
    )]
    ExceedRange { poly_modulus_degree: usize },
    /// Error that occurs when user ask to generate too many coeff moduli.
    #[error(
        "The number {0} of desired coeff moduli is exceed upper bound {}",
        COEFF_MOD_COUNT_MAX
    )]
    DesireTooManyModuli(usize),
    /// Error that occurs when user ask to generate a modulus with invalid bit count.
    #[error("The bit count of desired coeff modulus is not valid")]
    BitCountError,
}
