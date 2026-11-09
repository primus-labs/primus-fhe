//! Decomposition operators for fully homomorphic encryption.
//!
//! Approximate signed decomposition is a core building block for FHE schemes
//! such as FHEW/TFHE. This crate provides two flavors:
//!
//! - [`primitive`] — operates on single-limb values (`T: FheUint`).
//! - [`big_integer`] — operates on multi-limb [`BigUint`] values.
//!
//! [`BigUint`]: primus_integer::BigUint

#![deny(missing_docs)]

mod error;
mod parameters;

pub use error::{ApproxSignedBasisError, DecompositionBaseLogError, DecompositionLevelCountError};
pub use parameters::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};

/// Smallest supported base-2 logarithm of a decomposition basis.
pub const MIN_DECOMPOSITION_LOG_BASIS: u32 = 2;

/// Multi-limb decomposition operators and basis.
pub mod big_integer;
/// Single-limb (primitive) decomposition operators and basis.
pub mod primitive;

/// Selects the retained high levels and their first bit offset.
/// Callers have already validated `0 < log_basis <= value_bits`.
fn level_count_and_drop_bits(
    value_bits: u32,
    log_basis: DecompositionBaseLog,
    level_count: Option<DecompositionLevelCount>,
) -> Result<(DecompositionLevelCount, u32), ApproxSignedBasisError> {
    let log_basis = log_basis.get();
    let full_level_count = (value_bits / log_basis) as usize;
    let level_count = level_count.map_or(full_level_count, DecompositionLevelCount::get);
    if level_count > full_level_count {
        return Err(ApproxSignedBasisError::LevelCountTooLarge {
            level_count,
            full_level_count,
        });
    }
    // level_count <= value_bits/log_basis, so narrowing the retained count is
    // lossless and its product with log_basis cannot exceed value_bits.
    Ok((
        DecompositionLevelCount::new(level_count),
        value_bits - level_count as u32 * log_basis,
    ))
}
