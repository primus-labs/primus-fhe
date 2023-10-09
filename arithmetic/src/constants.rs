//! This module defines a number of common constants,
//! which are mainly constraints.

/// The maximum number of bits in modulus.
pub const MODULUS_BIT_COUNT_MAX: usize = 62;
/// The minimum number of bits in modulus.
pub const MODULUS_BIT_COUNT_MIN: usize = 2;

/// The maximum number of bits of user-defined coefficient moduli
pub const USER_MOD_BIT_COUNT_MAX: u32 = 60;
/// The minimum number of bits of user-defined coefficient moduli
pub const USER_MOD_BIT_COUNT_MIN: u32 = 2;

/// Upper bound for number of coefficient moduli (no hard requirement)
pub const COEFF_MOD_COUNT_MAX: usize = 64;
/// Lower bound for number of coefficient moduli (no hard requirement)
pub const COEFF_MOD_COUNT_MIN: usize = 1;

/// The maximum degree of polynomial modulus.
pub const POLY_MODULUS_DEGREE_MAX: usize = 131072;
/// The minimum degree of polynomial modulus.
///
/// This lower bound is constrained by the implementation of NTT and INTT.
pub const POLY_MODULUS_DEGREE_MIN: usize = 8;

/// In the dot product operation, the maximum number
/// of multiplicative sums for u64 that can be accommodated in a u128.
pub const DOT_PROUDCT_COUNTS_MAX: usize = 1 << (128 - (MODULUS_BIT_COUNT_MAX << 1));
