//! Define `NTTField`` trait

use super::PrimeField;

/// A helper trait  for number theory transform
///
/// It's optimized for the vector with the length of power of two.
///
/// For ease of introduction we use `n` for `degreee` and `p` for prime number.
///
/// Let `n` be a power of 2 and `p` a prime with `p ≡ 1 (mod 2n)`.
///
/// This trait define the function to get the primitive `n`-th root of unity  reduce `p`.
///
/// let `ω` be a primitive `n`-th root of unity in `Z_p`, which means that `ω^n ≡ 1 (mod p)`
///
/// We start try to get a primitive `p-1`-th root `g` for `p`. So, `g^(p-1) = 1 mod p`.
///
/// Next, we get `ω` = `g^((p-1)/n)`. It should satisfy the formula that
/// `ω^(n/2) = -1 mod p`.
///
/// We can get a minimal root `ω` with one more iteration.
pub trait NTTField: PrimeField {
    /// NTT table type
    type Table;

    /// Root type
    type Root;

    /// Degree type
    type Degree;

    /// Check if `root` is a primitive `degree`-th root of unity in integers reduce `p`.
    fn is_primitive_root(root: Self, degree: Self::Degree) -> bool;

    /// Try to get a primitive `degree`-th root of unity reduce `p`.
    fn try_primitive_root(degree: Self::Degree) -> Result<Self, crate::AlgebraError>;

    /// Try to get the minimal primitive `degree`-th root of unity reduce `p`.
    fn try_minimal_primitive_root(degree: Self::Degree) -> Result<Self, crate::AlgebraError>;

    /// generate the ntt table of the ntt field
    fn generate_ntt_table(log_n: u32) -> Result<Self::Table, crate::AlgebraError>;
}
