//! Define `NTTField`` trait

use std::{fmt::Debug, sync::Arc};

use crate::transformation::{AbstractNTT, MonomialNTT};

use super::{FheField, PrimeField};

/// A trait for fields where Number Theoretic Transforms (NTT) can be performed.
/// It's optimized for the vector with the length of power of two.
///
/// The `NTTField` trait extends `PrimeField` to provide additional structure and operations
/// necessary for efficiently performing NTTs, which are the modular arithmetic equivalent of
/// the Fast Fourier Transform (FFT). NTTs are used extensively in polynomial multiplication,
/// particularly in cryptographic protocols like lattice-based cryptography.
///
/// Implementing types must provide functionality to work with roots of unity, decompose elements
/// with respect to a basis, and generate and manage tables for NTT operations.
pub trait NTTField: PrimeField + FheField + From<usize> {
    /// An abstraction over the data structure used to store precomputed values for NTT.
    type Table: AbstractNTT<Self> + MonomialNTT<Self>;

    /// The type representing the roots of unity within the field.
    type Root: Copy + Debug + Default;

    /// Degree type
    type Degree;

    /// Convert `root` into `Self` type.
    fn from_root(root: Self::Root) -> Self;

    /// Convert `self` into `Self::Root` type.
    fn to_root(self) -> Self::Root;

    /// Calculate `self * root`.
    fn mul_root(self, root: Self::Root) -> Self;

    /// Calculate `self *= root`.
    fn mul_root_assign(&mut self, root: Self::Root);

    /// Check if `root` is a primitive `degree`-th root of unity in integers reduce `p`.
    fn is_primitive_root(root: Self, degree: Self::Degree) -> bool;

    /// Try to get a primitive `degree`-th root of unity reduce `p`.
    fn try_primitive_root(degree: Self::Degree) -> Result<Self, crate::AlgebraError>;

    /// Try to get the minimal primitive `degree`-th root of unity reduce `p`.
    ///
    /// For ease of introduction we use `n` for `degree` and `p` for prime number.
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
    fn try_minimal_primitive_root(degree: Self::Degree) -> Result<Self, crate::AlgebraError>;

    /// Generate the ntt table of the ntt field with desired `log_n`.
    fn generate_ntt_table(log_n: u32) -> Result<Self::Table, crate::AlgebraError>;

    /// Get the ntt table of the ntt field with desired `log_n`.
    fn get_ntt_table(log_n: u32) -> Result<Arc<Self::Table>, crate::AlgebraError>;

    /// Init ntt table with `log_n` slice.
    fn init_ntt_table(log_n_slice: &[u32]) -> Result<(), crate::AlgebraError>;
}
