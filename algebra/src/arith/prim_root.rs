use crate::AlgebraError;

/// For ease of introduction we use `n` for `degree` and `p` for prime number.
///
/// Let `n` be a power of 2 and `p` a prime with `p ≡ 1 (mod n)`.
///
/// This trait define the function to get the primitive `n`-th root of unity reduce `p`.
///
/// let `ω` be a primitive `n`-th root of unity in `Z_p`, which means that `ω^n ≡ 1 (mod p)`
///
/// We start try to get a primitive `p-1`-th root `g` for `p`. So, `g^(p-1) = 1 mod p`.
///
/// Next, we get `ω` = `g^((p-1)/n)`. It should satisfy the formula that
/// `ω^(n/2) = -1 mod p`.
///
/// We can get a minimal root `ω` with one more iteration.
pub trait PrimitiveRoot<T> {
    /// Check if `root` is a primitive `degree`-th root of unity in integers reduce `p`.
    fn check_primitive_root(self, root: T, log_degree: u32) -> bool;

    /// Try to get a primitive `degree`-th root of unity reduce `p`.
    fn try_primitive_root(self, log_degree: u32) -> Result<T, AlgebraError>;

    /// Try to get the minimal primitive `degree`-th root of unity reduce `p`.
    fn try_minimal_primitive_root(self, log_degree: u32) -> Result<T, AlgebraError>;
}
