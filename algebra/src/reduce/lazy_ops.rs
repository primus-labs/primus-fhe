/// The lazy modulo operation.
pub trait LazyReduce<Modulus>: Sized {
    /// Output type.
    type Output;

    /// Calculates `self (mod 2*modulus)`.
    ///
    /// If `Modulus` doesn't support this special case,
    /// just fall back to `Reduce` trait.
    fn lazy_reduce(self, modulus: Modulus) -> Self::Output;
}

/// The lazy modulo assignment operation.
pub trait LazyReduceAssign<Modulus>: Sized {
    /// Calculates `self (mod 2*modulus)`.
    ///
    /// If `Modulus` doesn't support this special case,
    /// just fall back to `ReduceAssign` trait.
    fn lazy_reduce_assign(&mut self, modulus: Modulus);
}

/// The lazy modular multiplication.
pub trait LazyMulReduce<Modulus, Rhs = Self> {
    /// Output type.
    type Output;

    /// Calculates `self * rhs (mod 2*modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self*rhs < modulus^2`
    ///
    /// If `Modulus` doesn't support this special case,
    /// just fall back to `MulReduce` trait.
    fn lazy_mul_reduce(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The lazy modular multiplication assignment.
pub trait LazyMulReduceAssign<Modulus, Rhs = Self> {
    /// Calculates `self *= rhs (mod 2*modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self*rhs < modulus^2`
    ///
    /// If `Modulus` doesn't support this special case,
    /// just fall back to `MulReduceAssign` trait.
    fn lazy_mul_reduce_assign(&mut self, rhs: Rhs, modulus: Modulus);
}
