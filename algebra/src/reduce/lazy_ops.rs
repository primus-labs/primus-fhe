/// The lazy modulo operation.
pub trait LazyReduce<Modulus>: Sized {
    /// Output type.
    type Output;

    /// Caculates `self (mod 2*modulus)`.
    ///
    /// If `Modulus` doesn't support this special case,
    /// just fall back to `Reduce` trait.
    fn lazy_reduce(self, modulus: Modulus) -> Self::Output;
}

/// The lazy modulo assignment operation.
pub trait LazyReduceAssign<Modulus>: Sized {
    /// Caculates `self (mod 2*modulus)`.
    ///
    /// If `Modulus` doesn't support this special case,
    /// just fall back to `ReduceAssign` trait.
    fn lazy_reduce_assign(&mut self, modulus: Modulus);
}

/// The lazy modular addition.
pub trait LazyAddReduce<Modulus, Rhs = Self> {
    /// Output type.
    type Output;

    /// Calculates `self + rhs (mod 2*modulus)`
    ///
    /// # Correctness
    ///
    /// - `self < 2*modulus`
    /// - `rhs < 2*modulus`
    ///
    /// If `Modulus` doesn't support this special case,
    /// just fall back to `AddReduce` trait.
    fn lazy_add_reduce(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The lazy modular addition assignment.
pub trait LazyAddReduceAssign<Modulus, Rhs = Self> {
    /// Calculates `self += rhs (mod 2*modulus)`
    ///
    /// # Correctness
    ///
    /// - `self < 2*modulus`
    /// - `rhs < 2*modulus`
    ///
    /// If `Modulus` doesn't support this special case,
    /// just fall back to `AddReduceAssign` trait.
    fn lazy_add_reduce_assign(&mut self, rhs: Rhs, modulus: Modulus);
}

/// The lazy modular subtraction.
pub trait LazySubReduce<Modulus, Rhs = Self> {
    /// Output type.
    type Output;

    /// Calculates `self - rhs (mod 2*modulus)`
    ///
    /// # Correctness
    ///
    /// - `self < 2*modulus`
    /// - `rhs < 2*modulus`
    ///
    /// If `Modulus` doesn't support this special case,
    /// just fall back to `SubReduce` trait.
    fn lazy_sub_reduce(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The lazy modular subtraction assignment.
pub trait LazySubReduceAssign<Modulus, Rhs = Self> {
    /// Calculates `self -= rhs (mod 2*modulus)`
    ///
    /// # Correctness
    ///
    /// - `self < 2*modulus`
    /// - `rhs < 2*modulus`
    ///
    /// If `Modulus` doesn't support this special case,
    /// just fall back to `SubReduceAssign` trait.
    fn lazy_sub_reduce_assign(&mut self, rhs: Rhs, modulus: Modulus);
}

/// The lazy modular negation.
pub trait LazyNegReduce<Modulus> {
    /// Output type.
    type Output;

    /// Calculates `-self (mod 2*modulus)`
    ///
    /// # Correctness
    ///
    /// - `self < 2*modulus`
    ///
    /// If `Modulus` doesn't support this special case,
    /// just fall back to `NegReduce` trait.
    fn lazy_neg_reduce(self, modulus: Modulus) -> Self::Output;
}

/// The lazy modular negation assignment.
pub trait LazyNegReduceAssign<Modulus> {
    /// Calculates `-self (mod 2*modulus)`
    ///
    /// # Correctness
    ///
    /// - `self < 2*modulus`
    ///
    /// If `Modulus` doesn't support this special case,
    /// just fall back to `NegReduceAssign` trait.
    fn lazy_neg_reduce_assign(&mut self, modulus: Modulus);
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

/// The lazy modular division.
pub trait LazyDivReduce<Modulus, Rhs = Self> {
    /// Output type.
    type Output;

    /// Calculates `self / rhs (mod 2*modulus)`.
    ///
    /// If `Modulus` doesn't support this special case,
    /// just fall back to `DivReduce` trait.
    fn lazy_div_reduce(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The lazy modular division assignment.
pub trait LazyDivReduceAssign<Modulus, Rhs = Self> {
    /// Calculates `self /= rhs (mod 2*modulus)`.
    ///
    /// If `Modulus` doesn't support this special case,
    /// just fall back to `DivReduceAssign` trait.
    fn lazy_div_reduce_assign(&mut self, rhs: Rhs, modulus: Modulus);
}
