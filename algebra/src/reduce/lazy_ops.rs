/// The lazy modulo operation.
pub trait LazyReduce<Modulus>: Sized {
    /// Output type.
    type Output;

    /// Caculates `self (mod 2*modulus)`.
    fn lazy_reduce(self, modulus: Modulus) -> Self::Output;
}

/// The lazy modulo assignment operation.
pub trait LazyReduceAssign<Modulus>: Sized {
    /// Caculates `self (mod 2*modulus)`.
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
    fn lazy_neg_reduce(self, modulus: Modulus) -> Self::Output;
}

/// The lazy modular negation assignment.
pub trait LazyNegReduceAssign<Modulus> {
    /// Calculates `-self (mod 2*modulus)`
    ///
    /// # Correctness
    ///
    /// - `self < 2*modulus`
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
    fn lazy_mul_reduce(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The lazy modular multiplication assignment.
pub trait LazyMulReduceAssign<Modulus, Rhs = Self> {
    /// Calculates `self *= rhs (mod 2*modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self*rhs < modulus^2`
    fn lazy_mul_reduce_assign(&mut self, rhs: Rhs, modulus: Modulus);
}

/// The lazy modular division.
pub trait LazyDivReduce<Modulus, Rhs = Self> {
    /// Output type.
    type Output;

    /// Calculates `self / rhs (mod 2*modulus)`.
    fn lazy_div_reduce(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The lazy modular division assignment.
pub trait LazyDivReduceAssign<Modulus, Rhs = Self> {
    /// Calculates `self /= rhs (mod 2*modulus)`.
    fn lazy_div_reduce_assign(&mut self, rhs: Rhs, modulus: Modulus);
}
