/// The lazy modulo operation.
pub trait LazyReduce<T> {
    /// Output type.
    type Output;

    /// Calculates `value (mod 2*modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// Input range for `value` is **implementation-defined** (same as
    /// [`Reduce`](crate::Reduce)). The result is only guaranteed to be in
    /// `[0, 2*modulus)`, not the canonical `[0, modulus)`; callers must
    /// perform a final reduction when a canonical result is required.
    ///
    /// If the modulus type does not natively support lazy reduction,
    /// implementations should fall back to [`Reduce`](crate::Reduce).
    #[must_use]
    fn lazy_reduce(self, value: T) -> Self::Output;
}

/// The lazy modulo assignment operation.
pub trait LazyReduceAssign<T> {
    /// Calculates `value (mod 2*modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// Input range is implementation-defined. Result is in `[0, 2*modulus)`.
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ReduceAssign] trait.
    fn lazy_reduce_assign(self, value: &mut T);
}

/// The lazy modular multiplication.
pub trait LazyReduceMul<T, B = T> {
    /// Output type.
    type Output;

    /// Calculates `a * b (mod 2*modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a * b < modulus²`
    /// - Result is in `[0, 2*modulus)`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ReduceMul] trait.
    #[must_use]
    fn lazy_reduce_mul(self, a: T, b: B) -> Self::Output;
}

/// The lazy modular multiplication assignment.
pub trait LazyReduceMulAssign<T, B = T> {
    /// Calculates `a *= b (mod 2*modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a * b < modulus²`
    /// - Result is in `[0, 2*modulus)`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ReduceMulAssign] trait.
    fn lazy_reduce_mul_assign(self, a: &mut T, b: B);
}

/// The lazy modular multiply-add.
pub trait LazyReduceMulAdd<T, B = T, C = T> {
    /// Output type.
    type Output;

    /// Calculates `a * b + c (mod 2*modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    /// - `c < modulus`
    /// - Result is in `[0, 2*modulus)`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ReduceMulAdd] trait.
    #[must_use]
    fn lazy_reduce_mul_add(self, a: T, b: B, c: C) -> Self::Output;
}

/// The lazy modular multiply-add assignment.
pub trait LazyReduceMulAddAssign<T, B = T, C = T> {
    /// Calculates `a * b + c (mod 2*modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    /// - `c < modulus`
    /// - Result is in `[0, 2*modulus)`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ReduceMulAddAssign] trait.
    fn lazy_reduce_mul_add_assign(self, a: &mut T, b: B, c: C);
}

/// The lazy modular subtraction.
pub trait LazyReduceSub<T, B = T> {
    /// Output type.
    type Output;

    /// Calculates `a - b (mod 2*modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    /// - Result is in `[0, 2*modulus)`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ReduceSub] trait.
    #[must_use]
    fn lazy_reduce_sub(self, a: T, b: B) -> Self::Output;
}

/// The lazy modular subtraction assignment.
pub trait LazyReduceSubAssign<T, B = T> {
    /// Calculates `a -= b (mod 2*modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    /// - Result is in `[0, 2*modulus)`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ReduceSubAssign] trait.
    fn lazy_reduce_sub_assign(self, a: &mut T, b: B);
}

/// The lazy modular negation.
pub trait LazyReduceNeg<T> {
    /// Output type.
    type Output;

    /// Calculates `-value (mod 2*modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `value < modulus`
    /// - Result is in `[0, 2*modulus)`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ReduceNeg] trait.
    #[must_use]
    fn lazy_reduce_neg(self, value: T) -> Self::Output;
}

/// The lazy modular negation assignment.
pub trait LazyReduceNegAssign<T> {
    /// Calculates `value = -value (mod 2*modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `value < modulus`
    /// - Result is in `[0, 2*modulus)`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ReduceNegAssign] trait.
    fn lazy_reduce_neg_assign(self, value: &mut T);
}
