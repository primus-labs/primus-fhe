/// The lazy modulo operation.
pub trait LazyReduce<T> {
    /// Output type.
    type Output;

    /// Calculates `value (mod 2*modulus)` where `self` is modulus.
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::reduce::Reduce] trait.
    fn lazy_reduce(self, value: T) -> Self::Output;
}

/// The lazy modulo assignment operation.
pub trait LazyReduceAssign<T> {
    /// Calculates `value (mod 2*modulus)` where `self` is modulus.
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::reduce::ReduceAssign] trait.
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
    /// - `a*b < modulus²`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::reduce::ReduceMul] trait.
    fn lazy_reduce_mul(self, a: T, b: B) -> Self::Output;
}

/// The lazy modular multiplication assignment.
pub trait LazyReduceMulAssign<T, B = T> {
    /// Calculates `a *= b (mod 2*modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a*b < modulus²`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::reduce::ReduceMulAssign] trait.
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
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::reduce::ReduceMulAdd] trait.
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
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::reduce::ReduceMulAddAssign] trait.
    fn lazy_reduce_mul_add_assign(self, a: &mut T, b: B, c: C);
}
