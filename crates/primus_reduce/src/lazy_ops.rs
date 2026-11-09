/// Lazy modular reduction.
pub trait LazyReduce<T> {
    /// Output type.
    type Output;

    /// Calculates a representative congruent to `value` modulo `self`.
    ///
    /// # Preconditions
    ///
    /// The supported input range is implementation-defined; see the concrete
    /// modulus type.
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`. It may be non-canonical and must be
    /// reduced once when a value in `[0, modulus)` is required.
    ///
    /// If the modulus type does not natively support lazy reduction,
    /// implementations should fall back to [`Reduce`](crate::Reduce).
    #[must_use]
    fn lazy_reduce(self, value: T) -> Self::Output;
}

/// In-place lazy modular reduction.
pub trait LazyReduceAssign<T> {
    /// Replaces `value` with a representative congruent to it modulo `self`.
    ///
    /// # Preconditions
    ///
    /// The supported input range is implementation-defined; see the concrete
    /// modulus type.
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`ReduceAssign`](crate::ReduceAssign).
    fn lazy_reduce_assign(self, value: &mut T);
}

/// The lazy modular multiplication.
pub trait LazyReduceMul<T> {
    /// Output type.
    type Output;

    /// Calculates a lazy representative of `a * b` modulo `self`.
    ///
    /// # Preconditions
    ///
    /// - `a * b < modulus²`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`ReduceMul`](crate::ReduceMul).
    #[must_use]
    fn lazy_reduce_mul(self, a: T, b: T) -> Self::Output;
}

/// The lazy modular multiplication assignment.
pub trait LazyReduceMulAssign<T> {
    /// Replaces `a` with a lazy representative of `a * b` modulo `self`.
    ///
    /// # Preconditions
    ///
    /// - `a * b < modulus²`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`ReduceMulAssign`](crate::ReduceMulAssign).
    fn lazy_reduce_mul_assign(self, a: &mut T, b: T);
}

/// The lazy modular multiply-add.
pub trait LazyReduceMulAdd<T> {
    /// Output type.
    type Output;

    /// Calculates a lazy representative of `a * b + c` modulo `self`.
    ///
    /// # Preconditions
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    /// - `c < modulus`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`ReduceMulAdd`](crate::ReduceMulAdd).
    #[must_use]
    fn lazy_reduce_mul_add(self, a: T, b: T, c: T) -> Self::Output;
}

/// The lazy modular multiply-add assignment.
pub trait LazyReduceMulAddAssign<T> {
    /// Replaces `a` with a lazy representative of `a * b + c` modulo `self`.
    ///
    /// # Preconditions
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    /// - `c < modulus`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`ReduceMulAddAssign`](crate::ReduceMulAddAssign).
    fn lazy_reduce_mul_add_assign(self, a: &mut T, b: T, c: T);
}

/// The lazy modular subtraction.
pub trait LazyReduceSub<T> {
    /// Output type.
    type Output;

    /// Calculates a lazy representative of `a - b` modulo `self`.
    ///
    /// # Preconditions
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`ReduceSub`](crate::ReduceSub).
    #[must_use]
    fn lazy_reduce_sub(self, a: T, b: T) -> Self::Output;
}

/// The lazy modular subtraction assignment.
pub trait LazyReduceSubAssign<T> {
    /// Replaces `a` with a lazy representative of `a - b` modulo `self`.
    ///
    /// # Preconditions
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`ReduceSubAssign`](crate::ReduceSubAssign).
    fn lazy_reduce_sub_assign(self, a: &mut T, b: T);
}

/// The lazy modular negation.
pub trait LazyReduceNeg<T> {
    /// Output type.
    type Output;

    /// Calculates a lazy representative of `-value` modulo `self`.
    ///
    /// # Preconditions
    ///
    /// - `value < modulus`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`ReduceNeg`](crate::ReduceNeg).
    #[must_use]
    fn lazy_reduce_neg(self, value: T) -> Self::Output;
}

/// The lazy modular negation assignment.
pub trait LazyReduceNegAssign<T> {
    /// Replaces `value` with a lazy representative of `-value` modulo `self`.
    ///
    /// # Preconditions
    ///
    /// - `value < modulus`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`ReduceNegAssign`](crate::ReduceNegAssign).
    fn lazy_reduce_neg_assign(self, value: &mut T);
}
