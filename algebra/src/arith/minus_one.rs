/// Defines `-1`.
pub trait MinusOne: Sized {
    /// Returns `-1` of `Self`.
    ///
    /// # Purity
    ///
    /// This function should return the same result at all times regardless of
    /// external mutable state.
    fn minus_one() -> Self;

    /// Sets `self` to `-1` of `Self`.
    #[inline]
    fn set_minus_one(&mut self) {
        *self = MinusOne::minus_one();
    }

    /// Returns `true` if `self` is equal to `-1`.
    ///
    /// For performance reasons, it's best to implement this manually.
    /// After a semver bump, this method will be required, and the
    /// `where Self: PartialEq` bound will be removed.
    #[inline]
    fn is_minus_one(&self) -> bool
    where
        Self: PartialEq,
    {
        *self == Self::minus_one()
    }
}

/// Defines an associated constant representing `-1` for `Self`.
pub trait ConstMinusOne: MinusOne {
    /// `-1`.
    const MINUS_ONE: Self;
}
