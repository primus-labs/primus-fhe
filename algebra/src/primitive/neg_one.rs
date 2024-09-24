/// Defines `-1` for `Self`.
pub trait NegOne: Sized {
    /// Returns `-1` of `Self`.
    ///
    /// # Purity
    ///
    /// This function should return the same result at all times regardless of
    /// external mutable state.
    fn neg_one() -> Self;

    /// Sets `self` to `-1` of `Self`.
    fn set_neg_one(&mut self) {
        *self = NegOne::neg_one();
    }

    /// Returns `true` if `self` is equal to `-1`.
    ///
    /// For performance reasons, it's best to implement this manually.
    /// After a semver bump, this method will be required, and the
    /// `where Self: PartialEq` bound will be removed.
    #[inline]
    fn is_neg_one(&self) -> bool
    where
        Self: PartialEq,
    {
        *self == Self::neg_one()
    }
}

/// Defines an associated constant representing `-1` for `Self`.
pub trait ConstNegOne: NegOne {
    /// `-1`.
    const NEG_ONE: Self;
}
