use primus_integer::{FheUint, UnsignedInteger};

mod scalar;
mod slice;

/// An explicit unsigned-integer modulus for basic modular arithmetic.
///
/// This context stores only the modulus and does not precompute reduction data.
/// [`Self::new`] checks the range; tuple construction and writes to the public
/// field do not.
///
/// # Correctness
///
/// Keep the stored modulus greater than one, including after direct construction
/// or field updates. Arithmetic methods rely on this invariant and their operand
/// range contracts; they do not generally recheck the modulus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct UintModulus<T>(pub T);

impl<T: UnsignedInteger> UintModulus<T> {
    /// Creates a [`UintModulus<T>`] for the given modulus.
    ///
    /// # Panics
    ///
    /// Panics if `value ≤ 1`.
    #[must_use]
    #[inline(always)]
    pub fn new(value: T) -> Self {
        assert!(value > T::ONE, "modulus can't be 0 or 1.");
        Self(value)
    }

    /// Returns the modulus.
    #[must_use]
    #[inline(always)]
    pub const fn value(self) -> T {
        self.0
    }
}

impl<T: FheUint> primus_reduce::Modulus for UintModulus<T> {
    type ValueT = T;

    #[inline(always)]
    fn explicit_value(self) -> Option<Self::ValueT> {
        Some(self.0)
    }

    #[inline(always)]
    fn minus_one(self) -> Self::ValueT {
        debug_assert!(
            self.0 > T::ONE,
            "UintModulus value must be greater than one"
        );
        self.0 - T::ONE
    }
}

impl<T: FheUint> primus_reduce::ExplicitModulus for UintModulus<T> {
    #[inline(always)]
    fn value(self) -> Self::ValueT {
        self.0
    }
}
