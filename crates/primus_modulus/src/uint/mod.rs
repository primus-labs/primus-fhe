use primus_integer::{FheUint, UnsignedInteger};

mod scalar;
mod slice;

/// Unsigned integer modulus.
///
/// Just store the modulus value and only support some basic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct UintModulus<T>(pub T);

impl<T: UnsignedInteger> UintModulus<T> {
    /// Creates a new [`UintModulus<T>`].
    ///
    /// # Panics
    ///
    /// Panics if `value ≤ 1`.
    #[inline(always)]
    pub fn new(value: T) -> Self {
        assert!(value > T::ONE, "modulus can't be 0 or 1.");
        Self(value)
    }
}

impl<T: FheUint> primus_reduce::Modulus for UintModulus<T> {
    type ValueT = T;

    #[inline(always)]
    fn value(self) -> Option<Self::ValueT> {
        Some(self.0)
    }

    #[inline(always)]
    unsafe fn value_unchecked(self) -> Self::ValueT {
        self.0
    }

    #[inline(always)]
    fn minus_one(self) -> Self::ValueT {
        self.0 - T::ONE
    }
}
