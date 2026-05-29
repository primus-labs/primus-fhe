use primus_integer::{FheUint, UnsignedInteger};

mod scalar;
mod slice;

/// Compact unsigned integer modulus.
///
/// Just store the modulus value and only support some basic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct CompactModulus<T>(pub T);

impl<T: UnsignedInteger> CompactModulus<T> {
    /// Creates a new [`CompactModulus<T>`].
    ///
    /// # Panics
    ///
    /// Panics if `value >= 2^{T::BITS - 2}` or `value ≤ 1`. The SIMD `reduce_sub` kernel
    /// relies on `modulus < 2^{BITS-2}` to avoid overflow in the wrapping
    /// subtraction path. All FHE parameter sets satisfy this bound.
    #[inline(always)]
    pub fn new(value: T) -> Self {
        assert!(
            value.leading_zeros() > 1,
            "CompactModulus value must be < 2^(T::BITS - 2), got {value:?}"
        );
        assert!(value > T::ONE, "modulus can't be 0 or 1.");
        Self(value)
    }
}

impl<T: FheUint> primus_reduce::Modulus for CompactModulus<T> {
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
