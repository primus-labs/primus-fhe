use primus_integer::{FheUint, UnsignedInteger};

mod scalar;
mod slice;

/// An explicit modulus with a restricted range for compact arithmetic kernels.
///
/// This context stores only the modulus and does not precompute reduction data.
/// [`Self::new`] checks the range; tuple construction and writes to the public
/// field do not.
///
/// # Correctness
///
/// Keep `1 < value < 2^(T::BITS - 2)`, including after direct construction or
/// field updates. The two spare high bits are required by the compact kernels.
/// Arithmetic methods rely on this invariant and their operand range contracts;
/// they do not generally recheck the modulus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct CompactModulus<T>(pub T);

impl<T: UnsignedInteger> CompactModulus<T> {
    /// Creates a [`CompactModulus<T>`] for the given modulus.
    ///
    /// # Panics
    ///
    /// Panics unless `1 < value < 2^(T::BITS - 2)`.
    #[must_use]
    #[inline(always)]
    pub fn new(value: T) -> Self {
        assert!(
            value.leading_zeros() > 1,
            "CompactModulus value must be < 2^(T::BITS - 2), got {value:?}"
        );
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

impl<T: FheUint> primus_reduce::Modulus for CompactModulus<T> {
    type ValueT = T;

    #[inline(always)]
    fn explicit_value(self) -> Option<Self::ValueT> {
        Some(self.0)
    }

    #[inline(always)]
    fn minus_one(self) -> Self::ValueT {
        debug_assert!(
            self.0 > T::ONE,
            "CompactModulus value must be greater than one"
        );
        self.0 - T::ONE
    }
}

impl<T: FheUint> primus_reduce::ExplicitModulus for CompactModulus<T> {
    #[inline(always)]
    fn value(self) -> Self::ValueT {
        self.0
    }
}
