use core::marker::PhantomData;

use primus_integer::{FheUint, UnsignedInteger};

mod ops;
mod slice;

#[cfg(feature = "simd")]
mod simd;

/// The implicit modulus `2^(T::BITS)`, implemented with wrapping arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeModulus<T: UnsignedInteger>(PhantomData<T>);

impl<T: UnsignedInteger> Default for NativeModulus<T> {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl<T: UnsignedInteger> NativeModulus<T> {
    /// Creates a [`NativeModulus<T>`].
    #[must_use]
    #[inline(always)]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: FheUint> primus_reduce::Modulus for NativeModulus<T> {
    type ValueT = T;

    #[inline(always)]
    fn explicit_value(self) -> Option<Self::ValueT> {
        None
    }

    #[inline(always)]
    fn minus_one(self) -> Self::ValueT {
        T::MAX
    }
}
