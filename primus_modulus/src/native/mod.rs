use core::marker::PhantomData;

use primus_integer::{FheUint, UnsignedInteger};

mod ops;
mod slice;

#[cfg(feature = "simd")]
mod simd;

/// Native modulus.
///
/// - For `u8`, this type acts as `2⁸`
/// - For `u16`, this type acts as `2¹⁶`
/// - For `u32`, this type acts as `2³²`
/// - For `u64`, this type acts as `2⁶⁴`
/// - For `u128`, this type acts as `2¹²⁸`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeModulus<T: UnsignedInteger>(PhantomData<T>);

impl<T: UnsignedInteger> Default for NativeModulus<T> {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl<T: UnsignedInteger> NativeModulus<T> {
    /// Creates a new [`NativeModulus<T>`].
    #[inline(always)]
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: FheUint> primus_reduce::Modulus for NativeModulus<T> {
    type ValueT = T;

    #[inline(always)]
    fn value(self) -> Option<Self::ValueT> {
        None
    }

    #[inline(always)]
    unsafe fn value_unchecked(self) -> Self::ValueT {
        panic!("The value of the Native Modulus can not be represented.");
    }

    #[inline(always)]
    fn minus_one(self) -> Self::ValueT {
        T::MAX
    }
}
