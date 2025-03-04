use std::marker::PhantomData;

use crate::{
    integer::UnsignedInteger,
    reduce::{Modulus, ModulusValue},
};

mod ops;

/// Native modulus.
///
/// - For `u8`, this type acts as `2⁸`
/// - For `u16`, this type acts as `2¹⁶`
/// - For `u32`, this type acts as `2³²`
/// - For `u64`, this type acts as `2⁶⁴`
/// - For `u128`, this type acts as `2¹²⁸`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct NativeModulus<T: UnsignedInteger> {
    phantom: PhantomData<T>,
}

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
        Self {
            phantom: PhantomData,
        }
    }
}

impl<T: UnsignedInteger> Modulus<T> for NativeModulus<T> {
    #[inline(always)]
    fn modulus_minus_one(&self) -> T {
        T::MAX
    }

    #[inline(always)]
    fn modulus_value(&self) -> ModulusValue<T> {
        ModulusValue::Native
    }

    #[inline]
    fn from_value(value: ModulusValue<T>) -> Self {
        match value {
            ModulusValue::Native => Self::new(),
            _ => panic!("The value is not a native modulus."),
        }
    }
}
