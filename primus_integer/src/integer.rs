use core::{
    fmt::{Debug, Display},
    ops::{
        BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Shl, ShlAssign, Shr,
        ShrAssign,
    },
};

use bytemuck::Pod;
use num_traits::{ConstOne, ConstZero, FromBytes, MulAdd, MulAddAssign, NumAssign, Pow, ToBytes};
use rand::distr::uniform::SampleUniform;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::integer_traits::*;

/// An abstraction over integer types.
///
/// `Integer` is the core numeric supertrait of this crate, aggregating all the
/// arithmetic, bitwise, comparison, conversion, and serialization capabilities
/// that a primitive integer-like type must provide. It is implemented for all
/// standard Rust integer types (`u8`–`u128`, `i8`–`i128`, `usize`, `isize`).
///
/// Rather than duplicating APIs, higher-level crates bound generic parameters
/// on `Integer` (or [`UnsignedInteger`](crate::UnsignedInteger)) and rely on the
/// fine-grained subtraits for specific operations such as checked,
/// wrapping, overflowing, or widening arithmetic.
pub trait Integer:
    Sized
    + Pod
    + Send
    + Sync
    + Clone
    + Copy
    + Default
    + PartialOrd
    + Ord
    + PartialEq
    + Eq
    + Debug
    + Display
    + Bits
    + ByteCount
    + ToBytes
    + FromBytes
    + ConstZero
    + ConstOne
    + ConstTwo
    + ConstBounded
    + AsCast
    + NumAssign
    + WrappingAdd
    + WrappingSub
    + WrappingNeg
    + WrappingMul
    + WrappingShl
    + WrappingShr
    + OverflowingAdd
    + OverflowingSub
    + OverflowingMul
    + CheckedAdd
    + CheckedSub
    + CheckedMul
    + CheckedDiv
    + CheckedNeg
    + CheckedRem
    + CheckedShl
    + CheckedShr
    + MulAdd
    + MulAddAssign
    + Not<Output = Self>
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + BitAndAssign
    + BitOrAssign
    + BitXorAssign
    + Shl<usize, Output = Self>
    + Shr<usize, Output = Self>
    + Shl<u32, Output = Self>
    + Shr<u32, Output = Self>
    + ShlAssign<u32>
    + ShrAssign<u32>
    + Pow<u32, Output = Self>
    + Pow<usize, Output = Self>
    + Serialize
    + for<'de> Deserialize<'de>
    + Zeroize
{
}

macro_rules! empty_trait_impl {
    ($name:ident for $($t:ty)*) => ($(
        impl $name for $t {}
    )*)
}

empty_trait_impl!(Integer for u8 u16 u32 u64 u128 usize i8 i16 i32 i64 i128 isize);

/// Signed integer types used as the scalar basis of ciphertext arithmetic.
///
/// Only `i16`, `i32`, and `i64` are included — `i8` is too narrow and `i128`
/// lacks native SIMD support.
pub trait FheInt: Integer + SampleUniform<Sampler: Copy + Send + Sync> {}

empty_trait_impl!(FheInt for i16 i32 i64 u16 u32 u64);
