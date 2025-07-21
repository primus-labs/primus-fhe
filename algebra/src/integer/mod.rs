//! Defines some traits and operation for integer.

mod bits;
mod bounded;
mod cast;
mod checked;
mod overflowing;
mod two;
mod wrapping;

use core::{
    fmt::{Debug, Display},
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, Not, Shl, ShlAssign, Shr, ShrAssign},
};
use std::ops::BitXorAssign;

use num_traits::{ConstOne, ConstZero, MulAdd, MulAddAssign, NumAssign, Pow, Unsigned};
use rand::distributions::uniform::SampleUniform;

use crate::numeric::{BorrowingSub, CarryingAdd};
use crate::reduce::*;

pub use bits::Bits;
pub use bounded::ConstBounded;
pub use cast::*;
pub use checked::*;
pub use overflowing::*;
pub use two::ConstTwo;
pub use wrapping::*;

/// An abstract over interger type.
pub trait Integer:
    'static
    + Sized
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
    + ConstZero
    + ConstOne
    + ConstTwo
    + ConstBounded
    + AsCast
    + AsFrom<bool>
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
    + SampleUniform<Sampler: Copy + Clone>
{
}

/// An abstract over unsigned interger type.
pub trait UnsignedInteger:
    Integer
    + Unsigned
    + CarryingAdd<CarryT = bool>
    + BorrowingSub<BorrowT = bool>
    + ReduceOnce<Self, Output = Self>
    + ReduceAdd<Self, Output = Self>
    + ReduceSub<Self, Output = Self>
    + ReduceNeg<Self, Output = Self>
    + ReduceDouble<Self, Output = Self>
    + ReduceOnceAssign<Self>
    + ReduceAddAssign<Self>
    + ReduceSubAssign<Self>
    + ReduceNegAssign<Self>
    + ReduceDoubleAssign<Self>
    + ReduceInv<Self, Output = Self>
    + ReduceInvAssign<Self>
    + TryReduceInv<Self, Output = Self>
    + TryFrom<usize>
    + TryInto<usize>
{
    /// Returns `true` if and only if `self == 2^k` for some `k`.
    #[must_use]
    #[inline(always)]
    fn is_power_of_two(self) -> bool {
        self.count_ones() == 1
    }
}

macro_rules! empty_trait_impl {
    ($name:ident for $($t:ty)*) => ($(
        impl $name for $t {}
    )*)
}

empty_trait_impl!(Integer for u8 u16 u32 u64 u128 usize i8 i16 i32 i64 i128 isize);

empty_trait_impl!(UnsignedInteger for u8 u16 u32 u64 u128 usize);
