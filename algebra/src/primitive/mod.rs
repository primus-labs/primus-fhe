use std::{
    fmt::{Debug, Display},
    ops::{
        Add, AddAssign, BitAnd, BitOr, BitXor, Mul, MulAssign, Not, Shl, ShlAssign, Shr, ShrAssign,
        Sub, SubAssign,
    },
};

use num_traits::{ConstOne, ConstZero, NumAssign};

mod bits;
mod bounded;
mod cast;
mod neg_one;
mod widening;
mod wrapping;

pub use bits::Bits;
pub use bounded::ConstBounded;
pub use cast::*;
pub use neg_one::{ConstNegOne, NegOne};
use rand_distr::uniform::SampleUniform;
pub use widening::*;
pub use wrapping::*;

use crate::{
    random::UniformBase,
    reduce::{
        AddReduce, AddReduceAssign, NegReduce, NegReduceAssign, SubReduce, SubReduceAssign,
        TryInvReduce,
    },
};

/// Define the primitive value type in `Field`.
pub trait Primitive:
    Sized
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
    + ConstBounded
    + NumAssign
    + Into<u64>
    + AsCast
    + AsFrom<bool>
    + Widening
    + WrappingOps
    + UniformBase
    + Not<Output = Self>
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + Shl<usize, Output = Self>
    + Shr<usize, Output = Self>
    + Shl<u32, Output = Self>
    + Shr<u32, Output = Self>
    + ShlAssign<u32>
    + ShrAssign<u32>
    + AddReduce<Self, Output = Self>
    + SubReduce<Self, Output = Self>
    + NegReduce<Self, Output = Self>
    + AddReduceAssign<Self>
    + SubReduceAssign<Self>
    + NegReduceAssign<Self>
    + TryInvReduce<Self>
    + SampleUniform
    + AsFrom<usize> //For NTT, calculates `N^{-1}`
{
}

impl Primitive for u8 {}
impl Primitive for u16 {}
impl Primitive for u32 {}
impl Primitive for u64 {}

///
pub trait AddOps
where
    Self: Copy
        + ConstZero
        + Add<Self, Output = Self>
        + AddAssign<Self>
        + for<'a> Add<&'a Self, Output = Self>
        + for<'a> AddAssign<&'a Self>,
{
}

impl<T> AddOps for T where
    Self: Copy
        + ConstZero
        + Add<Self, Output = Self>
        + AddAssign<Self>
        + for<'a> Add<&'a Self, Output = Self>
        + for<'a> AddAssign<&'a Self>
{
}

///
pub trait SubOps
where
    Self: Copy
        + ConstZero
        + Sub<Self, Output = Self>
        + SubAssign<Self>
        + for<'a> Sub<&'a Self, Output = Self>
        + for<'a> SubAssign<&'a Self>,
{
}

impl<T> SubOps for T where
    Self: Copy
        + ConstZero
        + Sub<Self, Output = Self>
        + SubAssign<Self>
        + for<'a> Sub<&'a Self, Output = Self>
        + for<'a> SubAssign<&'a Self>
{
}

///
pub trait MulOps
where
    Self: Copy
        + ConstOne
        + Mul<Self, Output = Self>
        + MulAssign<Self>
        + for<'a> Mul<&'a Self, Output = Self>
        + for<'a> MulAssign<&'a Self>,
{
}

impl<T> MulOps for T where
    Self: Copy
        + ConstOne
        + Mul<Self, Output = Self>
        + MulAssign<Self>
        + for<'a> Mul<&'a Self, Output = Self>
        + for<'a> MulAssign<&'a Self>
{
}
