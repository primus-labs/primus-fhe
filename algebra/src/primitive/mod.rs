use std::{
    fmt::{Debug, Display},
    ops::{Shl, ShlAssign, Shr, ShrAssign},
};

use num_traits::{ConstOne, ConstZero, NumAssign, PrimInt};

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
pub use widening::*;
pub use wrapping::*;

use crate::random::UniformBase;

/// Define the primitive value type in `Field`.
pub trait Primitive:
    Debug
    + Display
    + Send
    + Sync
    + PrimInt
    + Bits
    + ConstZero
    + ConstOne
    + ConstBounded
    + NumAssign
    + Widening
    + WrappingOps
    + Into<u64>
    + AsCast
    + UniformBase
    + Shl<u32, Output = Self>
    + Shr<u32, Output = Self>
    + ShlAssign<u32>
    + ShrAssign<u32>
{
}

impl Primitive for u8 {}
impl Primitive for u16 {}
impl Primitive for u32 {}
impl Primitive for u64 {}
