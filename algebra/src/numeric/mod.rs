//! Defines some traits for extended [UnsignedInteger].

use crate::integer::{AsFrom, UnsignedInteger};

mod widening;

pub use widening::*;

/// [UnsignedInteger] extended trait, insure some arithmetic operation.
pub trait Numeric: UnsignedInteger + WideningMul + CarryingMul + AsFrom<Self::WideT> {
    /// Wide type for multiplication and division.
    type WideT: UnsignedInteger + AsFrom<Self>;
}

macro_rules! impl_numeric {
    (impl Numeric for $ValueT:ty; WideType: $WideT:ty) => {
        impl Numeric for $ValueT {
            type WideT = $WideT;
        }
    };
}

impl_numeric!(impl Numeric for u8; WideType: u16);
impl_numeric!(impl Numeric for u16; WideType: u32);
impl_numeric!(impl Numeric for u32; WideType: u64);
impl_numeric!(impl Numeric for u64; WideType: u128);
