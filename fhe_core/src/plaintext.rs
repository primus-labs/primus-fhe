use std::{
    fmt::Display,
    ops::{Shl, Shr},
};

use algebra::{
    modulus::PowOf2Modulus,
    reduce::{
        AddReduce, AddReduceAssign, DotProductReduce, MulReduce, MulReduceAssign, NegReduce,
        SubReduce,
    },
    AsFrom, AsInto,
};
use num_traits::{ConstOne, ConstZero, PrimInt};
use rand::distributions::uniform::SampleUniform;

pub trait Shrink {
    /// shrink to small container.
    fn shrink(c: u64) -> Self;
}

macro_rules! shrink_impl {
    (@ bool) => {
        impl Shrink for bool {
            #[inline(always)]
            fn shrink(c: u64) -> bool {
                match c {
                    0 => false,
                    1 => true,
                    _ => panic!("shrink error!")
                }
            }
        }
    };
    (@@ $($M:ty),*) => {
        $(
            impl Shrink for $M {
                #[inline(always)]
                fn shrink(c: u64) -> $M {
                    c as $M
                }
            }
        )*
    };
    () => {
        shrink_impl!(@ bool);
        shrink_impl!(@@ u8, u16, u32, u64);
    }
}

shrink_impl!();

/// Encodes a message.
///
/// `t` is message space, `q` is cipher text space.
/// This function needs `q` and `t` are power of 2.
#[inline]
pub fn encode<M, C>(message: M, t: u64, q: u64) -> C
where
    M: LWEPlainContainer,
    C: LWECipherValueContainer,
{
    // Shift the message to the most significant part of `C`.
    let message: u64 = message.as_into();
    let cipher: u64 = message << (q / t).trailing_zeros();
    cipher.as_into()
}

/// Decodes a plain text
///
/// `m` is the real message space of the scheme.
/// `t` is message space, `q` is cipher text space.
/// This function needs `q` and `t` are power of 2.
#[inline]
pub fn decode<M, C>(cipher: C, t: u64, q: u64) -> M
where
    M: LWEPlainContainer,
    C: LWECipherValueContainer,
{
    // Move the message to the least significant part of `C`.
    // Leave one more bit for round.
    let cipher: u64 = cipher.as_into();
    let temp = cipher >> ((q / t).trailing_zeros() - 1);
    let decoded = ((temp >> 1u32) + (temp & 1)) & (t - 1);

    M::shrink(decoded)
}

/// LWE plain text container trait
pub trait LWEPlainContainer: Copy + Send + Sync + AsInto<u64> + Shrink {}

macro_rules! plain_impl {
    (@ $($M:ty),*) => {
        $(
            impl LWEPlainContainer for $M {}
        )*
    };
    () =>{
        plain_impl!(@ bool, u8, u16, u32, u64);
    }
}

plain_impl!();

/// The inner value container trait of LWE cipher text.
pub trait LWECipherValueContainer:
    PrimInt
    + Send
    + Sync
    + Display
    + ConstOne
    + ConstZero
    + Shl<u32, Output = Self>
    + Shr<u32, Output = Self>
    + AsFrom<u32>
    + AsFrom<u64>
    + AsFrom<f64>
    + AsInto<f64>
    + AsInto<usize>
    + AsInto<u64>
    + TryFrom<u64>
    + TryInto<usize>
    + SampleUniform
    + AddReduce<PowOf2Modulus<Self>, Output = Self>
    + SubReduce<PowOf2Modulus<Self>, Output = Self>
    + MulReduce<PowOf2Modulus<Self>, Output = Self>
    + AddReduceAssign<PowOf2Modulus<Self>>
    + MulReduceAssign<PowOf2Modulus<Self>>
    + NegReduce<PowOf2Modulus<Self>, Output = Self>
    + DotProductReduce<PowOf2Modulus<Self>, Output = Self>
{
    /// 2
    const TWO: Self;
    /// Generate the corresponding power of 2 modulus.
    fn to_power_of_2_modulus(self) -> PowOf2Modulus<Self>;
}

macro_rules! cipher_impl {
    ($($T:ty),*) => {
        $(
            impl LWECipherValueContainer for $T {
                const TWO: Self = 2;
                #[inline]
                fn to_power_of_2_modulus(self) -> PowOf2Modulus<Self> {
                    PowOf2Modulus::<$T>::new(self)
                }
            }
        )*
    };
}

cipher_impl!(u8, u16, u32, u64);