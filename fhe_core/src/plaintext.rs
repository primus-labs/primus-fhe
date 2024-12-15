use std::{
    fmt::{Debug, Display},
    ops::{BitAnd, Shl, Shr},
};

use algebra::{modulus::PowOf2Modulus, reduce::RingReduceOps, AsCast, AsInto, Bits};
use num_traits::{ConstOne, ConstZero, NumAssign};
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
    (@ u64) => {
        impl Shrink for u64 {
            #[inline(always)]
            fn shrink(c: u64) -> u64 {
                c
            }
        }
    };
    (@@ $($M:ty),*) => {
        $(
            impl Shrink for $M {
                #[inline(always)]
                fn shrink(c: u64) -> $M {
                    if c > <$M>::MAX as u64 {
                        panic!("shrink error!")
                    } else {
                        c as $M
                    }
                }
            }
        )*
    };
    () => {
        shrink_impl!(@ bool);
        shrink_impl!(@ u64);
        shrink_impl!(@@ u8, u16, u32);
    }
}

shrink_impl!();

/// Encodes a message.
///
/// # Parameters
///
/// - `t` is message space
/// - `q` is LWE modulus value.
/// - This function needs `q` and `t` are power of 2.
///
/// # Panic
///
/// Panics if the message exceeds the message space.
#[inline]
pub fn encode<M, C>(message: M, t: u64, q: u64) -> C
where
    M: LWEMsgType,
    C: LWEModulusType,
{
    debug_assert!(q.is_power_of_two() && t.is_power_of_two());
    // Shift the message to the most significant part of `C`.
    let message: u64 = message.as_into();
    assert!(
        message < t,
        "message {message} is bigger than the message space"
    );
    let cipher: u64 = message << (q / t).trailing_zeros();
    cipher.as_into()
}

/// Decodes an encode value.
///
/// # Parameters
///
/// - `t` is message space
/// - `q` is LWE modulus value.
/// - This function needs `q` and `t` are power of 2.
///
/// # Panic
///
/// Panics if the decoded message cannot fit in `M`.
#[inline]
pub fn decode<M, C>(cipher: C, t: u64, q: u64) -> M
where
    M: LWEMsgType,
    C: LWEModulusType,
{
    debug_assert!(q.is_power_of_two() && t.is_power_of_two());
    // Move the message to the least significant part of `C`.
    // Leave one more bit for round.
    let cipher: u64 = cipher.as_into();
    let temp = cipher >> ((q / t).trailing_zeros() - 1);
    let decoded = ((temp >> 1u32) + (temp & 1)) & (t - 1);

    M::shrink(decoded)
}

/// Trait for LWE message type.
pub trait LWEMsgType: Copy + Send + Sync + AsInto<u64> + Shrink {}

macro_rules! plain_impl {
    (@ $($M:ty),*) => {
        $(
            impl LWEMsgType for $M {}
        )*
    };
    () =>{
        plain_impl!(@ bool, u8, u16, u32, u64);
    }
}

plain_impl!();

/// Trait for LWE cipher text modulus value type.
pub trait LWEModulusType:
    Sized
    + Send
    + Sync
    + Clone
    + Copy
    + Debug
    + Display
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + ConstZero
    + ConstOne
    + Bits
    + NumAssign
    + BitAnd<Output = Self>
    + Shl<usize, Output = Self>
    + Shr<usize, Output = Self>
    + Shl<u32, Output = Self>
    + Shr<u32, Output = Self>
    + AsCast
    + TryFrom<u64>
    + TryInto<usize>
    + SampleUniform
    + RingReduceOps<PowOf2Modulus<Self>>
{
    /// 2
    const TWO: Self;
    /// Generate the corresponding power of 2 modulus.
    fn to_power_of_2_modulus(self) -> PowOf2Modulus<Self>;
}

macro_rules! cipher_impl {
    ($($T:ty),*) => {
        $(
            impl LWEModulusType for $T {
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
