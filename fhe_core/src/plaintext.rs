use std::{
    fmt::Display,
    marker::PhantomData,
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

pub trait Shrink<C> {
    /// shrink to small container.
    fn shrink(c: C) -> Self;
}

macro_rules! shrink_impl {
    (@ bool, $($C:ty),*) => {
        impl Shrink<bool> for bool {
            #[inline(always)]
            fn shrink(c: bool) -> bool {
                c
            }

        }
        $(
            impl Shrink<$C> for bool {
                #[inline]
                fn shrink(c: $C) -> bool {
                    match c {
                        0 => false,
                        1 => true,
                        _ => panic!("shrink error!")
                    }
                }

            }
        )*
    };
    (@@ $M:ty, $($C:ty),*) => {
        impl Shrink<$M> for $M {
            #[inline(always)]
            fn shrink(c: $M) -> $M {
                c
            }

        }
        $(
            impl Shrink<$C> for $M {
                #[inline(always)]
                fn shrink(c: $C) -> $M {
                    c.try_into().unwrap()
                }

            }
        )*
    };
    () =>{
        shrink_impl!(@ bool, u8, u16, u32, u64);
        shrink_impl!(@@ u8, u16, u32, u64);
        shrink_impl!(@@ u16, u32, u64);
        shrink_impl!(@@ u32, u64);
        shrink_impl!(@@ u64,);
    }
}

shrink_impl!();

#[derive(Debug, Clone, Copy)]
/// A struct for `encode` and `decode`.
pub struct Code<M, C>
where
    M: LWEPlainContainer<C>,
    C: LWECipherContainer,
{
    /// Refer to `m` of the LWE,
    /// which is the real message space of the scheme.
    real_message_size: C,
    /// Refer to `t-1` of the LWE.
    /// 
    /// `t` is message space which is used to perform LWE operation.
    t_mask: C,
    /// `q`'s bit count sub `t`'s bit count.
    q_bits_sub_t_bits: u32,
    phantom: PhantomData<M>,
}

impl<M, C> Code<M, C>
where
    M: LWEPlainContainer<C>,
    C: LWECipherContainer,
{
    /// Generate the coder.
    #[inline]
    pub fn new(real_message_size: C, padding_message_size: C, q: C) -> Self {
        assert!(real_message_size <= padding_message_size && padding_message_size < q);
        assert!(padding_message_size.count_ones() == 1);
        assert!(q.count_ones() == 1);
        let t_bits = padding_message_size.trailing_zeros();
        let q_bits = q.trailing_zeros();
        let q_bits_sub_t_bits = q_bits - t_bits;

        Self {
            real_message_size,
            t_mask: padding_message_size - C::ONE,
            q_bits_sub_t_bits,
            phantom: PhantomData,
        }
    }

    /// Encodes a message
    #[inline]
    pub fn encode(&self, message: M) -> C {
        // Shift the message to the most significant part of `C`.
        message.into() << self.q_bits_sub_t_bits
    }

    /// Decodes a plain text
    #[inline]
    pub fn decode(&self, cipher: C) -> M {
        // Move the message to the least significant part of `C`. 
        // Leave one more bit for round.
        let temp = cipher >> (self.q_bits_sub_t_bits - 1);
        let decoded = ((temp >> 1u32) + (temp & C::ONE)) & self.t_mask;

        assert!(decoded <= self.real_message_size);

        M::shrink(decoded)
    }
}

/// LWE plain text container trait
pub trait LWEPlainContainer<C>: Copy + Send + Sync + Into<C> + Shrink<C> {}

macro_rules! plain_impl {
    (@ $M:ty, $($C:ty),*) => {
        impl LWEPlainContainer<$M> for $M {}
        $(
            impl LWEPlainContainer<$C> for $M {}
        )*
    };
    () =>{
        plain_impl!(@ bool, u8, u16, u32, u64);
        plain_impl!(@ u8, u16, u32, u64);
        plain_impl!(@ u16, u32, u64);
        plain_impl!(@ u32, u64);
        plain_impl!(@ u64,);


    }
}

plain_impl!();

/// LWE cipher text container trait
pub trait LWECipherContainer:
    PrimInt
    + Send
    + Sync
    + Display
    + ConstOne
    + ConstZero
    + Shl<u32, Output = Self>
    + Shr<u32, Output = Self>
    + AsFrom<u32>
    + AsFrom<f64>
    + AsInto<f64>
    + AsInto<usize>
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
            impl LWECipherContainer for $T {
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
