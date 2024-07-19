use std::{
    fmt::Display,
    marker::PhantomData,
    ops::{Add, BitAnd, Shl, Shr},
};

use num_traits::ConstOne;

/// A struct for `encode` and `decode`.
pub struct Code<M, C>
where
    M: Into<C>,
    C: Copy
        + ConstOne
        + Add<Output = C>
        + Shl<u32, Output = C>
        + Shr<u32, Output = C>
        + BitAnd<Output = C>,
{
    t_mask: C,
    q_bits_sub_t_bits: u32,
    phantom: PhantomData<M>,
}

impl<M, C> Code<M, C>
where
    M: Into<C> + TryFrom<C>,
    C: Copy
        + Display
        + ConstOne
        + Add<Output = C>
        + Shl<u32, Output = C>
        + Shr<u32, Output = C>
        + BitAnd<Output = C>,
{
    /// Encodes a message
    #[inline]
    pub fn encode(&self, message: M) -> C {
        message.into() << self.q_bits_sub_t_bits
    }

    /// Decodes a plain text
    #[inline]
    pub fn decode(&self, cipher: C) -> M {
        let temp = cipher >> (self.q_bits_sub_t_bits - 1);
        let decoded = ((temp >> 1) + (temp & C::ONE)) & self.t_mask;

        match M::try_from(decoded) {
            Ok(m) => m,
            Err(_) => panic!("Wrong decoding output: {}", decoded),
        }
    }
}

/// LWE bool Plain text
pub type LWEMessageType = bool;

/// LWE modulus type
pub type LWEModulusType = u16;

/// Encodes a message
#[inline]
pub fn encode(message: LWEMessageType, lwe_modulus: LWEModulusType) -> LWEModulusType {
    if message {
        // q/4
        lwe_modulus >> 2
    } else {
        0
    }
}

/// Decodes a plain text
pub fn decode(plaintext: LWEModulusType, lwe_modulus: LWEModulusType) -> LWEMessageType {
    assert!(lwe_modulus.is_power_of_two() && lwe_modulus >= 8);

    let temp = plaintext >> (lwe_modulus.trailing_zeros() - 3);
    let decoded = ((temp >> 1) + (temp & 1)) & 3;

    match decoded {
        0 => false,
        1 => true,
        _ => panic!("Wrong decoding output: {:?}", decoded),
    }
}
