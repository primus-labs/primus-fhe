//! Define a 128-bit chunk type and related operations.

use bytemuck::{Pod, Zeroable};
use std::{
    fmt::{Debug, Display},
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign},
};

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// A 128-bit chunk type.\
/// It is also viewed as an element in `GF(2^128)` with polynomial `x^128 + x^7 + x^2 + x + 1`\
/// Use intrinsics whenever available to speedup.\
/// Now support aarch64 and x86/x86_64
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Block(pub uint8x16_t);

/// A 128-bit chunk type.\
/// It is also viewed as an element in `GF(2^128)` with polynomial `x^128 + x^7 + x^2 + x + 1`\
/// Use intrinsics whenever available to speedup.\
/// Now support aarch64 and x86/x86_64
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Block(pub __m128i);

unsafe impl Pod for Block {}
unsafe impl Zeroable for Block {}

impl Block {
    /// The constant block with value `0`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub const ZERO: Block = Block(unsafe { std::mem::transmute::<u128, __m128i>(0u128) });

    /// The constant block with value `0`.
    #[cfg(target_arch = "aarch64")]
    pub const ZERO: Block = Block(unsafe { std::mem::transmute::<u128, uint8x16_t>(0u128) });

    #[inline(always)]
    /// New a Block with a byte slice with length 16.
    pub fn new(bytes: &[u8; 16]) -> Self {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            Self(vld1q_u8(bytes.as_ptr()))
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            Self(_mm_loadu_si128(bytes.as_ptr() as *const __m128i))
        }
    }

    /// Convert a byte slice to Block.
    #[inline(always)]
    pub fn try_from_slice(bytes_slice: &[u8]) -> Option<Self> {
        if bytes_slice.len() != 16 {
            return None;
        }
        let mut bytes: [u8; 16] = [0; 16];
        bytes[..16].clone_from_slice(&bytes_slice[..16]);
        Some(Block::new(&bytes))
    }
}
impl Default for Block {
    #[inline(always)]
    fn default() -> Self {
        Block::from(0u128)
    }
}

impl From<Block> for [u8; 16] {
    #[inline(always)]
    fn from(m: Block) -> [u8; 16] {
        bytemuck::cast(m)
    }
}

impl From<Block> for [u64; 2] {
    #[inline(always)]
    fn from(m: Block) -> Self {
        bytemuck::cast(m)
    }
}

impl From<Block> for u128 {
    #[inline(always)]
    fn from(m: Block) -> u128 {
        bytemuck::cast(m)
    }
}

impl From<[u8; 16]> for Block {
    #[inline(always)]
    fn from(m: [u8; 16]) -> Self {
        bytemuck::cast(m)
    }
}

impl From<[u64; 2]> for Block {
    #[inline(always)]
    fn from(m: [u64; 2]) -> Self {
        bytemuck::cast(m)
    }
}
impl From<u128> for Block {
    #[inline(always)]
    fn from(m: u128) -> Block {
        bytemuck::cast(m)
    }
}

impl PartialEq for Block {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        let x: u128 = (*self).into();
        let y: u128 = (*other).into();
        x == y
    }
}

impl Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let block: [u8; 16] = (*self).into();
        for byte in block.iter().rev() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let block: [u8; 16] = (*self).into();
        for byte in block.iter().rev() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl AsRef<[u8]> for Block {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }
}

impl AsMut<[u8]> for Block {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        bytemuck::bytes_of_mut(self)
    }
}

impl BitXor for Block {
    type Output = Self;
    #[inline(always)]
    fn bitxor(self, other: Self) -> Self::Output {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            Self(veorq_u8(self.0, other.0))
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            Self(_mm_xor_si128(self.0, other.0))
        }
    }
}

impl BitXorAssign for Block {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl BitOr for Block {
    type Output = Self;
    #[inline(always)]
    fn bitor(self, rhs: Self) -> Self::Output {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            Self(vorrq_u8(self.0, rhs.0))
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            Self(_mm_or_si128(self.0, rhs.0))
        }
    }
}

impl BitOrAssign for Block {
    #[inline(always)]
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs
    }
}

impl BitAnd for Block {
    type Output = Self;
    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            Self(vandq_u8(self.0, rhs.0))
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            Self(_mm_and_si128(self.0, rhs.0))
        }
    }
}

impl BitAndAssign for Block {
    #[inline(always)]
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs
    }
}

impl rand::distributions::Distribution<Block> for rand::distributions::Standard {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Block {
        Block::from(rng.gen::<u128>())
    }
}

#[test]
fn type_test() {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();

    let x: [u8; 16] = rng.gen();
    let blk = Block::from(x);
    let _x: [u8; 16] = blk.into();
    assert_eq!(x, _x);

    let x: [u64; 2] = rng.gen();
    let blk = Block::from(x);
    let _x: [u64; 2] = blk.into();
    assert_eq!(x, _x);

    let x: u128 = rng.gen();
    let blk = Block::from(x);
    let _x: u128 = blk.into();
    assert_eq!(x, _x);

    let y = blk.as_ref();
    assert_eq!(blk, Block::try_from_slice(y).unwrap());
}

#[test]
fn bit_test() {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    let x: u128 = rng.gen();
    let y: u128 = rng.gen();

    let x: Block = Block::from(x);
    let y: Block = Block::from(y);

    let _x: u128 = x.into();
    let _y: u128 = y.into();

    assert_eq!(Block::from(_x ^ _y), x ^ y);
    assert_eq!(Block::from(_x | _y), x | y);
    assert_eq!(Block::from(_x & _y), x & y);

    let mut z = x;
    z ^= y;
    assert_eq!(Block::from(_x ^ _y), z);

    z = x;
    z |= y;
    assert_eq!(Block::from(_x | _y), z);

    z = x;
    z &= y;
    assert_eq!(Block::from(_x & _y), z);
}

#[test]
fn to_bytes_test() {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();

    let x: Block = rng.gen::<u128>().into();
    assert_eq!(x, Block::try_from_slice(x.as_ref()).unwrap());

    let mut y: Block = rng.gen::<u128>().into();
    let _y = Block::try_from_slice(y.as_mut()).unwrap();
    assert_eq!(y, _y);
}
