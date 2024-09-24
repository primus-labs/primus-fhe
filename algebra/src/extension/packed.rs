use core::slice;
use std::{
    mem,
    ops::{Add, AddAssign, Div, Mul, MulAssign, Sub, SubAssign},
};

use crate::Field;

/// A trait to constrain types that can be packed into a packed value.
///
/// The `Packable` trait allows us to specify implementations for potentially conflicting types.
pub trait Packable: Default + Copy + Send + Sync + PartialEq + Eq {}

/// # Safety
/// - `WIDTH` is assumed to be a power of 2.
/// - If `P` implements `PackedField` then `P` must be castable to/from `[P::Value; P::WIDTH]`
///   without UB.
pub unsafe trait PackedValue: Copy + From<Self::Value> + Send + Sync {
    /// Value type
    type Value: Packable;

    /// Degree
    const WIDTH: usize;

    /// Convert from slice
    fn from_slice(slice: &[Self::Value]) -> &Self;

    /// Convert from slice mut
    fn from_mut_slice(slice: &mut [Self::Value]) -> &mut Self;

    /// Similar to `core:array::from_fn`.
    fn from_fn<F>(f: F) -> Self
    where
        F: FnMut(usize) -> Self::Value;

    /// as slice
    fn as_slice(&self) -> &[Self::Value];

    /// as mut slice
    fn as_mut_slice(&mut self) -> &mut [Self::Value];

    /// pack slice
    fn pack_slice(buf: &[Self::Value]) -> &[Self] {
        // Sources vary, but this should be true on all platforms we care about.
        // This should be a const assert, but trait methods can't access `Self` in a const context,
        // even with inner struct instantiation. So we will trust LLVM to optimize this out.
        assert!(mem::align_of::<Self>() <= mem::align_of::<Self::Value>());
        assert!(
            buf.len() % Self::WIDTH == 0,
            "Slice length (got {}) must be a multiple of packed field width ({}).",
            buf.len(),
            Self::WIDTH
        );
        let buf_ptr = buf.as_ptr().cast::<Self>();
        let n = buf.len() / Self::WIDTH;
        unsafe { slice::from_raw_parts(buf_ptr, n) }
    }

    /// pack slice with suffix
    fn pack_slice_with_suffix(buf: &[Self::Value]) -> (&[Self], &[Self::Value]) {
        let (packed, suffix) = buf.split_at(buf.len() - buf.len() % Self::WIDTH);
        (Self::pack_slice(packed), suffix)
    }

    /// pack slice mut
    fn pack_slice_mut(buf: &mut [Self::Value]) -> &mut [Self] {
        assert!(mem::align_of::<Self>() <= mem::align_of::<Self::Value>());
        assert!(
            buf.len() % Self::WIDTH == 0,
            "Slice length (got {}) must be a multiple of packed field width ({}).",
            buf.len(),
            Self::WIDTH
        );
        let buf_ptr = buf.as_mut_ptr().cast::<Self>();
        let n = buf.len() / Self::WIDTH;
        unsafe { slice::from_raw_parts_mut(buf_ptr, n) }
    }

    /// pack_slice_with_suffix_mut
    fn pack_slice_with_suffix_mut(buf: &mut [Self::Value]) -> (&mut [Self], &mut [Self::Value]) {
        let (packed, suffix) = buf.split_at_mut(buf.len() - buf.len() % Self::WIDTH);
        (Self::pack_slice_mut(packed), suffix)
    }

    /// unpack_slice
    fn unpack_slice(buf: &[Self]) -> &[Self::Value] {
        assert!(mem::align_of::<Self>() >= mem::align_of::<Self::Value>());
        let buf_ptr = buf.as_ptr().cast::<Self::Value>();
        let n = buf.len() * Self::WIDTH;
        unsafe { slice::from_raw_parts(buf_ptr, n) }
    }
}

/// # Safety
/// - See `PackedValue` above.
pub unsafe trait PackedField: Field
    + PackedValue<Value = Self::Scalar>
    + From<Self::Scalar>
    + Add<Self::Scalar, Output = Self>
    + Sub<Self::Scalar, Output = Self>
    + Mul<Self::Scalar, Output = Self>
    + AddAssign<Self::Scalar>
    + SubAssign<Self::Scalar>
    + MulAssign<Self::Scalar>
    // TODO: Implement packed / packed division
    + Div<Self::Scalar, Output = Self>
{
    /// Scalar type
    type Scalar: Field;

    /// Take interpret two vectors as chunks of `block_len` elements. Unpack and interleave those
    /// chunks. This is best seen with an example. If we have:
    /// ```text
    /// A = [x0, y0, x1, y1]
    /// B = [x2, y2, x3, y3]
    /// ```
    ///
    /// then
    ///
    /// ```text
    /// interleave(A, B, 1) = ([x0, x2, x1, x3], [y0, y2, y1, y3])
    /// ```
    ///
    /// Pairs that were adjacent in the input are at corresponding positions in the output.
    ///
    /// `r` lets us set the size of chunks we're interleaving. If we set `block_len = 2`, then for
    ///
    /// ```text
    /// A = [x0, x1, y0, y1]
    /// B = [x2, x3, y2, y3]
    /// ```
    ///
    /// we obtain
    ///
    /// ```text
    /// interleave(A, B, block_len) = ([x0, x1, x2, x3], [y0, y1, y2, y3])
    /// ```
    ///
    /// We can also think about this as stacking the vectors, dividing them into 2x2 matrices, and
    /// transposing those matrices.
    ///
    /// When `block_len == WIDTH`, this operation is a no-op. `block_len` must divide `WIDTH`. Since
    /// `WIDTH` is specified to be a power of 2, `block_len` must also be a power of 2. It cannot be
    /// 0 and it cannot exceed `WIDTH`.
    fn interleave(&self, other: Self, block_len: usize) -> (Self, Self);
}

unsafe impl<T: Packable> PackedValue for T {
    type Value = Self;

    const WIDTH: usize = 1;

    fn from_slice(slice: &[Self::Value]) -> &Self {
        &slice[0]
    }

    fn from_mut_slice(slice: &mut [Self::Value]) -> &mut Self {
        &mut slice[0]
    }

    fn from_fn<Fn>(mut f: Fn) -> Self
    where
        Fn: FnMut(usize) -> Self::Value,
    {
        f(0)
    }

    fn as_slice(&self) -> &[Self::Value] {
        slice::from_ref(self)
    }

    fn as_mut_slice(&mut self) -> &mut [Self::Value] {
        slice::from_mut(self)
    }
}

unsafe impl<F: Field + Packable> PackedField for F {
    type Scalar = Self;

    fn interleave(&self, other: Self, block_len: usize) -> (Self, Self) {
        match block_len {
            1 => (*self, other),
            _ => panic!("unsupported block length"),
        }
    }
}

impl Packable for u8 {}

impl Packable for u16 {}

impl Packable for u32 {}

impl Packable for u64 {}

impl Packable for u128 {}
