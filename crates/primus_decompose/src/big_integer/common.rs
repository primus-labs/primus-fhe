use core::{iter::FusedIterator, num::NonZeroU32, slice::Iter};

use primus_integer::{BigUint, FheUint};
use serde::{Deserialize, Serialize};

/// Mask to extract a window of bits from a multi-limb `BigUint`.
///
/// The window spans `bit_len(mask)` bits, starting at bit position `shr_bits`
/// within `value[index]`. When the window crosses a limb boundary (i.e.
/// `shr_bits + bit_len(mask) > T::BITS`), the upper part spills into
/// `value[index + 1]` and must be shifted back into place with `shl_bits`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: FheUint"))]
pub struct ValueMask<T: FheUint> {
    /// The bitmask applied after shifting — equal to `basis - 1`.
    mask: T,
    /// Which limb to read from `value[index]`.
    index: usize,
    /// Right-shift amount applied to the lower limb.
    shr_bits: u32,
    /// Left-shift amount for the upper limb, when the window crosses a limb
    /// boundary. `None` means the window fits entirely in one limb.
    ///
    /// Invariant: when `Some(n)`, `n == T::BITS - shr_bits` and `n > 0`.
    shl_bits: Option<NonZeroU32>,
}

impl<T: FheUint> ValueMask<T> {
    /// Creates a mask starting at bit offset `drop_bits`.
    ///
    /// `drop_bits` may span multiple limbs — `index` advances past whole limbs,
    /// `shr_bits` is the remainder within the current limb.
    #[inline]
    pub fn new(mask: T, drop_bits: u32) -> Self {
        let index = (drop_bits / T::BITS) as usize;
        let shr_bits = drop_bits % T::BITS;

        // The window crosses a limb boundary iff the highest set bit of `mask`,
        // left-shifted by `shr_bits`, would exceed the first limb.
        // `mask.leading_zeros()` = T::BITS - bit_len(mask), so this is:
        //     shr_bits + bit_len(mask) > T::BITS.
        let shl_bits = if mask.leading_zeros() < shr_bits {
            NonZeroU32::new(T::BITS - shr_bits)
        } else {
            None
        };

        Self {
            mask,
            index,
            shr_bits,
            shl_bits,
        }
    }

    /// Advances the window by `advance` bits for the next decomposition step.
    #[inline]
    pub fn next(mut self, advance: u32) -> Self {
        let mut shr_bits = advance + self.shr_bits;

        if shr_bits >= T::BITS {
            self.index += 1;
            shr_bits -= T::BITS;
        }

        self.shr_bits = shr_bits;
        self.shl_bits = if self.mask.leading_zeros() < shr_bits {
            NonZeroU32::new(T::BITS - shr_bits)
        } else {
            None
        };

        self
    }

    /// Extracts the masked window from `value` using shift-then-AND.
    ///
    /// On the happy path (no limb cross), this is simply
    /// `(value[index] >> shr_bits) & mask`, matching the primitive version.
    /// When the window straddles two limbs, we shift each limb independently
    /// to align the bits and OR them together before masking.
    #[inline]
    fn get_value(&self, value: &[T]) -> T {
        let lower = value[self.index] >> self.shr_bits;

        if let Some(shl_bits) = self.shl_bits {
            (lower | (value[self.index + 1] << shl_bits.get())) & self.mask
        } else {
            lower & self.mask
        }
    }
}

/// An iterator over the signed decomposition operators for [`BigUint`] values.
///
/// [`BigUint`]: primus_integer::BigUint
pub struct BigUintSignedDecomposerIter<'a, T: FheUint> {
    pub(super) value_masks: Iter<'a, ValueMask<T>>,
    pub(super) carry_mask: T,
    pub(super) basis_minus_one: T,
    pub(super) modulus_minus_basis: &'a [T],
}

impl<'a, T: FheUint> BigUintSignedDecomposerIter<'a, T> {
    #[inline]
    fn make_item(&self, value_mask: &ValueMask<T>) -> OnceBigUintSignedDecomposer<'a, T> {
        OnceBigUintSignedDecomposer {
            value_mask: *value_mask,
            carry_mask: self.carry_mask,
            basis_minus_one: self.basis_minus_one,
            modulus_minus_basis: BigUint(self.modulus_minus_basis),
        }
    }
}

impl<'a, T: FheUint> Iterator for BigUintSignedDecomposerIter<'a, T> {
    type Item = OnceBigUintSignedDecomposer<'a, T>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.value_masks.next().map(|v| self.make_item(v))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.len();
        (n, Some(n))
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.value_masks.nth(n).map(|v| self.make_item(v))
    }

    #[inline]
    fn last(mut self) -> Option<Self::Item> {
        self.next_back()
    }
}

impl<'a, T: FheUint> FusedIterator for BigUintSignedDecomposerIter<'a, T> {}

impl<'a, T: FheUint> core::iter::DoubleEndedIterator for BigUintSignedDecomposerIter<'a, T> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.value_masks.next_back().map(|v| self.make_item(v))
    }

    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.value_masks.nth_back(n).map(|v| self.make_item(v))
    }
}

impl<'a, T: FheUint> ExactSizeIterator for BigUintSignedDecomposerIter<'a, T> {
    #[inline]
    fn len(&self) -> usize {
        self.value_masks.len()
    }
}

/// The signed decomposition operator which can execute once decomposition.
pub struct OnceBigUintSignedDecomposer<'a, T: FheUint> {
    pub(super) value_mask: ValueMask<T>,
    pub(super) carry_mask: T,
    pub(super) basis_minus_one: T,
    pub(super) modulus_minus_basis: BigUint<&'a [T]>,
}

impl<'a, T: FheUint> OnceBigUintSignedDecomposer<'a, T> {
    /// Execute once decomposition and return the decomposed value and carry for next decomposition.
    #[inline]
    pub fn decompose(&self, value: &[T], carry: bool) -> (Vec<T>, bool) {
        let temp = self.value_mask.get_value(value) + T::as_from(carry);

        let next_carry = !(temp & self.carry_mask).is_zero();
        let mut result = BigUint(vec![T::ZERO; value.len()]);
        if next_carry {
            if temp <= self.basis_minus_one {
                let _ = self.modulus_minus_basis.add_value_to(temp, &mut result);
            }
        } else {
            result[0] = temp;
        }

        (result.0, next_carry)
    }

    /// Execute once unsigned decomposition and return the decomposed value and carry.
    #[inline]
    pub fn unsigned_decompose(&self, value: &[T], carry: bool) -> (T, bool) {
        let temp = self.value_mask.get_value(value) + T::as_from(carry);

        let next_carry = !(temp & self.carry_mask).is_zero();

        (temp & self.basis_minus_one, next_carry)
    }

    /// Execute once decomposition, store carry for next decomposition back to `carry`.
    #[inline]
    pub fn decompose_to(&self, value: &[T], decomposed_value: &mut [T], carry: &mut bool) {
        let temp = self.value_mask.get_value(value) + T::as_from(*carry);
        *carry = !(temp & self.carry_mask).is_zero();

        if *carry {
            if temp > self.basis_minus_one {
                decomposed_value.fill(T::ZERO);
            } else {
                let _ = self
                    .modulus_minus_basis
                    .add_value_to(temp, &mut BigUint(decomposed_value));
            }
        } else {
            decomposed_value.fill(T::ZERO);
            decomposed_value[0] = temp;
        }
    }

    /// Execute once unsigned decomposition, store carry for next decomposition back to `carry`.
    #[inline]
    pub fn unsigned_decompose_to(
        &self,
        value: &[T],
        decomposed_unsigned_value: &mut T,
        carry: &mut bool,
    ) {
        let temp = self.value_mask.get_value(value) + T::as_from(*carry);
        *carry = !(temp & self.carry_mask).is_zero();

        *decomposed_unsigned_value = temp & self.basis_minus_one;
    }

    /// Execute once decomposition for slice, store carries for next decomposition back to `carries`.
    #[inline]
    pub fn decompose_slice_to(
        &self,
        big_uint_values: &[T],
        decomposed_big_uint_values: &mut [T],
        carries: &mut [bool],
        big_uint_value_len: usize,
    ) {
        debug_assert_eq!(decomposed_big_uint_values.len(), big_uint_values.len());
        debug_assert_eq!(big_uint_values.len(), carries.len() * big_uint_value_len);
        for ((value, decomposed_value), carry) in big_uint_values
            .chunks_exact(big_uint_value_len)
            .zip(decomposed_big_uint_values.chunks_exact_mut(big_uint_value_len))
            .zip(carries)
        {
            self.decompose_to(value, decomposed_value, carry);
        }
    }

    /// Execute once unsigned decomposition for slice, store carries for next decomposition back to `carries`.
    #[inline]
    pub fn unsigned_decompose_slice_to(
        &self,
        big_uint_values: &[T],
        decomposed_unsigned_values: &mut [T],
        carries: &mut [bool],
        big_uint_value_len: usize,
    ) {
        debug_assert_eq!(carries.len(), decomposed_unsigned_values.len());
        debug_assert_eq!(big_uint_values.len(), carries.len() * big_uint_value_len);
        for ((value, decomposed_unsigned_value), carry) in big_uint_values
            .chunks_exact(big_uint_value_len)
            .zip(decomposed_unsigned_values.iter_mut())
            .zip(carries)
        {
            self.unsigned_decompose_to(value, decomposed_unsigned_value, carry);
        }
    }
}
