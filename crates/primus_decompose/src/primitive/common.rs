use core::{
    iter::{Copied, FusedIterator},
    slice::Iter,
};

use primus_integer::FheUint;
use serde::{Deserialize, Serialize};

/// How to initialize the carry bit and adjust the input value before decomposition.
///
/// For non-power-of-two moduli, values near the top of the range may need to
/// wrap around (by adding `2^value_bits - modulus`) and/or set an initial carry
/// to ensure the decomposition is approximately correct.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: FheUint"))]
pub enum ValueCarryInitMode<T: FheUint> {
    /// Both adjust the value and extract a carry bit.
    AdjustAndCarry {
        /// Values `>= threshold` are adjusted by `add`.
        threshold: T,
        /// Amount added to adjust the value.
        add: T,
        /// Mask applied to extract the initial carry.
        mask: T,
    },
    /// Extract a carry bit from the value without adjustment.
    CarryOnly {
        /// Mask applied to extract the initial carry.
        mask: T,
    },
    /// Adjust the value without extracting a carry bit.
    AdjustOnly {
        /// Values `>= threshold` are adjusted by `add`.
        threshold: T,
        /// Amount added to adjust the value.
        add: T,
    },
    /// No adjustment and no initial carry — value passes through unchanged.
    Plain,
}

/// An iterator over scalars.
pub struct ScalarIter<'a, T: FheUint> {
    iter: Copied<Iter<'a, T>>,
}

impl<'a, T: FheUint> ScalarIter<'a, T> {
    /// Creates a new [`ScalarIter<T>`].
    #[inline]
    pub fn new(scalars: &'a [T]) -> Self {
        Self {
            iter: scalars.iter().copied(),
        }
    }
}

impl<'a, T: FheUint> Iterator for ScalarIter<'a, T> {
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
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
        self.iter.nth(n)
    }

    #[inline]
    fn last(mut self) -> Option<Self::Item> {
        self.next_back()
    }
}

impl<'a, T: FheUint> FusedIterator for ScalarIter<'a, T> {}

impl<'a, T: FheUint> core::iter::DoubleEndedIterator for ScalarIter<'a, T> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back()
    }

    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth_back(n)
    }
}

impl<'a, T: FheUint> ExactSizeIterator for ScalarIter<'a, T> {
    #[inline]
    fn len(&self) -> usize {
        self.iter.len()
    }
}

/// Mask to extract a window of bits from a single-limb value.
///
/// The window spans `bit_len(mask)` bits, starting at bit position `shr_bits`.
/// Extraction uses shift-then-AND: `(value >> shr_bits) & mask`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: FheUint"))]
pub struct ValueMask<T: FheUint> {
    /// The bitmask applied after shifting — equal to `basis - 1`.
    mask: T,
    /// Right-shift amount applied before masking.
    shr_bits: u32,
}

impl<T: FheUint> ValueMask<T> {
    /// Creates a mask starting at bit offset `drop_bits`.
    #[inline]
    pub fn new(mask: T, drop_bits: u32) -> Self {
        Self {
            mask,
            shr_bits: drop_bits,
        }
    }

    /// Advances the window by `advance` bits for the next decomposition step.
    #[inline]
    pub fn next(self, advance: u32) -> Self {
        Self {
            mask: self.mask,
            shr_bits: self.shr_bits + advance,
        }
    }

    /// Extracts the masked window from `value`.
    #[inline]
    pub fn get_value(&self, value: T) -> T {
        (value >> self.shr_bits) & self.mask
    }
}

/// An iterator over the signed decomposition operators.
pub struct SignedDecomposeIter<'a, T: FheUint> {
    pub(super) value_masks: Iter<'a, ValueMask<T>>,
    pub(super) carry_mask: T,
    pub(super) basis_minus_one: T,
    pub(super) modulus_minus_basis: T,
}

impl<'a, T: FheUint> SignedDecomposeIter<'a, T> {
    #[inline]
    fn make_item(&self, value_mask: &ValueMask<T>) -> OnceSignedDecomposer<T> {
        OnceSignedDecomposer {
            value_mask: *value_mask,
            carry_mask: self.carry_mask,
            basis_minus_one: self.basis_minus_one,
            modulus_minus_basis: self.modulus_minus_basis,
        }
    }
}

impl<'a, T: FheUint> Iterator for SignedDecomposeIter<'a, T> {
    type Item = OnceSignedDecomposer<T>;

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

impl<'a, T: FheUint> FusedIterator for SignedDecomposeIter<'a, T> {}

impl<'a, T: FheUint> core::iter::DoubleEndedIterator for SignedDecomposeIter<'a, T> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.value_masks.next_back().map(|v| self.make_item(v))
    }

    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.value_masks.nth_back(n).map(|v| self.make_item(v))
    }
}

impl<'a, T: FheUint> ExactSizeIterator for SignedDecomposeIter<'a, T> {
    #[inline]
    fn len(&self) -> usize {
        self.value_masks.len()
    }
}

/// The signed decomposition operator which can execute once decomposition.
pub struct OnceSignedDecomposer<T: FheUint> {
    value_mask: ValueMask<T>,
    carry_mask: T,
    basis_minus_one: T,
    modulus_minus_basis: T,
}

impl<T: FheUint> OnceSignedDecomposer<T> {
    /// Execute once decomposition and return the decomposed value and carry for next decomposition.
    #[inline]
    pub fn decompose(&self, value: T, carry: bool) -> (T, bool) {
        let mut temp = self.value_mask.get_value(value) + T::as_from(carry);

        let next_carry = !(temp & self.carry_mask).is_zero();
        if next_carry {
            if temp > self.basis_minus_one {
                temp = T::ZERO;
            } else {
                temp += self.modulus_minus_basis
            }
        }

        (temp, next_carry)
    }

    /// Execute once decomposition, store carry for next decomposition back to `carry`.
    #[inline]
    pub fn decompose_to(&self, value: T, decomposed_value: &mut T, carry: &mut bool) {
        let temp = self.value_mask.get_value(value) + T::as_from(*carry);
        *carry = !(temp & self.carry_mask).is_zero();

        if *carry {
            if temp > self.basis_minus_one {
                *decomposed_value = T::ZERO;
            } else {
                *decomposed_value = temp + self.modulus_minus_basis
            }
        } else {
            *decomposed_value = temp;
        }
    }

    /// Execute once decomposition for slice, store carries for next decomposition back to `carries`.
    #[inline]
    pub fn decompose_slice_to(
        &self,
        values: &[T],
        decomposed_values: &mut [T],
        carries: &mut [bool],
    ) {
        for ((&value, decomposed_value), carry) in values.iter().zip(decomposed_values).zip(carries)
        {
            self.decompose_to(value, decomposed_value, carry);
        }
    }
}
