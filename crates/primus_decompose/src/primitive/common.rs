use core::{iter::FusedIterator, slice::Iter};

use primus_integer::FheUint;

/// How to initialize the carry bit and adjust the input value before decomposition.
///
/// For non-power-of-two moduli, values near the top of the range may need to
/// wrap around (by adding `2^value_bits - modulus`) and/or set an initial carry
/// to ensure the decomposition is approximately correct.
#[derive(Debug, Clone, Copy)]
pub(super) enum ValueCarryInitMode<T: FheUint> {
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

/// Mask to extract a window of bits from a single-limb value.
///
/// The window spans `bit_len(mask)` bits, starting at bit position `shr_bits`.
/// Extraction uses shift-then-AND: `(value >> shr_bits) & mask`.
#[derive(Debug, Clone, Copy)]
pub(super) struct ValueMask<T: FheUint> {
    /// The bitmask applied after shifting — equal to `basis - 1`.
    mask: T,
    /// Right-shift amount applied before masking.
    shr_bits: u32,
}

impl<T: FheUint> ValueMask<T> {
    /// Creates a mask starting at bit offset `drop_bits`.
    #[must_use]
    #[inline]
    pub fn new(mask: T, drop_bits: u32) -> Self {
        Self {
            mask,
            shr_bits: drop_bits,
        }
    }

    /// Extracts the masked window from `value`.
    #[must_use]
    #[inline]
    pub fn get_value(&self, value: T) -> T {
        (value >> self.shr_bits) & self.mask
    }
}

/// An iterator over the signed decomposition operators.
pub struct SignedDecomposerIter<'a, T: FheUint> {
    pub(super) value_masks: Iter<'a, ValueMask<T>>,
    pub(super) carry_mask: T,
    pub(super) basis_minus_one: T,
    pub(super) modulus_minus_basis: T,
}

impl<'a, T: FheUint> SignedDecomposerIter<'a, T> {
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

impl<'a, T: FheUint> Iterator for SignedDecomposerIter<'a, T> {
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

impl<'a, T: FheUint> FusedIterator for SignedDecomposerIter<'a, T> {}

impl<'a, T: FheUint> core::iter::DoubleEndedIterator for SignedDecomposerIter<'a, T> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.value_masks.next_back().map(|v| self.make_item(v))
    }

    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.value_masks.nth_back(n).map(|v| self.make_item(v))
    }
}

impl<'a, T: FheUint> ExactSizeIterator for SignedDecomposerIter<'a, T> {
    #[inline]
    fn len(&self) -> usize {
        self.value_masks.len()
    }
}

/// Extracts one signed digit from an initialized decomposition input.
///
/// Obtain operators from [`super::ApproxSignedBasis::decomposer_iter`] and
/// apply them in order to the same adjusted value. The first carry comes
/// from initialization; later carries come from the preceding level.
/// A carry can be true even when the returned digit is zero.
pub struct OnceSignedDecomposer<T: FheUint> {
    value_mask: ValueMask<T>,
    carry_mask: T,
    basis_minus_one: T,
    modulus_minus_basis: T,
}

impl<T: FheUint> OnceSignedDecomposer<T> {
    /// Returns a digit encoded modulo `q` and the carry for the next level.
    ///
    /// The signed digit lies in `[-B/2, B/2)`. Negative digits are represented
    /// by `q + digit`, using `q = 2^T::BITS` for the implicit native modulus.
    /// `value` and `carry` must follow this operator's initialization protocol.
    #[must_use]
    #[inline]
    pub fn decompose(&self, value: T, carry: bool) -> (T, bool) {
        let mut temp = self.value_mask.get_value(value) + T::as_from(carry);

        // temp is in [0, B]. The two-bit mask tests temp >= B/2, including B.
        // Subtracting B gives [-B/2, B/2); temp == B is zero with a carry.
        let next_carry = !(temp & self.carry_mask).is_zero();
        if next_carry {
            if temp > self.basis_minus_one {
                temp = T::ZERO;
            } else {
                temp += self.modulus_minus_basis;
            }
        }

        (temp, next_carry)
    }

    /// Overwrites the digit output and advances `carry`, as in [`Self::decompose`].
    #[inline]
    fn decompose_to(&self, value: T, decomposed_value: &mut T, carry: &mut bool) {
        let temp = self.value_mask.get_value(value) + T::as_from(*carry);
        // Keep this output kernel separate from the value-returning version.
        // Routing either through the other regressed batch decomposition or
        // LWE key switching in benchmarks by changing LLVM's scheduling.
        *carry = !(temp & self.carry_mask).is_zero();
        if *carry {
            if temp > self.basis_minus_one {
                *decomposed_value = T::ZERO;
            } else {
                *decomposed_value = temp + self.modulus_minus_basis;
            }
        } else {
            *decomposed_value = temp;
        }
    }

    /// Writes one digit per adjusted input and advances the corresponding carries.
    ///
    /// All slices must have equal lengths. Each input and carry must follow
    /// [`Self::decompose`]; `decomposed_values` is overwritten, not accumulated.
    #[inline]
    pub fn decompose_slice_to(
        &self,
        values: &[T],
        decomposed_values: &mut [T],
        carries: &mut [bool],
    ) {
        debug_assert_eq!(values.len(), decomposed_values.len());
        debug_assert_eq!(values.len(), carries.len());

        for ((&value, decomposed_value), carry) in values.iter().zip(decomposed_values).zip(carries)
        {
            self.decompose_to(value, decomposed_value, carry);
        }
    }
}
