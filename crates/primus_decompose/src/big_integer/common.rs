use core::{iter::FusedIterator, num::NonZeroU32, slice::Iter};

use primus_integer::{BigUint, FheUint};

/// How to initialize the carry bit and adjust a `BigUint` input before decomposition.
///
/// `threshold` is the split value: inputs `>= threshold` are adjusted by `add`.
/// `index` and `mask` select the limb and bit used to extract the initial carry.
#[derive(Debug, Clone)]
pub(super) enum BigUintValueCarryInitMode<T: FheUint> {
    /// Both adjust the value and extract a carry bit.
    AdjustAndCarry {
        /// Values `>= threshold` are adjusted.
        threshold: BigUint<Vec<T>>,
        /// Amount added to adjust the value.
        add: BigUint<Vec<T>>,
        /// Limb index used to extract the initial carry.
        index: usize,
        /// Mask applied to extract the initial carry.
        mask: T,
    },
    /// Adjust the value without extracting a carry bit.
    AdjustOnly {
        /// Values `>= threshold` are adjusted.
        threshold: BigUint<Vec<T>>,
        /// Amount added to adjust the value.
        add: BigUint<Vec<T>>,
    },
}

/// Mask to extract a window of bits from a multi-limb `BigUint`.
///
/// The window spans `bit_len(mask)` bits, starting at bit position `shr_bits`
/// within `value[index]`. When the window crosses a limb boundary (i.e.
/// `shr_bits + bit_len(mask) > T::BITS`), the upper part spills into
/// `value[index + 1]` and must be shifted back into place with `shl_bits`.
#[derive(Debug, Clone, Copy)]
pub(super) struct ValueMask<T: FheUint> {
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
    #[must_use]
    #[inline]
    pub fn new(mask: T, drop_bits: u32) -> Self {
        let index = (drop_bits / T::BITS) as usize;
        // FheUint limbs have a power-of-two bit width (16, 32, or 64).
        let shr_bits = drop_bits & (T::BITS - 1);

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

/// Extracts one signed digit from an initialized multi-limb input.
///
/// Obtain operators from [`super::BigUintApproxSignedBasis::decomposer_iter`]
/// and apply them in order to the same adjusted value. The first carry comes
/// from initialization; later carries come from the preceding level.
/// A carry can be true even when the returned digit is zero.
///
/// Full-width values have exactly the basis's `big_uint_value_len()`
/// little-endian limbs. Batch buffers are value-major, with all limbs of each
/// value contiguous. Radix-encoded digit outputs instead use one limb per value.
pub struct OnceBigUintSignedDecomposer<'a, T: FheUint> {
    pub(super) value_mask: ValueMask<T>,
    pub(super) carry_mask: T,
    pub(super) basis_minus_one: T,
    pub(super) modulus_minus_basis: BigUint<&'a [T]>,
}

impl<'a, T: FheUint> OnceBigUintSignedDecomposer<'a, T> {
    #[inline]
    fn big_uint_value_len(&self) -> usize {
        // `modulus_minus_basis` is computed in-place from the fixed-width modulus,
        // so it always has the same number of limbs as an input value.
        self.modulus_minus_basis.len()
    }

    /// Extracts a retained window plus the incoming carry, in [0, B], and
    /// advances `carry` to the next level.
    /// The signed digit is temp - next_carry*B. In particular, temp == B
    /// produces digit zero but must still carry into the next level.
    /// The two-bit mask tests temp >= B/2, including the overflow bit at B.
    #[inline]
    fn extract_with_carry(&self, value: &[T], carry: &mut bool) -> T {
        let temp = self.value_mask.get_value(value) + T::as_from(*carry);
        *carry = !(temp & self.carry_mask).is_zero();
        temp
    }

    /// Returns a signed digit encoded modulo `B`, and the next carry.
    ///
    /// The result is in `[0, B)`: values below `B/2` encode themselves, and
    /// values at or above `B/2` encode `result - B`. For example, `B - 1`
    /// encodes `-1`, not a positive digit. Unlike [`Self::decompose_slice_to`], this
    /// returns one limb rather than a residue modulo `Q`.
    /// `value` must contain exactly `big_uint_value_len()` little-endian limbs.
    /// It must be initialized with this basis and remain unchanged across
    /// levels; `carry` comes from initialization or the preceding level.
    /// When lifting to another modulus, interpret the result as a centered
    /// signed digit, not as an ordinary nonnegative residue.
    #[must_use]
    #[inline]
    pub fn decompose_radix(&self, value: &[T], mut carry: bool) -> (T, bool) {
        debug_assert_eq!(value.len(), self.big_uint_value_len());
        let temp = self.extract_with_carry(value, &mut carry);

        (temp & self.basis_minus_one, carry)
    }

    // temp is in [0,B]. A carry encodes the negative digit as Q-B+temp,
    // except temp=B: its digit is zero but the carry must still propagate.
    // The public caller has established exact input/output limb counts.
    #[inline]
    fn decompose_to_kernel(&self, value: &[T], decomposed_value: &mut [T], carry: &mut bool) {
        let temp = self.extract_with_carry(value, carry);

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

    #[inline]
    fn decompose_radix_to_kernel(&self, value: &[T], radix_digit: &mut T, carry: &mut bool) {
        let temp = self.extract_with_carry(value, carry);

        *radix_digit = temp & self.basis_minus_one;
    }

    /// Writes full-width digits modulo `Q` and advances the corresponding carries.
    ///
    /// Both value buffers must have length `carries.len() * big_uint_value_len()`
    /// in value-major layout. Inputs and carries follow [`Self::decompose_radix`].
    /// The signed digit lies in `[-B/2, B/2)`: negative digits are encoded as
    /// `Q + digit`, rather than modulo `B`. All output limbs are overwritten,
    /// not accumulated.
    #[inline]
    pub fn decompose_slice_to(
        &self,
        big_uint_values: &[T],
        decomposed_big_uint_values: &mut [T],
        carries: &mut [bool],
    ) {
        let big_uint_value_len = self.big_uint_value_len();
        debug_assert_eq!(decomposed_big_uint_values.len(), big_uint_values.len());
        debug_assert_eq!(big_uint_values.len(), carries.len() * big_uint_value_len);
        for ((value, decomposed_value), carry) in big_uint_values
            .chunks_exact(big_uint_value_len)
            .zip(decomposed_big_uint_values.chunks_exact_mut(big_uint_value_len))
            .zip(carries)
        {
            self.decompose_to_kernel(value, decomposed_value, carry);
        }
    }

    /// Writes one digit modulo `B` per adjusted input and advances its carry.
    ///
    /// `big_uint_values.len()` must equal `carries.len() * big_uint_value_len()`
    /// in value-major layout. The digit output must have `carries.len()` limbs.
    /// Inputs follow [`Self::decompose_radix`]; outputs are overwritten.
    #[inline]
    pub fn decompose_radix_slice_to(
        &self,
        big_uint_values: &[T],
        radix_digits: &mut [T],
        carries: &mut [bool],
    ) {
        let big_uint_value_len = self.big_uint_value_len();
        debug_assert_eq!(carries.len(), radix_digits.len());
        debug_assert_eq!(big_uint_values.len(), carries.len() * big_uint_value_len);
        // Constant strides let the optimizer use interleaved vector loads for
        // common widths. Choose the width once per batch.
        match big_uint_value_len {
            1 => {
                return self.decompose_radix_fixed::<1>(big_uint_values, radix_digits, carries);
            }
            2 => {
                return self.decompose_radix_fixed::<2>(big_uint_values, radix_digits, carries);
            }
            4 => {
                return self.decompose_radix_fixed::<4>(big_uint_values, radix_digits, carries);
            }
            _ => {}
        }
        for ((value, radix_digit), carry) in big_uint_values
            .chunks_exact(big_uint_value_len)
            .zip(radix_digits.iter_mut())
            .zip(carries)
        {
            self.decompose_radix_to_kernel(value, radix_digit, carry);
        }
    }

    /// The caller selected LIMBS from the basis's fixed input width.
    /// Keep these batch loops out of the caller: inlining all widths enlarges
    /// the level loop and can regress the runtime-stride fallback. One call
    /// per batch lets each fixed-stride loop be optimized independently.
    #[inline(never)]
    fn decompose_radix_fixed<const LIMBS: usize>(
        &self,
        values: &[T],
        digits: &mut [T],
        carries: &mut [bool],
    ) {
        let (values, _) = values.as_chunks::<LIMBS>();
        for ((value, digit), carry) in values.iter().zip(digits).zip(carries) {
            self.decompose_radix_to_kernel(value, digit, carry);
        }
    }
}
