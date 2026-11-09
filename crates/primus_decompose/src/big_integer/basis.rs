use primus_integer::{BigUint, BigUintIter, BigUintIterMut, DivRem, FheUint};

use crate::{
    ApproxSignedBasisError, DecompositionBaseLog, DecompositionLevelCount,
    level_count_and_drop_bits,
};

use super::common::{BigUintSignedDecomposerIter, BigUintValueCarryInitMode, ValueMask};

/// Precomputed approximate signed decomposition modulo a multi-limb integer `Q`.
///
/// With radix `B = 2^log_basis`, level `i` has weight `2^drop_bits * B^i`.
/// Digits lie in `[-B/2, B/2)` and are visited from the lowest retained level
/// to the highest. Their weighted sum approximates the input modulo `Q`;
/// [`Self::approximate_error_bound`] bounds the circular distance modulo `Q`.
///
/// The decomposition width is `m = bit_width(Q)`, including when `Q` is a
/// power of two. The full level count is `m / log_basis`; retaining `k`
/// levels leaves `drop_bits = m - k * log_basis`. Unlike the primitive
/// basis, this representation always uses the adjusted-input protocol.
///
/// Inputs and full-width outputs use exactly [`Self::big_uint_value_len`]
/// little-endian limbs per value. Batches are value-major: each consecutive
/// chunk contains all limbs of one value, unlike modulus-major RNS residues.
#[derive(Debug, Clone)]
pub struct BigUintApproxSignedBasis<T: FheUint> {
    modulus: Vec<T>,
    basis: T,
    basis_minus_one: T,
    level_count: DecompositionLevelCount,
    log_basis: DecompositionBaseLog,
    drop_bits: u32,
    value_carry_init_mode: BigUintValueCarryInitMode<T>,
    carry_mask: T,
    modulus_sub_basis: Vec<T>,
    scalars: Vec<T>,
    value_masks: Vec<ValueMask<T>>,
}

impl<T: FheUint> BigUintApproxSignedBasis<T> {
    /// Creates a decomposition basis for the given integer modulus.
    ///
    /// `modulus` must be nonempty, with little-endian limbs and a nonzero
    /// most-significant limb. The basis owns a copy of the modulus.
    /// `log_basis` is the base-2 logarithm of the decomposition basis
    /// (`basis = 2^log_basis`) and must satisfy `2 <= log_basis < T::BITS`.
    /// `level_count` selects how many highest decomposition levels to retain;
    /// `None` uses the full level count. Retaining fewer levels discards more low bits.
    ///
    /// # Panics
    ///
    /// Panics when [`try_new`](Self::try_new) returns an error.
    #[must_use]
    #[inline]
    pub fn new(
        modulus: BigUint<&[T]>,
        log_basis: DecompositionBaseLog,
        level_count: Option<DecompositionLevelCount>,
    ) -> Self {
        Self::try_new(modulus, log_basis, level_count).unwrap_or_else(|error| {
            panic!("failed to construct BigUint approximate signed basis: {error}")
        })
    }

    /// Tries to create a decomposition basis for the given modulus.
    ///
    /// `modulus` must be nonempty, with little-endian limbs and a nonzero
    /// most-significant limb. `log_basis` must satisfy
    /// `log_basis < T::BITS` (its lower bound is already checked), and `2^log_basis` must not
    /// exceed that modulus. `level_count`, when provided, must be in the
    /// range `1..=full_level_count`; positivity is already checked.
    /// It retains the highest levels; iteration still proceeds from the
    /// lowest retained level to the highest.
    /// The modulus bit width and offsets use `u32`; the packed scalar
    /// element count must fit `usize`. These ranges are checked here,
    /// before allocating the precomputed basis storage.
    ///
    /// # Errors
    ///
    /// Returns [`ApproxSignedBasisError`] when any parameter is invalid.
    #[inline]
    pub fn try_new(
        modulus: BigUint<&[T]>,
        log_basis: DecompositionBaseLog,
        level_count: Option<DecompositionLevelCount>,
    ) -> Result<Self, ApproxSignedBasisError> {
        if log_basis.get() >= T::BITS {
            return Err(ApproxSignedBasisError::InvalidLogBasis {
                log_basis: log_basis.get(),
                limb_bits: T::BITS,
            });
        }

        let big_uint_value_len = modulus.len();
        let unused_bits = match modulus.0.last() {
            Some(high) if !high.is_zero() => high.leading_zeros(),
            _ => return Err(ApproxSignedBasisError::InvalidModulusRepresentation),
        };
        let modulus_bits_count = modulus
            .checked_bit_width()
            .ok_or(ApproxSignedBasisError::ModulusBitWidthTooLarge)?;
        if modulus_bits_count <= log_basis.get() {
            return Err(ApproxSignedBasisError::BasisExceedsModulus);
        }

        let checked_log_basis = log_basis;
        let log_basis = log_basis.get();
        let basis = T::ONE << log_basis;
        let basis_minus_one = basis - T::ONE;
        let (level_count, drop_bits) =
            level_count_and_drop_bits(modulus_bits_count, checked_log_basis, level_count)?;
        let checked_level_count = level_count;
        let level_count = level_count.get();
        let scalar_storage_len = big_uint_value_len.checked_mul(level_count).ok_or(
            ApproxSignedBasisError::ScalarStorageLengthOverflow {
                limb_count: big_uint_value_len,
                level_count,
            },
        )?;

        let init_carry_mask = if drop_bits > 0 {
            let bits = drop_bits - 1;

            let (index, bits) = bits.div_rem(T::BITS);
            Some((index as usize, T::ONE << bits))
        } else {
            None
        };

        let carry_mask = (T::ONE << log_basis) | (T::ONE << (log_basis - 1));

        let threshold = wrap_threshold(big_uint_value_len, log_basis, level_count, drop_bits);

        let mut modulus_sub_basis = BigUint(modulus.0.to_vec());
        let borrow = modulus_sub_basis.sub_value_assign(basis);
        debug_assert!(!borrow);

        // (2^m - 1) - Q + 1 avoids representing 2^m or allocating Q - 1.
        let mut add = BigUint(vec![T::MAX; big_uint_value_len]);
        add[big_uint_value_len - 1] >>= unused_bits;
        let borrow = add.sub_assign(&modulus);
        debug_assert!(!borrow);
        let carry = add.add_value_assign(T::ONE);
        debug_assert!(!carry);

        let mut scalars = vec![T::ZERO; scalar_storage_len];
        let mut value_masks = Vec::with_capacity(level_count);
        // Each reconstruction weight is a single bit, including when the
        // lowest retained level starts beyond the first limb. With m the
        // checked modulus width and d=m-L*log_basis, every offset satisfies
        // d+i*log_basis <= m-log_basis. Thus the offset fits u32 and the
        // whole extraction window lies within the modulus's limb storage.
        for (level, scalar) in scalars.chunks_exact_mut(big_uint_value_len).enumerate() {
            let bit = drop_bits + level as u32 * log_basis;
            let (index, shift) = bit.div_rem(T::BITS);
            scalar[index as usize] = T::ONE << shift;
            value_masks.push(ValueMask::new(basis_minus_one, bit));
        }

        // Every valid BigUint modulus has a negative region to adjust.
        // Only the presence of an initial rounding carry varies.
        let value_carry_init_mode = match init_carry_mask {
            Some((index, mask)) => BigUintValueCarryInitMode::AdjustAndCarry {
                threshold,
                add,
                index,
                mask,
            },
            None => BigUintValueCarryInitMode::AdjustOnly { threshold, add },
        };

        Ok(Self {
            modulus: modulus.0.to_vec(),
            basis,
            basis_minus_one,
            level_count: checked_level_count,
            log_basis: checked_log_basis,
            drop_bits,
            value_carry_init_mode,
            carry_mask,
            modulus_sub_basis: modulus_sub_basis.0,
            scalars,
            value_masks,
        })
    }

    /// Returns a reference to the modulus of this [`BigUintApproxSignedBasis<T>`].
    #[must_use]
    #[inline]
    pub fn modulus(&self) -> &[T] {
        &self.modulus
    }

    /// Returns the number of limbs in each fixed-width [`BigUint`] value.
    #[must_use]
    #[inline]
    pub fn big_uint_value_len(&self) -> usize {
        self.modulus.len()
    }

    /// Returns the basis of this [`BigUintApproxSignedBasis<T>`].
    #[must_use]
    #[inline]
    pub fn basis_value(&self) -> T {
        self.basis
    }

    /// Returns the retained level count of this [`BigUintApproxSignedBasis<T>`].
    #[must_use]
    #[inline]
    pub fn level_count(&self) -> DecompositionLevelCount {
        self.level_count
    }

    /// Returns the log basis of this [`BigUintApproxSignedBasis<T>`].
    #[must_use]
    #[inline]
    pub fn log_basis(&self) -> DecompositionBaseLog {
        self.log_basis
    }

    /// Returns the drop bits of this [`BigUintApproxSignedBasis<T>`].
    #[must_use]
    #[inline]
    pub fn drop_bits(&self) -> u32 {
        self.drop_bits
    }

    /// Returns the maximum approximation error caused by the dropped low bits.
    ///
    /// This is `0` when no bits are dropped, otherwise `2^(drop_bits - 1)`.
    /// Error is measured as circular distance modulo `Q`.
    #[must_use]
    #[inline]
    pub fn approximate_error_bound(&self) -> BigUint<Vec<T>> {
        let mut bound = BigUint(vec![T::ZERO; self.big_uint_value_len()]);
        if let Some(bit) = self.drop_bits.checked_sub(1) {
            let (index, shift) = bit.div_rem(T::BITS);
            bound[index as usize] = T::ONE << shift;
        }
        bound
    }

    /// Returns decomposition operators from the lowest retained level to the highest.
    ///
    /// Initialize the input with [`Self::init_value_carry_slice_to`] or
    /// [`Self::init_value_carry_slice_assign`] first. Apply all
    /// operators in order to that same adjusted input, forwarding the carry
    /// from each level to the next. Reversing or skipping levels does not
    /// preserve this carry protocol.
    #[must_use]
    #[inline]
    pub fn decomposer_iter<'a>(&'a self) -> BigUintSignedDecomposerIter<'a, T> {
        BigUintSignedDecomposerIter {
            value_masks: self.value_masks.iter(),
            carry_mask: self.carry_mask,
            basis_minus_one: self.basis_minus_one,
            modulus_minus_basis: &self.modulus_sub_basis,
        }
    }

    /// Returns full-width reconstruction weights in the same order as [`Self::decomposer_iter`].
    /// Each weight is a little-endian chunk of [`Self::big_uint_value_len`] limbs.
    #[inline]
    pub fn scalar_iter(&self) -> std::slice::ChunksExact<'_, T> {
        self.scalars.chunks_exact(self.big_uint_value_len())
    }

    /// Adjusts a value-major batch in place and overwrites its initial carries.
    ///
    /// Each input must be in `[0, Q)`, stored in exactly
    /// [`Self::big_uint_value_len`] little-endian limbs. `values.len()` must
    /// equal `carries.len() * big_uint_value_len()`. Adjusted values follow the
    /// internal representation described by [`Self::init_value_carry_slice_to`].
    #[inline]
    pub fn init_value_carry_slice_assign(&self, values: &mut [T], carries: &mut [bool]) {
        let big_uint_value_len = self.big_uint_value_len();
        debug_assert_eq!(values.len(), carries.len() * big_uint_value_len);

        match &self.value_carry_init_mode {
            BigUintValueCarryInitMode::AdjustAndCarry {
                threshold,
                add,
                index,
                mask,
            } => {
                BigUintIterMut::new(values, big_uint_value_len)
                    .zip(carries)
                    .for_each(|(mut value, carry)| {
                        if value.cmp(threshold).is_ge() {
                            let _ = value.add_assign(add);
                        }
                        *carry = !(value[*index] & *mask).is_zero();
                    });
            }
            BigUintValueCarryInitMode::AdjustOnly { threshold, add } => {
                BigUintIterMut::new(values, big_uint_value_len).for_each(|mut value| {
                    if value.cmp(threshold).is_ge() {
                        let _ = value.add_assign(add);
                    }
                });
                carries.fill(false);
            }
        }
    }

    /// Writes adjusted inputs and initial carries for a value-major batch.
    ///
    /// Each input must be in `[0, Q)`, stored in exactly
    /// [`Self::big_uint_value_len`] little-endian limbs. Both value buffers
    /// must have length `carries.len() * big_uint_value_len()`. Outputs are
    /// overwritten. Adjusted values are an internal bit representation, not
    /// necessarily reduced modulo `Q`; pass them unchanged to each successive
    /// decomposition operator, advancing its carry from level to level.
    #[inline]
    pub fn init_value_carry_slice_to(
        &self,
        big_uint_values: &[T],
        adjust_big_uint_values: &mut [T],
        carries: &mut [bool],
    ) {
        let big_uint_value_len = self.big_uint_value_len();
        debug_assert_eq!(big_uint_values.len(), adjust_big_uint_values.len());
        debug_assert_eq!(big_uint_values.len(), carries.len() * big_uint_value_len);

        match &self.value_carry_init_mode {
            BigUintValueCarryInitMode::AdjustAndCarry {
                threshold,
                add,
                index,
                mask,
            } => {
                BigUintIter::new(big_uint_values, big_uint_value_len)
                    .zip(BigUintIterMut::new(
                        adjust_big_uint_values,
                        big_uint_value_len,
                    ))
                    .zip(carries)
                    .for_each(|((value, mut adjust), carry)| {
                        if value.cmp(threshold).is_ge() {
                            // Write the adjusted value directly, without first
                            // copying it and then reading it back for the add.
                            let _ = value.add_to(add, &mut adjust);
                        } else {
                            adjust.0.copy_from_slice(value.0);
                        }
                        *carry = !(adjust[*index] & *mask).is_zero();
                    });
            }
            BigUintValueCarryInitMode::AdjustOnly { threshold, add } => {
                BigUintIter::new(big_uint_values, big_uint_value_len)
                    .zip(BigUintIterMut::new(
                        adjust_big_uint_values,
                        big_uint_value_len,
                    ))
                    .for_each(|(value, mut adjust)| {
                        if value.cmp(threshold).is_ge() {
                            // Write the adjusted value directly, without first
                            // copying it and then reading it back for the add.
                            let _ = value.add_to(add, &mut adjust);
                        } else {
                            adjust.0.copy_from_slice(value.0);
                        }
                    });
                carries.fill(false);
            }
        }
    }
}

/// Builds the wrap split for k retained digits and d dropped bits.
///
/// With B = 2^log_basis and m = k*log_basis + d, let
/// P = (B/2 - 1) * sum(B^i, 0 <= i < k). The split is P*2^d plus the rounding
/// half-step (or 1 when d=0). It is always below 2^(m-1) <= Q:
/// for d>0 the gap is 2^(d-1)*sum(B^i); for d=0 it is
/// (B^k-B)/(2*(B-1)) > 0 since the constructor guarantees m>log_basis.
/// Thus neither a comparison with Q nor a "no adjustment" mode is needed.
fn wrap_threshold<T: FheUint>(
    value_len: usize,
    log_basis: u32,
    levels: usize,
    drop_bits: u32,
) -> BigUint<Vec<T>> {
    let positive_digit = (T::ONE << (log_basis - 1)) - T::ONE;
    let mut value = BigUint(vec![T::ZERO; value_len]);
    for _ in 0..levels {
        let carry = value.left_shift_assign(log_basis);
        debug_assert_eq!(carry, T::ZERO);
        value[0] |= positive_digit;
    }
    if drop_bits > 0 {
        let carry = value.left_shift_assign(1);
        debug_assert_eq!(carry, T::ZERO);
        value[0] |= T::ONE;
        // Scale (2P + 1) by 2^(d-1). The integer shift API accepts only
        // sub-limb shifts, so move whole limbs first. The proven width bound
        // ensures all high limbs discarded by copy_within are zero.
        let (limbs, bits) = (drop_bits - 1).div_rem(T::BITS);
        let limbs = limbs as usize;
        if limbs != 0 {
            value.0.copy_within(..value_len - limbs, limbs);
            value.0[..limbs].fill(T::ZERO);
        }
        let carry = value.left_shift_assign(bits);
        debug_assert_eq!(carry, T::ZERO);
    } else {
        let carry = value.add_value_assign(T::ONE);
        debug_assert!(!carry);
    }
    value
}
