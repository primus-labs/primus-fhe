use core::{iter::Copied, slice::Iter};

use primus_integer::FheUint;

use crate::{
    ApproxSignedBasisError, DecompositionBaseLog, DecompositionLevelCount,
    level_count_and_drop_bits,
};

use super::common::{SignedDecomposerIter, ValueCarryInitMode, ValueMask};

/// Precomputed approximate signed decomposition modulo `q`.
///
/// With radix `B = 2^log_basis`, level `i` has weight `2^drop_bits * B^i`.
/// Digits lie in `[-B/2, B/2)` and are encoded as canonical residues modulo
/// `q` (modulo `2^T::BITS` for the implicit native modulus). Their weighted
/// sum approximates the input, with circular distance bounded by
/// [`Self::approximate_error_bound`].
///
/// The decomposition width `m` is `log2(q)` for power-of-two moduli and
/// `bit_width(q)` otherwise. The full level count is `m / log_basis`;
/// retaining `k` levels leaves `drop_bits = m - k * log_basis`.
/// Power-of-two inputs need no adjustment buffer: use [`Self::init_carry_slice`].
#[derive(Debug, Clone)]
pub struct ApproxSignedBasis<T: FheUint> {
    modulus: Option<T>,
    modulus_is_power_of_2: bool,
    basis: T,
    basis_minus_one: T,
    modulus_minus_basis: T,
    level_count: DecompositionLevelCount,
    log_basis: DecompositionBaseLog,
    drop_bits: u32,
    carry_mask: T,
    value_carry_init_mode: ValueCarryInitMode<T>,
    scalars: Vec<T>,
    value_masks: Vec<ValueMask<T>>,
}

impl<T: FheUint> Eq for ApproxSignedBasis<T> {}

impl<T: FheUint> PartialEq for ApproxSignedBasis<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.modulus == other.modulus
            && self.basis == other.basis
            && self.level_count == other.level_count
    }
}

impl<T: FheUint> ApproxSignedBasis<T> {
    /// Creates a decomposition basis.
    ///
    /// `modulus` may be `None` to use the implicit power-of-two modulus
    /// `2^T::BITS`. `log_basis` is the base-2 logarithm of the decomposition
    /// basis (`basis = 2^log_basis`) and must be below `T::BITS`. The checked type establishes its lower bound.
    /// `level_count` selects how many highest decomposition levels to retain;
    /// `None` uses the full level count. Retaining fewer levels discards more low bits.
    ///
    /// Digits lie in `[-basis / 2, basis / 2)`. Both decomposition operators
    /// and their corresponding scalars are yielded from the lowest retained
    /// level to the highest retained level.
    ///
    /// # Panics
    ///
    /// Panics if `log_basis >= T::BITS`, if an explicit modulus
    /// is smaller than the basis, or if `level_count` exceeds
    /// the full level count.
    #[must_use]
    #[inline]
    pub fn new(
        modulus: Option<T>,
        log_basis: DecompositionBaseLog,
        level_count: Option<DecompositionLevelCount>,
    ) -> Self {
        Self::try_new(modulus, log_basis, level_count).unwrap_or_else(|message| panic!("{message}"))
    }

    /// Tries to create a decomposition basis with the same validity rules as
    /// [`Self::new`].
    #[inline]
    pub fn try_new(
        modulus: Option<T>,
        log_basis: DecompositionBaseLog,
        level_count: Option<DecompositionLevelCount>,
    ) -> Result<Self, ApproxSignedBasisError> {
        if log_basis.get() >= T::BITS {
            return Err(ApproxSignedBasisError::InvalidLogBasis {
                log_basis: log_basis.get(),
                limb_bits: T::BITS,
            });
        }

        let checked_log_basis = log_basis;
        let log_basis = log_basis.get();
        let basis = T::ONE << log_basis;
        let basis_minus_one = basis - T::ONE;

        // The primitive power-of-two domain uses log2(q), not bit_width(q).
        let (modulus_is_power_of_2, value_bits, modulus_minus_basis) = match modulus {
            None => (true, T::BITS, T::MAX - basis_minus_one),
            Some(q) => {
                if q < basis {
                    return Err(ApproxSignedBasisError::BasisExceedsModulus);
                }
                let power_of_two = q.is_power_of_two();
                let bits = if power_of_two {
                    q.trailing_zeros()
                } else {
                    q.bit_width()
                };
                (power_of_two, bits, q - basis)
            }
        };
        let (level_count, drop_bits) =
            level_count_and_drop_bits(value_bits, checked_log_basis, level_count)?;
        let checked_level_count = level_count;
        let level_count = level_count.get();
        let init_carry_mask = drop_bits.checked_sub(1).map(|bit| T::ONE << bit);

        // Power-of-two inputs already have the right bit representation. Other
        // moduli need the negative region lifted from q to the binary domain.
        let value_carry_init_mode = if modulus_is_power_of_2 {
            match init_carry_mask {
                Some(mask) => ValueCarryInitMode::CarryOnly { mask },
                None => ValueCarryInitMode::Plain,
            }
        } else {
            let q = modulus.unwrap();
            let threshold = wrap_threshold(log_basis, level_count, drop_bits);
            // Compute 2^value_bits - q without representing 2^T::BITS.
            let add = (T::MAX >> (T::BITS - value_bits)) - (q - T::ONE);
            match init_carry_mask {
                Some(mask) => ValueCarryInitMode::AdjustAndCarry {
                    threshold,
                    add,
                    mask,
                },
                None => ValueCarryInitMode::AdjustOnly { threshold, add },
            }
        };

        // Weights and extraction windows refer to the same ascending levels.
        let scalars = (0..level_count)
            .map(|level| T::ONE << (drop_bits + level as u32 * log_basis))
            .collect();
        let value_masks = (0..level_count)
            .map(|level| ValueMask::new(basis_minus_one, drop_bits + level as u32 * log_basis))
            .collect();
        let carry_mask = (T::ONE << log_basis) | (T::ONE << (log_basis - 1));

        Ok(Self {
            modulus,
            modulus_is_power_of_2,
            basis,
            basis_minus_one,
            modulus_minus_basis,
            carry_mask,
            level_count: checked_level_count,
            log_basis: checked_log_basis,
            drop_bits,
            value_carry_init_mode,
            scalars,
            value_masks,
        })
    }

    /// Returns the explicit modulus, or `None` for the implicit native modulus.
    #[must_use]
    #[inline]
    pub fn modulus(&self) -> Option<T> {
        self.modulus
    }

    /// Checks whether the modulus of this [`ApproxSignedBasis<T>`] is power of 2.
    #[must_use]
    #[inline]
    pub fn modulus_is_power_of_2(&self) -> bool {
        self.modulus_is_power_of_2
    }

    /// Returns the retained level count of this [`ApproxSignedBasis<T>`].
    #[must_use]
    #[inline]
    pub fn level_count(&self) -> DecompositionLevelCount {
        self.level_count
    }

    /// Returns the basis value of this [`ApproxSignedBasis<T>`].
    #[must_use]
    #[inline]
    pub fn basis_value(&self) -> T {
        self.basis
    }

    /// Returns the log basis of this [`ApproxSignedBasis<T>`].
    #[must_use]
    #[inline]
    pub fn log_basis(&self) -> DecompositionBaseLog {
        self.log_basis
    }

    /// Returns the drop bits of this [`ApproxSignedBasis<T>`].
    ///
    /// This means some bits of the value will be dropped according to
    /// approximate signed decomposition. The discarded part is rounded to
    /// the nearest retained value, with exact half-way cases rounded up.
    #[must_use]
    #[inline]
    pub fn drop_bits(&self) -> u32 {
        self.drop_bits
    }

    /// Returns the maximum approximation error caused by the dropped low bits.
    ///
    /// This is `0` when no bits are dropped, otherwise `2^(drop_bits - 1)`.
    /// Error is measured as circular distance modulo the decomposition modulus.
    #[must_use]
    #[inline]
    pub fn approximate_error_bound(&self) -> T {
        if self.drop_bits == 0 {
            T::ZERO
        } else {
            T::ONE << (self.drop_bits - 1)
        }
    }

    /// Returns decomposition operators from the lowest retained level to the highest.
    ///
    /// Initialize the input with an `init_value_carry*` method first (or
    /// [`Self::init_carry_slice`] when no adjustment is needed). Apply all
    /// operators in order to that same adjusted input, forwarding the carry
    /// from each level to the next. Reversing or skipping levels does not
    /// preserve this carry protocol.
    #[must_use]
    #[inline]
    pub fn decomposer_iter<'a>(&'a self) -> SignedDecomposerIter<'a, T> {
        SignedDecomposerIter {
            value_masks: self.value_masks.iter(),
            carry_mask: self.carry_mask,
            basis_minus_one: self.basis_minus_one,
            modulus_minus_basis: self.modulus_minus_basis,
        }
    }

    /// Returns copied reconstruction weights in the same order as [`Self::decomposer_iter`].
    #[inline]
    pub fn scalar_iter(&self) -> Copied<Iter<'_, T>> {
        self.scalars.iter().copied()
    }

    /// Returns an adjusted input and its initial carry.
    ///
    /// For an explicit modulus `q`, `value` must be reduced to `[0, q)`.
    /// With the implicit native modulus, every value of `T` is valid.
    /// The adjusted value is an internal bit representation, not necessarily
    /// reduced modulo `q`; pass it unchanged to every decomposition operator.
    #[must_use]
    #[inline]
    pub fn init_value_carry(&self, value: T) -> (T, bool) {
        match self.value_carry_init_mode {
            ValueCarryInitMode::AdjustAndCarry {
                threshold,
                add,
                mask,
            } => {
                let adjust = if value >= threshold {
                    value + add
                } else {
                    value
                };
                (adjust, !(adjust & mask).is_zero())
            }
            ValueCarryInitMode::AdjustOnly { threshold, add } => {
                let adjust = if value >= threshold {
                    value + add
                } else {
                    value
                };
                (adjust, false)
            }
            ValueCarryInitMode::CarryOnly { mask } => (value, !(value & mask).is_zero()),
            ValueCarryInitMode::Plain => (value, false),
        }
    }

    /// Writes adjusted inputs and initial carries for a batch.
    ///
    /// For an explicit modulus `q`, every input value must be reduced to
    /// `[0, q)`. With the implicit native modulus, every value of `T` is valid.
    /// All three slices must have equal lengths. Both outputs are overwritten;
    /// adjusted values follow [`Self::init_value_carry`].
    #[inline]
    pub fn init_value_carry_slice_to(
        &self,
        values: &[T],
        adjust_values: &mut [T],
        carries: &mut [bool],
    ) {
        debug_assert_eq!(values.len(), adjust_values.len());
        debug_assert_eq!(values.len(), carries.len());

        match self.value_carry_init_mode {
            // Compute the adjusted value once, then use that same value for the
            // carry bit instead of reading `adjust_values` in a second pass.
            ValueCarryInitMode::AdjustAndCarry {
                threshold,
                add,
                mask,
            } => {
                values.iter().zip(adjust_values).zip(carries).for_each(
                    |((&value, adjust_value), carry)| {
                        let adjusted = if value >= threshold {
                            value + add
                        } else {
                            value
                        };
                        *adjust_value = adjusted;
                        *carry = !(adjusted & mask).is_zero();
                    },
                );
            }
            ValueCarryInitMode::AdjustOnly { threshold, add } => {
                values
                    .iter()
                    .zip(adjust_values)
                    .for_each(|(&value, adjust_value)| {
                        *adjust_value = if value >= threshold {
                            value + add
                        } else {
                            value
                        };
                    });
                carries.fill(false);
            }
            // Without adjustment, copy and carry extraction can still share one pass.
            ValueCarryInitMode::CarryOnly { mask } => {
                values.iter().zip(adjust_values).zip(carries).for_each(
                    |((&value, adjust_value), carry)| {
                        *adjust_value = value;
                        *carry = !(value & mask).is_zero();
                    },
                );
            }
            ValueCarryInitMode::Plain => {
                adjust_values.copy_from_slice(values);
                carries.fill(false);
            }
        }
    }

    /// Extract initial carry bits from `values` without copying or adjusting.
    ///
    /// For an explicit power-of-two modulus `q`, every input value must be
    /// reduced to `[0, q)`. With the implicit native modulus, every value of
    /// `T` is valid.
    /// The slices must have equal lengths; all carries are overwritten.
    ///
    /// This only supports power-of-two modulus (the common TFHE case).  For
    /// non-power-of-two moduli, use [`Self::init_value_carry_slice_to`] instead,
    /// which also computes adjusted values.
    ///
    /// # Panics
    ///
    /// Panics if this basis was created for a non-power-of-two modulus.
    #[inline]
    pub fn init_carry_slice(&self, values: &[T], carries: &mut [bool]) {
        debug_assert_eq!(values.len(), carries.len());
        match self.value_carry_init_mode {
            ValueCarryInitMode::CarryOnly { mask } => {
                values
                    .iter()
                    .zip(carries)
                    .for_each(|(&v, c)| *c = !(v & mask).is_zero());
            }
            ValueCarryInitMode::Plain => carries.fill(false),
            _ => panic!(
                "init_carry_slice does not support non-power-of-two modulus \
                 (mode requires value adjustment); use init_value_carry_slice_to instead"
            ),
        }
    }
}

/// First input whose rounded positive digits would exceed the retained range.
///
/// For radix B, k levels and d dropped bits, the largest positive digit sum is
/// P = (B/2 - 1) * sum(B^i, 0 <= i < k). The split is P*2^d + 2^(d-1)
/// when d > 0, or P + 1 otherwise. Inputs at/above it are represented as x-q.
///
/// In the non-power-of-two domain, m = k*log_basis + d > log_basis.
/// This split is strictly below 2^(m-1) <= q, so adjustment is always needed
/// for some canonical inputs; there is no optional "no split" case.
fn wrap_threshold<T: FheUint>(log_basis: u32, levels: usize, drop_bits: u32) -> T {
    let positive_digit = (T::ONE << (log_basis - 1)) - T::ONE;
    let mut positive_limit = T::ZERO;
    for _ in 0..levels {
        positive_limit = (positive_limit << log_basis) | positive_digit;
    }
    let rounding_offset = if drop_bits == 0 {
        T::ONE
    } else {
        T::ONE << (drop_bits - 1)
    };
    (positive_limit << drop_bits) + rounding_offset
}
