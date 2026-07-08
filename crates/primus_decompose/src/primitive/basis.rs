use core::iter::successors;

use num_traits::ConstOne;
use primus_integer::FheUint;
use serde::{Deserialize, Serialize};

use super::{ScalarIter, SignedDecomposeIter, ValueCarryInitMode, ValueMask};

/// The basis for approximate signed decomposition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: FheUint"))]
pub struct ApproxSignedBasis<T: FheUint> {
    modulus: Option<T>,
    modulus_is_power_of_2: bool,
    basis: T,
    basis_minus_one: T,
    modulus_minus_basis: T,
    decompose_length: usize,
    value_bits: u32,
    log_basis: u32,
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
            && self.decompose_length == other.decompose_length
    }
}

impl<T: FheUint> ApproxSignedBasis<T> {
    /// Creates a decomposition basis.
    ///
    /// `modulus` may be `None` to use the implicit power-of-two modulus
    /// `2^T::BITS`. `log_basis` is the base-2 logarithm of the decomposition
    /// basis (`basis = 2^log_basis`). `reverse_length`, when provided,
    /// limits the number of decomposition steps.
    #[inline]
    pub fn new(modulus: Option<T>, log_basis: u32, reverse_length: Option<usize>) -> Self {
        assert!(log_basis > 0);

        let basis = <T as ConstOne>::ONE << log_basis;
        let basis_minus_one = basis - <T as ConstOne>::ONE;

        let modulus_is_power_of_2;
        let value_bits;
        let modulus_minus_basis;

        if let Some(modulus) = modulus {
            if modulus.is_power_of_two() {
                modulus_is_power_of_2 = true;
                value_bits = modulus.trailing_zeros();
            } else {
                modulus_is_power_of_2 = false;
                value_bits = T::BITS - modulus.leading_zeros();
            }
            assert!(value_bits >= log_basis);
            modulus_minus_basis = modulus - basis;
        } else {
            assert!(T::BITS >= log_basis);
            modulus_is_power_of_2 = true;
            value_bits = T::BITS;
            modulus_minus_basis = T::MAX - basis_minus_one;
        }

        let decompose_length = value_bits / log_basis;
        let mut drop_bits = value_bits - decompose_length * log_basis;
        let mut decompose_length = decompose_length as usize;

        if let Some(reverse_len) = reverse_length {
            assert!(decompose_length >= reverse_len);
            decompose_length = reverse_len;
            drop_bits = value_bits - (reverse_len as u32) * log_basis;
        }

        assert!(decompose_length > 0);

        let init_carry_mask = if drop_bits > 0 {
            Some(<T as ConstOne>::ONE << (drop_bits - 1))
        } else {
            None
        };

        let carry_mask = if log_basis == 1 {
            T::ONE << 1u32
        } else {
            (T::ONE << log_basis) | (T::ONE << (log_basis - 1))
        };

        let mut wrap_threshold = None;
        let mut next_pow_of_2_sub_modulus = T::ZERO;
        if !modulus_is_power_of_2 {
            let modulus = modulus.unwrap();
            wrap_threshold = if log_basis == 1 {
                if drop_bits == 0 {
                    None
                } else {
                    let mut value = T::ZERO;
                    for _ in 0..decompose_length {
                        value <<= 1;
                        value |= T::ONE;
                    }
                    value <<= 1;
                    value |= T::ONE;
                    value <<= drop_bits - 1;
                    if value >= modulus { None } else { Some(value) }
                }
            } else {
                let mut value = T::ZERO;
                for _ in 0..decompose_length {
                    value <<= log_basis;
                    value |= basis_minus_one >> 1u32;
                }
                if drop_bits > 0 {
                    value <<= 1;
                    value |= T::ONE;
                    value <<= drop_bits - 1;
                } else {
                    value += T::ONE;
                }
                if value >= modulus { None } else { Some(value) }
            };

            next_pow_of_2_sub_modulus = (T::MAX >> (T::BITS - value_bits)) - (modulus - T::ONE);
        }

        let scalars: Vec<T> =
            successors(Some(T::ONE << drop_bits), |&prev| Some(prev << log_basis))
                .take(decompose_length)
                .collect();

        let value_masks: Vec<ValueMask<T>> =
            successors(Some(ValueMask::new(basis_minus_one, drop_bits)), |&prev| {
                Some(prev.next(log_basis))
            })
            .take(decompose_length)
            .collect();

        let value_carry_init_mode = match (wrap_threshold, init_carry_mask) {
            (Some(threshold), Some(mask)) => ValueCarryInitMode::AdjustAndCarry {
                threshold,
                add: next_pow_of_2_sub_modulus,
                mask,
            },
            (Some(threshold), None) => ValueCarryInitMode::AdjustOnly {
                threshold,
                add: next_pow_of_2_sub_modulus,
            },
            (None, Some(mask)) => ValueCarryInitMode::CarryOnly { mask },
            (None, None) => ValueCarryInitMode::Plain,
        };

        Self {
            modulus,
            modulus_is_power_of_2,
            basis,
            basis_minus_one,
            modulus_minus_basis,
            value_bits,
            carry_mask,
            decompose_length,
            log_basis,
            drop_bits,
            value_carry_init_mode,
            scalars,
            value_masks,
        }
    }

    /// Checks whether the modulus of this [`ApproxSignedBasis<T>`] is power of 2.
    #[inline]
    pub fn modulus_is_power_of_2(&self) -> bool {
        self.modulus_is_power_of_2
    }

    /// Returns the value bits of values in `[0, modulus - 1]`.
    #[inline]
    pub fn value_bits(&self) -> u32 {
        self.value_bits
    }

    /// Returns the decompose length of this [`ApproxSignedBasis<T>`].
    #[inline]
    pub fn decompose_length(&self) -> usize {
        self.decompose_length
    }

    /// Returns the basis value of this [`ApproxSignedBasis<T>`].
    #[inline]
    pub fn basis_value(&self) -> T {
        self.basis
    }

    /// Returns the basis minus one of this [`ApproxSignedBasis<T>`].
    #[inline]
    pub fn basis_minus_one(&self) -> T {
        self.basis_minus_one
    }

    /// Returns the log basis of this [`ApproxSignedBasis<T>`].
    #[inline]
    pub fn log_basis(&self) -> u32 {
        self.log_basis
    }

    /// Returns the drop bits of this [`ApproxSignedBasis<T>`].
    ///
    /// This means some bits of the value will be dropped
    /// according to approximate signed decomposition.
    #[inline]
    pub fn drop_bits(&self) -> u32 {
        self.drop_bits
    }

    /// Returns the maximum approximation error caused by the dropped low bits.
    ///
    /// This is `0` when no bits are dropped, otherwise `2^(drop_bits - 1)`.
    #[inline]
    pub fn approximate_error_bound(&self) -> T {
        if self.drop_bits == 0 {
            T::ZERO
        } else {
            T::ONE << (self.drop_bits - 1)
        }
    }

    /// Returns an iterator over the signed decomposition operators of this [`ApproxSignedBasis<T>`].
    #[inline]
    pub fn decompose_iter<'a>(&'a self) -> SignedDecomposeIter<'a, T> {
        SignedDecomposeIter {
            value_masks: self.value_masks.iter(),
            carry_mask: self.carry_mask,
            basis_minus_one: self.basis_minus_one,
            modulus_minus_basis: self.modulus_minus_basis,
        }
    }

    /// Returns an iterator over scalars of this [`ApproxSignedBasis<T>`].
    #[inline]
    pub fn scalar_iter<'a>(&'a self) -> ScalarIter<'a, T> {
        ScalarIter::new(&self.scalars)
    }

    /// Init carry and adjusted value for a value.
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

    /// Init carries and adjusted values for a slice and store the adjusted values back to `values`.
    #[inline]
    pub fn init_value_carry_slice_in_place(&self, values: &mut [T], carries: &mut [bool]) {
        debug_assert_eq!(values.len(), carries.len());

        match self.value_carry_init_mode {
            // When both adjustment and carry extraction are needed, do them in
            // the same pass so each value is loaded and stored only once.
            ValueCarryInitMode::AdjustAndCarry {
                threshold,
                add,
                mask,
            } => {
                values.iter_mut().zip(carries).for_each(|(value, carry)| {
                    if *value >= threshold {
                        *value += add;
                    }
                    *carry = !(*value & mask).is_zero();
                });
            }
            // No carry bit exists for this basis, so keep the fast fill path.
            ValueCarryInitMode::AdjustOnly { threshold, add } => {
                values.iter_mut().for_each(|value| {
                    if *value >= threshold {
                        *value += add;
                    }
                });
                carries.fill(false);
            }
            ValueCarryInitMode::CarryOnly { mask } => {
                values.iter().zip(carries).for_each(|(&value, carry)| {
                    *carry = !(value & mask).is_zero();
                });
            }
            ValueCarryInitMode::Plain => carries.fill(false),
        }
    }

    /// Init carries and adjusted values for a slice.
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
    /// This only supports power-of-two modulus (the common TFHE case).  For
    /// non-power-of-two moduli, use [`init_value_carry_slice_to`] instead,
    /// which also computes adjusted values.
    ///
    /// # Panics
    ///
    /// Panics if this basis was created for a non-power-of-two modulus (i.e.
    /// any initialization mode other than [`ValueCarryInitMode::CarryOnly`]
    /// or [`ValueCarryInitMode::Plain`]).
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
