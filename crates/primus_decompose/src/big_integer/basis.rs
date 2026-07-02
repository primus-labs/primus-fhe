use std::iter::successors;

use num_traits::ConstOne;
use primus_data::Data;
use primus_integer::{BigUint, BigUintIter, BigUintIterMut, DivRem, FheUint};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;
use serde::{Deserialize, Serialize};

use crate::big_integer::BigUintSignedDecomposerIter;

use super::{BigUintValueCarryInitMode, ValueMask};

/// The basis for approximate signed decomposition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: FheUint"))]
pub struct BigUintApproxSignedBasis<T: FheUint> {
    modulus: Vec<T>,
    basis: T,
    basis_minus_one: T,
    decompose_length: usize,
    log_basis: u32,
    drop_bits: u32,
    value_carry_init_mode: BigUintValueCarryInitMode<T>,
    carry_mask: T,
    modulus_sub_basis: Vec<T>,
    scalars: Vec<T>,
    scalars_residue: Vec<T>,
    moduli_count: usize,
    value_masks: Vec<ValueMask<T>>,
}

impl<T: FheUint> BigUintApproxSignedBasis<T> {
    /// Creates a decomposition basis for the given modulus.
    ///
    /// `log_basis` is the base-2 logarithm of the decomposition basis
    /// (`basis = 2^log_basis`). `reverse_length`, when provided, limits
    /// the number of decomposition steps to a prefix of the full chain.
    #[inline]
    pub fn new<M>(
        modulus: BigUint<&[T]>,
        log_basis: u32,
        reverse_length: Option<usize>,
        rns_base: &RNSBase<T, M>,
    ) -> Self
    where
        M: FieldContext<T>,
    {
        // FIXME: log_basis may be bigger than T::BITS
        assert!(!modulus.0.last().unwrap().is_zero());
        assert!(log_basis > 0 && T::BITS > log_basis);
        assert_eq!(modulus, rns_base.moduli_product());

        let modulus_value_len = modulus.len();
        let unused_bits = modulus.0.last().unwrap().leading_zeros();

        let basis = <T as ConstOne>::ONE << log_basis;
        let basis_minus_one = basis - <T as ConstOne>::ONE;
        let modulus_bits_count = T::BITS * (modulus_value_len as u32) - unused_bits;
        let decompose_length = modulus_bits_count / log_basis;
        let mut drop_bits = modulus_bits_count - decompose_length * log_basis;
        let mut decompose_length = decompose_length as usize;

        if let Some(reverse_len) = reverse_length {
            assert!(decompose_length >= reverse_len);
            decompose_length = reverse_len;
            drop_bits = modulus_bits_count - (reverse_len as u32) * log_basis;
        }

        assert!(decompose_length > 0);

        let init_carry_mask = if drop_bits > 0 {
            let bits = drop_bits - 1;

            let (index, bits) = bits.div_rem(T::BITS);
            Some((index as usize, T::ONE << bits))
        } else {
            None
        };

        let carry_mask = if log_basis == 1 {
            T::ONE << 1u32
        } else {
            (T::ONE << log_basis) | (T::ONE << (log_basis - 1))
        };

        let split_value: Option<BigUint<Vec<T>>> = if log_basis == 1 {
            if drop_bits == 0 {
                None
            } else {
                let mut value = BigUint(vec![T::ZERO; modulus_value_len]);
                for _ in 0..decompose_length {
                    let carry = value.left_shift_assign(1);
                    assert_eq!(carry, T::ZERO);
                    value[0] |= T::ONE;
                }
                let carry = value.left_shift_assign(1);
                assert_eq!(carry, T::ZERO);
                value[0] |= T::ONE;
                let carry = value.left_shift_assign(drop_bits - 1);
                assert_eq!(carry, T::ZERO);
                if value.cmp(&modulus).is_ge() {
                    None
                } else {
                    Some(value)
                }
            }
        } else {
            let mut value = BigUint(vec![T::ZERO; modulus_value_len]);
            for _ in 0..decompose_length {
                let carry = value.left_shift_assign(log_basis);
                assert_eq!(carry, T::ZERO);
                value[0] |= basis_minus_one >> 1u32;
            }
            if drop_bits > 0 {
                let carry = value.left_shift_assign(1);
                assert_eq!(carry, T::ZERO);
                value[0] |= T::ONE;
                let carry = value.left_shift_assign(drop_bits - 1);
                assert_eq!(carry, T::ZERO);
            } else {
                let carry = value.add_value_assign(T::ONE);
                assert!(!carry);
            }

            if value.cmp(&modulus).is_ge() {
                None
            } else {
                Some(value)
            }
        };

        let mut modulus_sub_basis = BigUint(modulus.0.to_vec());
        let borrow = modulus_sub_basis.sub_value_assign(basis);
        assert!(!borrow);

        let make_adjust_add = || {
            let mut next_pow_of_2_minus_one = BigUint(vec![T::MAX; modulus_value_len]);
            next_pow_of_2_minus_one[modulus_value_len - 1] >>= unused_bits;

            let mut modulus_minus_one = BigUint(modulus.0.to_vec());
            let _ = modulus_minus_one.sub_value_assign(T::ONE);

            let borrow = next_pow_of_2_minus_one.sub_assign(&modulus_minus_one);
            assert!(!borrow);
            next_pow_of_2_minus_one
        };

        let mut scalars = vec![T::ZERO; modulus_value_len * decompose_length];
        let mut prev: Option<BigUint<Vec<T>>> = None;

        BigUintIterMut::new(&mut scalars, modulus_value_len).for_each(|mut scalar| {
            if let Some(pre) = prev.as_mut() {
                let carry = pre.left_shift_assign(log_basis);
                assert_eq!(carry, T::ZERO);
                scalar.0.copy_from_slice(&pre.0);
            } else {
                scalar[0] = T::ONE;
                let carry = scalar.left_shift_assign(drop_bits);
                assert_eq!(carry, T::ZERO);
                prev = Some(BigUint(scalar.0.to_vec()));
            }
        });

        let moduli_count = rns_base.moduli_count();
        let mut scalars_residue = vec![T::ZERO; moduli_count * decompose_length];

        BigUintIter::new(&scalars, modulus_value_len)
            .zip(scalars_residue.chunks_exact_mut(moduli_count))
            .for_each(|(scalar, residues)| {
                rns_base.decompose_to(scalar, residues);
            });

        let value_masks: Vec<ValueMask<T>> =
            successors(Some(ValueMask::new(basis_minus_one, drop_bits)), |&prev| {
                Some(prev.next(log_basis))
            })
            .take(decompose_length)
            .collect();

        let value_carry_init_mode = match (split_value, init_carry_mask) {
            (Some(threshold), Some((index, mask))) => BigUintValueCarryInitMode::AdjustAndCarry {
                threshold,
                add: make_adjust_add(),
                index,
                mask,
            },
            (None, Some((index, mask))) => BigUintValueCarryInitMode::CarryOnly { index, mask },
            (Some(threshold), None) => BigUintValueCarryInitMode::AdjustOnly {
                threshold,
                add: make_adjust_add(),
            },
            (None, None) => BigUintValueCarryInitMode::Plain,
        };

        Self {
            modulus: modulus.0.to_vec(),
            basis,
            basis_minus_one,
            decompose_length,
            log_basis,
            drop_bits,
            value_carry_init_mode,
            carry_mask,
            modulus_sub_basis: modulus_sub_basis.0,
            scalars,
            scalars_residue,
            moduli_count,
            value_masks,
        }
    }

    /// Returns a reference to the modulus of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn modulus(&self) -> &[T] {
        &self.modulus
    }

    /// Returns the basis of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn basis_value(&self) -> T {
        self.basis
    }

    /// Returns the basis minus one of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn basis_minus_one(&self) -> T {
        self.basis_minus_one
    }

    /// Returns the decompose length of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn decompose_length(&self) -> usize {
        self.decompose_length
    }

    /// Returns the log basis of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn log_basis(&self) -> u32 {
        self.log_basis
    }

    /// Returns the drop bits of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn drop_bits(&self) -> u32 {
        self.drop_bits
    }

    /// Returns the maximum approximation error caused by the dropped low bits.
    ///
    /// This is `0` when no bits are dropped, otherwise the initial carry mask.
    #[inline]
    pub fn approximate_error_bound(&self) -> BigUint<Vec<T>> {
        self.value_carry_init_mode
            .approximate_error_bound(self.modulus.len())
    }

    /// Returns a reference to the modulus sub basis of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn modulus_sub_basis(&self) -> &[T] {
        &self.modulus_sub_basis
    }

    /// Returns a reference to the scalars residue of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn iter_scalar_residues(&self) -> std::slice::ChunksExact<'_, T> {
        self.scalars_residue.chunks_exact(self.moduli_count)
    }

    /// Returns an iterator over the signed decomposition operators of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn decomposer_iter<'a>(&'a self) -> BigUintSignedDecomposerIter<'a, T> {
        BigUintSignedDecomposerIter {
            value_masks: self.value_masks.iter(),
            carry_mask: self.carry_mask,
            basis_minus_one: self.basis_minus_one,
            modulus_minus_basis: &self.modulus_sub_basis,
        }
    }

    /// Returns an iterator over scalars of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn scalar_iter(&self) -> std::slice::ChunksExact<'_, T> {
        self.scalars.chunks_exact(self.modulus().len())
    }

    /// Init carry and adjusted value for a value.
    #[inline]
    pub fn init_value_carry<A>(&self, value: &BigUint<A>) -> (Vec<T>, bool)
    where
        A: Data<Elem = T>,
    {
        let value_digits = value.0.as_slice();

        match &self.value_carry_init_mode {
            BigUintValueCarryInitMode::AdjustAndCarry {
                threshold,
                add,
                index,
                mask,
            } => {
                let mut adjust = BigUint(value_digits.to_vec());
                if value.cmp(threshold).is_ge() {
                    let _ = adjust.add_assign(add);
                }
                let carry = !(adjust[*index] & *mask).is_zero();
                (adjust.0, carry)
            }
            BigUintValueCarryInitMode::AdjustOnly { threshold, add } => {
                let mut adjust = BigUint(value_digits.to_vec());
                if value.cmp(threshold).is_ge() {
                    let _ = adjust.add_assign(add);
                }
                (adjust.0, false)
            }
            BigUintValueCarryInitMode::CarryOnly { index, mask } => (
                value_digits.to_vec(),
                !(value_digits[*index] & *mask).is_zero(),
            ),
            BigUintValueCarryInitMode::Plain => (value_digits.to_vec(), false),
        }
    }

    /// Init carries and adjusted values for a slice and store the adjusted values back to `values`.
    #[inline]
    pub fn init_value_carry_slice_inplace(
        &self,
        values: &mut [T],
        carries: &mut [bool],
        big_uint_value_len: usize,
    ) {
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
            BigUintValueCarryInitMode::CarryOnly { index, mask } => {
                BigUintIter::new(values, big_uint_value_len)
                    .zip(carries)
                    .for_each(|(value, carry)| {
                        *carry = !(value[*index] & *mask).is_zero();
                    });
            }
            BigUintValueCarryInitMode::Plain => carries.fill(false),
        }
    }

    /// Init carries and adjusted values for a slice.
    #[inline]
    pub fn init_value_carry_slice_to(
        &self,
        big_uint_values: &[T],
        adjust_big_uint_values: &mut [T],
        carries: &mut [bool],
        big_uint_value_len: usize,
    ) {
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
                        adjust.0.copy_from_slice(value.0);
                        if value.cmp(threshold).is_ge() {
                            let _ = adjust.add_assign(add);
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
                        adjust.0.copy_from_slice(value.0);
                        if value.cmp(threshold).is_ge() {
                            let _ = adjust.add_assign(add);
                        }
                    });
                carries.fill(false);
            }
            BigUintValueCarryInitMode::CarryOnly { index, mask } => {
                BigUintIter::new(big_uint_values, big_uint_value_len)
                    .zip(BigUintIterMut::new(
                        adjust_big_uint_values,
                        big_uint_value_len,
                    ))
                    .zip(carries)
                    .for_each(|((value, adjust), carry)| {
                        adjust.0.copy_from_slice(value.0);
                        *carry = !(value[*index] & *mask).is_zero();
                    });
            }
            BigUintValueCarryInitMode::Plain => {
                adjust_big_uint_values.copy_from_slice(big_uint_values);
                carries.fill(false);
            }
        }
    }
}
