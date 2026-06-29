use std::iter::successors;

use num_traits::ConstOne;
use primus_data::Data;
use primus_integer::{BigUint, BigUintIter, BigUintIterMut, DivRem, FheUint};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;
use serde::{Deserialize, Serialize};

use crate::big_integer::BigUintSignedDecomposerIter;

use super::ValueMask;

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
    init_carry_mask: Option<(usize, T)>,
    carry_mask: T,
    split_value: Option<BigUint<Vec<T>>>,
    modulus_sub_basis: Vec<T>,
    next_pow_of_2_sub_modulus: BigUint<Vec<T>>,
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

        let next_pow_of_2_sub_modulus: BigUint<Vec<T>> = {
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

        Self {
            modulus: modulus.0.to_vec(),
            basis,
            basis_minus_one,
            decompose_length,
            log_basis,
            drop_bits,
            init_carry_mask,
            carry_mask,
            split_value,
            modulus_sub_basis: modulus_sub_basis.0,
            next_pow_of_2_sub_modulus,
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

    /// Returns the init carry mask of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn init_carry_mask(&self) -> Option<(usize, T)> {
        self.init_carry_mask
    }

    /// Returns the carry mask of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn carry_mask(&self) -> T {
        self.carry_mask
    }

    /// Returns the split value of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn split_value(&self) -> Option<&BigUint<Vec<T>>> {
        self.split_value.as_ref()
    }

    /// Returns a reference to the modulus sub basis of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn modulus_sub_basis(&self) -> &[T] {
        &self.modulus_sub_basis
    }

    /// Returns a reference to the next pow of 2 sub modulus of this [`BigUintApproxSignedBasis<T>`].
    #[inline]
    pub fn next_pow_of_2_sub_modulus(&self) -> &BigUint<Vec<T>> {
        &self.next_pow_of_2_sub_modulus
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
        let mut adjust = BigUint(value.0.as_slice().to_vec());
        if let Some(split) = &self.split_value
            && value.cmp(split).is_ge()
        {
            let _ = adjust.add_assign(&self.next_pow_of_2_sub_modulus);
        }

        let carry = match self.init_carry_mask {
            Some((i, mask)) => !(adjust[i] & mask).is_zero(),
            None => false,
        };

        (adjust.0, carry)
    }

    /// Init carries and adjusted values for a slice and store the adjusted values back to `values`.
    #[inline]
    pub fn init_value_carry_slice_inplace(
        &self,
        values: &mut [T],
        carries: &mut [bool],
        big_uint_value_len: usize,
    ) {
        if let Some(split) = &self.split_value {
            BigUintIterMut::new(values, big_uint_value_len).for_each(|mut value| {
                if value.cmp(split).is_ge() {
                    let _ = value.add_assign(&self.next_pow_of_2_sub_modulus);
                }
            })
        }

        match self.init_carry_mask {
            Some((i, mask)) => BigUintIterMut::new(values, big_uint_value_len)
                .zip(carries)
                .for_each(|(value, carry)| {
                    *carry = !(value[i] & mask).is_zero();
                }),
            None => carries.fill(false),
        };
    }

    /// Init carries and adjusted values for a slice.
    #[inline]
    pub fn init_value_carry_slice(
        &self,
        big_uint_values: &[T],
        adjust_big_uint_values: &mut [T],
        carries: &mut [bool],
        big_uint_value_len: usize,
    ) {
        adjust_big_uint_values.copy_from_slice(big_uint_values);
        self.init_value_carry_slice_inplace(adjust_big_uint_values, carries, big_uint_value_len);
    }
}
