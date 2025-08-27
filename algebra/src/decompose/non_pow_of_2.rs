use itertools::izip;
use num_traits::ConstOne;
use serde::{Deserialize, Serialize};

use crate::integer::{Bits, UnsignedInteger};

/// The basis for approximate signed decomposition of **non** power of 2 modulus value.
#[derive(Debug, Clone, Copy, Eq, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: UnsignedInteger"))]
pub struct NonPowOf2ApproxSignedBasis<T: UnsignedInteger> {
    modulus: T,
    basis: T,
    basis_minus_one: T,
    init_carry_mask: Option<T>,
    carry_mask: T,
    decompose_length: usize,
    log_basis: u32,
    drop_bits: u32,
    split_value: Option<T>,
    next_pow_of_2_sub_modulus: T,
}

impl<T: UnsignedInteger> PartialEq for NonPowOf2ApproxSignedBasis<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.modulus == other.modulus
            && self.basis == other.basis
            && self.decompose_length == other.decompose_length
    }
}

impl<T: UnsignedInteger> NonPowOf2ApproxSignedBasis<T> {
    /// Creates a new [`NonPowOf2ApproxSignedBasis<T>`].
    ///
    /// # Panics
    ///
    /// Panics if
    /// - modulus is a power of 2.
    /// - `log_basis` is large than `modulus bits` or equals to `0`.
    /// - `decompose_length` is equals to 0.
    #[inline]
    pub fn new(modulus: T, log_basis: u32, reverse_length: Option<usize>) -> Self {
        assert!(log_basis > 0 && !modulus.is_power_of_two());

        let modulus_bits = <T as Bits>::BITS - modulus.leading_zeros();

        assert!(modulus_bits >= log_basis);

        let basis = <T as ConstOne>::ONE << log_basis;
        let mut decompose_length = (modulus_bits / log_basis) as usize;
        let mut drop_bits = modulus_bits - (decompose_length as u32) * log_basis;

        if let Some(reverse_len) = reverse_length {
            assert!(decompose_length >= reverse_len);
            decompose_length = reverse_len;
            drop_bits = modulus_bits - (reverse_len as u32) * log_basis;
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

        let basis_minus_one = basis - <T as ConstOne>::ONE;

        let split_value = if log_basis == 1 {
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
                if value >= modulus {
                    None
                } else {
                    Some(value)
                }
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
            if value >= modulus {
                None
            } else {
                Some(value)
            }
        };

        let next_pow_of_2_sub_modulus = (T::MAX >> (T::BITS - modulus_bits)) - (modulus - T::ONE);

        Self {
            modulus,
            basis,
            basis_minus_one,
            init_carry_mask,
            carry_mask,
            decompose_length,
            log_basis,
            drop_bits,
            split_value,
            next_pow_of_2_sub_modulus,
        }
    }

    /// Returns the decompose length of this [`NonPowOf2ApproxSignedBasis<T>`].
    #[inline]
    pub fn decompose_length(&self) -> usize {
        self.decompose_length
    }

    /// Returns the basis value of this [`NonPowOf2ApproxSignedBasis<T>`].
    #[inline]
    pub fn basis_value(&self) -> T {
        self.basis
    }

    /// Returns the basis minus one of this [`NonPowOf2ApproxSignedBasis<T>`].
    #[inline]
    pub fn basis_minus_one(&self) -> T {
        self.basis_minus_one
    }

    /// Returns the log basis of this [`NonPowOf2ApproxSignedBasis<T>`].
    #[inline]
    pub fn log_basis(&self) -> u32 {
        self.log_basis
    }

    /// Returns the drop bits of this [`NonPowOf2ApproxSignedBasis<T>`].
    ///
    /// This means some bits of the value will be dropped
    /// according to approximate signed decomposition.
    #[inline]
    pub fn drop_bits(&self) -> u32 {
        self.drop_bits
    }

    /// Returns the init carry mask of this [`NonPowOf2ApproxSignedBasis<T>`].
    ///
    /// This value is used for generating the initial carry for decomposition.
    #[inline]
    pub fn init_carry_mask(&self) -> Option<T> {
        self.init_carry_mask
    }

    /// Returns an iterator over the signed decomposition operators of this [`NonPowOf2ApproxSignedBasis<T>`].
    #[inline]
    pub fn decompose_iter(&self) -> SignedDecomposeIter<T> {
        SignedDecomposeIter::<T> {
            length: self.decompose_length,
            value_chunk_mask: self.basis_minus_one << self.drop_bits,
            mask_shl_bits: self.log_basis,
            value_shr_bits: self.drop_bits,
            carry_mask: self.carry_mask,
            basis_minus_one: self.basis_minus_one,
            modulus_minus_basis: self.modulus - self.basis,
        }
    }

    /// Returns an iterator over scalars of this [`NonPowOf2ApproxSignedBasis<T>`].
    #[inline]
    pub fn scalar_iter(&self) -> ScalarIter<T> {
        ScalarIter::new(
            T::ONE << self.drop_bits,
            self.decompose_length,
            self.log_basis,
        )
    }

    /// Init carry and adjusted value for a value.
    #[inline]
    pub fn init_value_carry(&self, value: T) -> (T, bool) {
        let mut adjust = value;
        if let Some(split) = self.split_value {
            if value >= split {
                adjust += self.next_pow_of_2_sub_modulus;
            }
        }

        (
            adjust,
            match self.init_carry_mask {
                Some(mask) => !(adjust & mask).is_zero(),
                None => false,
            },
        )
    }

    /// Init carries and adjusted values for a slice and store the adjusted values back to `values`.
    #[inline]
    pub fn init_value_carry_slice_inplace(&self, values: &mut [T], carries: &mut [bool]) {
        if let Some(split) = self.split_value {
            values.iter_mut().for_each(|value| {
                if *value >= split {
                    *value += self.next_pow_of_2_sub_modulus;
                }
            })
        }

        match self.init_carry_mask {
            Some(mask) => izip!(values.iter(), carries).for_each(|(&value, carry)| {
                *carry = !(value & mask).is_zero();
            }),
            None => carries.fill(false),
        };
    }

    /// Init carries and adjusted values for a slice.
    #[inline]
    pub fn init_value_carry_slice(
        &self,
        values: &[T],
        carries: &mut [bool],
        adjust_values: &mut [T],
    ) {
        if let Some(split) = self.split_value {
            adjust_values
                .iter_mut()
                .zip(values)
                .for_each(|(adjust_value, &value)| {
                    if value >= split {
                        *adjust_value = value + self.next_pow_of_2_sub_modulus;
                    } else {
                        *adjust_value = value;
                    }
                })
        } else {
            adjust_values.copy_from_slice(values);
        }

        match self.init_carry_mask {
            Some(mask) => izip!(adjust_values.iter(), carries).for_each(|(&value, carry)| {
                *carry = !(value & mask).is_zero();
            }),
            None => carries.fill(false),
        };
    }
}

/// An iterator over the signed decomposition operators.
pub struct SignedDecomposeIter<T: UnsignedInteger> {
    pub(super) length: usize,
    pub(super) value_chunk_mask: T,
    pub(super) mask_shl_bits: u32,
    pub(super) value_shr_bits: u32,
    pub(super) carry_mask: T,
    pub(super) basis_minus_one: T,
    pub(super) modulus_minus_basis: T,
}

impl<T: UnsignedInteger> Iterator for SignedDecomposeIter<T> {
    type Item = SignedOnceDecompose<T>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.length == 0 {
            None
        } else {
            let next = SignedOnceDecompose::<T> {
                value_chunk_mask: self.value_chunk_mask,
                shr_bits: self.value_shr_bits,
                carry_mask: self.carry_mask,
                basis_minus_one: self.basis_minus_one,
                modulus_minus_basis: self.modulus_minus_basis,
            };

            self.length -= 1;

            if self.length > 0 {
                self.value_chunk_mask <<= self.mask_shl_bits;
                self.value_shr_bits += self.mask_shl_bits;
            }

            Some(next)
        }
    }
}

/// The signed decomposition operator which can execute once decomposition.
pub struct SignedOnceDecompose<T: UnsignedInteger> {
    value_chunk_mask: T,
    shr_bits: u32,
    carry_mask: T,
    basis_minus_one: T,
    modulus_minus_basis: T,
}

impl<T: UnsignedInteger> SignedOnceDecompose<T> {
    /// Execute once decomposition and return the decomposed value and carry for next decomposition.
    #[inline]
    pub fn decompose(&self, value: T, carry: bool) -> (T, bool) {
        let mut temp = ((value & self.value_chunk_mask) >> self.shr_bits) + T::as_from(carry);

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
    pub fn decompose_inplace(&self, value: T, carry: &mut bool, decomposed_value: &mut T) {
        let temp = ((value & self.value_chunk_mask) >> self.shr_bits) + T::as_from(*carry);
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
    pub fn decompose_slice_inplace(
        &self,
        values: &[T],
        carries: &mut [bool],
        decompose_slice: &mut [T],
    ) {
        for (&value, carry, des) in izip!(values, carries, decompose_slice) {
            self.decompose_inplace(value, carry, des);
        }
    }
}

/// An iterator over scalars.
pub struct ScalarIter<T: UnsignedInteger> {
    scalar: T,
    length: usize,
    log_basis: u32,
}

impl<T: UnsignedInteger> ScalarIter<T> {
    /// Creates a new [`ScalarIter<T>`].
    #[inline]
    pub fn new(scalar: T, length: usize, log_basis: u32) -> Self {
        Self {
            scalar,
            length,
            log_basis,
        }
    }
}

impl<T: UnsignedInteger> Iterator for ScalarIter<T> {
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.length == 0 {
            None
        } else {
            let next = self.scalar;
            self.length -= 1;
            if self.length != 0 {
                self.scalar <<= self.log_basis;
            }
            Some(next)
        }
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use rand::Rng;
    use rand_distr::Uniform;

    use crate::{
        modulus::BarrettModulus,
        reduce::{ReduceMulAdd, ReduceSub},
    };

    use super::*;

    type ValueT = u32;
    type SignedT = i64;

    #[test]
    #[ignore = "check implementation"]
    fn test_single_decompose() {
        let modulus_value: ValueT = 0b111_000_110;
        let modulus = <BarrettModulus<ValueT>>::new(modulus_value);
        let modulus_bits = (ValueT::BITS - modulus_value.leading_zeros()) as usize;
        let basis = NonPowOf2ApproxSignedBasis::new(modulus_value, 1, None);

        let differ_max = basis.init_carry_mask.unwrap_or(0);

        let basis_value = basis.basis_value();
        let log_basis = basis.log_basis as usize;
        let mut decv = Vec::with_capacity(basis.decompose_length());

        let mut value = 0b11_111_100;

        let show = |value: ValueT| {
            let value = if value > modulus_value.next_power_of_two() {
                value - modulus_value.next_power_of_two()
            } else {
                value
            };
            let value_str = format!("{:01$b}", value, modulus_bits);

            let (pre, end) = value_str.split_at(log_basis * basis.decompose_length);

            pre.chars().chunks(log_basis).into_iter().for_each(|v| {
                let str: String = v.collect();
                print!("{}|", str);
            });
            println!("{}", end);
        };

        println!("value");
        show(value);

        let (value_d, mut carry) = basis.init_value_carry(value);

        println!("value_d");
        show(value_d);

        for b in basis.decompose_iter() {
            let (di, ci) = b.decompose(value_d, carry);
            decv.push(di);
            carry = ci;
        }

        let result = basis
            .scalar_iter()
            .zip(decv.iter())
            .fold(0, |acc, (scalar, &dec)| {
                modulus.reduce_mul_add(scalar, dec, acc)
            });

        for &d in decv.iter().rev() {
            if basis_value > 2 {
                if d >= basis_value / 2 {
                    print!("{:1$}|", d as SignedT - modulus_value as SignedT, log_basis);
                } else {
                    print!("{:1$}|", d, log_basis);
                }
            } else {
                print!("{:1$}|", d, log_basis);
            }
        }
        println!();

        if value >= modulus_value {
            value -= modulus_value;
        }

        println!("value ={}", value);
        println!("result={}", result);

        let difference = modulus
            .reduce_sub(result, value)
            .min(modulus.reduce_sub(value, result));

        println!("differ={}", difference);
        println!("differ_max={}", differ_max);

        assert!(difference <= differ_max);
    }

    #[test]
    fn test_approx_signed_decompose() {
        let mut rng = rand::thread_rng();
        let modulus_value: ValueT = rng.gen_range(512..(1 << 30));
        let modulus = <BarrettModulus<ValueT>>::new(modulus_value);
        let modulus_bits = (ValueT::BITS - modulus_value.leading_zeros()) as usize;
        let basis = NonPowOf2ApproxSignedBasis::new(modulus_value, 4, None);

        let differ_max = basis.init_carry_mask.unwrap_or(0);

        let basis_value = basis.basis_value();
        let log_basis = basis.log_basis as usize;
        let distr = Uniform::new(0, modulus_value);

        let mut decv = Vec::with_capacity(basis.decompose_length());
        for value in rng.sample_iter(distr).take(1000) {
            decv.clear();

            let (value_d, mut carry) = basis.init_value_carry(value);
            for b in basis.decompose_iter() {
                let (di, ci) = b.decompose(value_d, carry);
                decv.push(di);
                carry = ci;
            }

            let result = basis
                .scalar_iter()
                .zip(decv.iter())
                .fold(0, |acc, (scalar, &dec)| {
                    modulus.reduce_mul_add(scalar, dec, acc)
                });

            let difference = modulus
                .reduce_sub(result, value)
                .min(modulus.reduce_sub(value, result));

            if difference > differ_max {
                let show = |value: ValueT| {
                    let value_str = format!("{:01$b}", value, modulus_bits);

                    let (pre, end) = value_str.split_at(log_basis * basis.decompose_length);

                    pre.chars().chunks(log_basis).into_iter().for_each(|v| {
                        let str: String = v.collect();
                        print!("{}|", str);
                    });
                    println!("{}", end);
                };

                println!("value");
                show(value);

                for &d in decv.iter().rev() {
                    if basis_value > 2 {
                        if d >= basis_value / 2 {
                            print!("{:1$}|", d as SignedT - modulus_value as SignedT, log_basis);
                        } else {
                            print!("{:1$}|", d, log_basis);
                        }
                    } else {
                        print!("{:1$}|", d, log_basis);
                    }
                }
                println!();

                println!("value ={}", value);
                println!("result={}", result);
                println!("differ={}", difference);
                panic!("basis={}", basis_value)
            }
        }
    }

    #[test]
    fn test_decompose_slice() {
        const N: usize = 32;
        let mut rng = rand::thread_rng();
        let modulus_value: ValueT = rng.gen_range(128..(1 << 30));
        let modulus = <BarrettModulus<ValueT>>::new(modulus_value);
        let distr = Uniform::new(0, modulus_value);

        let basis = NonPowOf2ApproxSignedBasis::new(modulus_value, 1, None);
        let differ_max = basis.init_carry_mask.unwrap_or(0);

        let input: Vec<ValueT> = rand::thread_rng().sample_iter(distr).take(N).collect();

        let mut carries = vec![false; N];
        let mut adjust_input = input.clone();
        // basis.init_value_carry_slice_inplace(&mut adjust_input, &mut carries);
        basis.init_value_carry_slice(&input, &mut carries, &mut adjust_input);

        let mut output = vec![vec![0; N]; basis.decompose_length()];
        basis
            .decompose_iter()
            .zip(&mut output)
            .for_each(|(d, out)| d.decompose_slice_inplace(&adjust_input, &mut carries, out));

        let result = output.iter().zip(basis.scalar_iter()).fold(
            vec![0; N],
            |mut acc: Vec<ValueT>, (dec, scalar)| {
                acc.iter_mut().zip(dec.iter()).for_each(|(r, &d)| {
                    *r = modulus.reduce_mul_add(d, scalar, *r);
                });
                acc
            },
        );

        izip!(input, result).for_each(|(i, o)| {
            let difference = modulus.reduce_sub(i, o).min(modulus.reduce_sub(o, i));
            if difference > differ_max {
                println!("i ={}", i);
                println!("o ={}", o);
                println!("differ={}", difference);
            }
        });
    }
}
