use itertools::izip;
use num_traits::ConstOne;

use crate::integer::UnsignedInteger;

use super::{ScalarIter, SignedDecomposeIter};

/// The basis for approximate signed decomposition of power of 2 modulus value.
#[derive(Debug, Clone, Copy, Eq)]
pub struct PowOf2ApproxSignedBasis<T: UnsignedInteger> {
    log_modulus: u32,
    basis: T,
    basis_minus_one: T,
    init_carry_mask: Option<T>,
    carry_mask: T,
    decompose_length: usize,
    log_basis: u32,
    drop_bits: u32,
}

impl<T: UnsignedInteger> PartialEq for PowOf2ApproxSignedBasis<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.log_modulus == other.log_modulus
            && self.basis == other.basis
            && self.decompose_length == other.decompose_length
    }
}

impl<T: UnsignedInteger> PowOf2ApproxSignedBasis<T> {
    /// Creates a new [`PowOf2ApproxSignedBasis<T>`].
    ///
    /// # Panics
    ///
    /// Panics if
    /// - modulus is not suitable for [`UnsignedInteger`] type `T`.
    /// - `log_basis` is large than `log_modulus` or equals to `0`.
    /// - `decompose_length` is equals to 0.
    #[inline]
    pub fn new(log_modulus: u32, log_basis: u32, reverse_length: Option<usize>) -> Self {
        assert!(log_basis > 0 && log_modulus <= T::BITS && log_modulus >= log_basis);

        let basis = <T as ConstOne>::ONE << log_basis;
        let mut decompose_length = (log_modulus / log_basis) as usize;
        let mut drop_bits = log_modulus - (decompose_length as u32) * log_basis;

        if let Some(reverse_len) = reverse_length {
            assert!(decompose_length >= reverse_len);
            decompose_length = reverse_len;
            drop_bits = log_modulus - (reverse_len as u32) * log_basis;
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

        Self {
            log_modulus,
            basis,
            basis_minus_one: basis - <T as ConstOne>::ONE,
            init_carry_mask,
            carry_mask,
            decompose_length,
            log_basis,
            drop_bits,
        }
    }

    /// Returns the decompose length of this [`PowOf2ApproxSignedBasis<T>`].
    #[inline]
    pub fn decompose_length(&self) -> usize {
        self.decompose_length
    }

    /// Returns the basis value of this [`PowOf2ApproxSignedBasis<T>`].
    #[inline]
    pub fn basis_value(&self) -> T {
        self.basis
    }

    /// Returns the basis minus one of this [`PowOf2ApproxSignedBasis<T>`].
    #[inline]
    pub fn basis_minus_one(&self) -> T {
        self.basis_minus_one
    }

    /// Returns the log basis of this [`PowOf2ApproxSignedBasis<T>`].
    #[inline]
    pub fn log_basis(&self) -> u32 {
        self.log_basis
    }

    /// Returns the drop bits of this [`PowOf2ApproxSignedBasis<T>`].
    ///
    /// This means some bits of the value will be dropped
    /// according to approximate signed decomposition.
    #[inline]
    pub fn drop_bits(&self) -> u32 {
        self.drop_bits
    }

    /// Returns the init carry mask of this [`PowOf2ApproxSignedBasis<T>`].
    ///
    /// This value is used for generating the initial carry for decomposition.
    #[inline]
    pub fn init_carry_mask(&self) -> Option<T> {
        self.init_carry_mask
    }

    /// Returns an iterator over the signed decomposition operators of this [`PowOf2ApproxSignedBasis<T>`].
    #[inline]
    pub fn decompose_iter(&self) -> SignedDecomposeIter<T> {
        SignedDecomposeIter::<T> {
            length: self.decompose_length,
            value_chunk_mask: self.basis_minus_one << self.drop_bits,
            mask_shl_bits: self.log_basis,
            value_shr_bits: self.drop_bits,
            carry_mask: self.carry_mask,
            basis_minus_one: self.basis_minus_one,
            modulus_minus_basis: (T::MAX >> (T::BITS - self.log_modulus)) - self.basis_minus_one,
        }
    }

    /// Returns an iterator over scalars of this [`PowOf2ApproxSignedBasis<T>`].
    #[inline]
    pub fn scalar_iter(&self) -> ScalarIter<T> {
        ScalarIter::new(
            T::ONE << self.drop_bits,
            self.decompose_length,
            self.log_basis,
        )
    }

    /// Init carry for a value.
    #[inline]
    pub fn init_carry(&self, value: T) -> bool {
        match self.init_carry_mask {
            Some(mask) => !(value & mask).is_zero(),
            None => false,
        }
    }

    /// Init carries for a slice.
    #[inline]
    pub fn init_carry_slice(&self, values: &[T], carries: &mut [bool]) {
        match self.init_carry_mask {
            Some(mask) => izip!(values, carries)
                .for_each(|(&value, carry)| *carry = !(value & mask).is_zero()),
            None => carries.fill(false),
        };
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use rand::{thread_rng, Rng};

    use crate::{
        modulus::PowOf2Modulus,
        reduce::{ReduceMulAdd, ReduceSub},
    };

    use super::*;

    type ValueT = u32;
    type WideSignedT = i64;
    const LOG_MODULUS: u32 = 16;
    const MODULUS_MINUS_ONE: ValueT = ValueT::MAX >> (ValueT::BITS - LOG_MODULUS);

    #[test]
    fn test_pow_of_2_approx_signed_decompose() {
        let rng = thread_rng();

        let modulus = <PowOf2Modulus<ValueT>>::new_with_mask(MODULUS_MINUS_ONE);
        let basis = PowOf2ApproxSignedBasis::new(LOG_MODULUS, 6, None);

        let differ_max = basis.init_carry_mask.unwrap_or(0);

        let basis_value = basis.basis_value();
        let log_basis = basis.log_basis as usize;

        let distr = rand_distr::Uniform::new_inclusive(0, MODULUS_MINUS_ONE);

        let mut decv = Vec::with_capacity(basis.decompose_length());
        for value in rng.sample_iter(distr).take(100) {
            decv.clear();

            let mut carry = basis.init_carry(value);
            for d in basis.decompose_iter() {
                let (di, ci) = d.decompose(value, carry);
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
                    let value_str = format!("{:01$b}", value, LOG_MODULUS as usize);

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
                            print!(
                                "{:1$}|",
                                d as WideSignedT - MODULUS_MINUS_ONE as WideSignedT - 1,
                                log_basis
                            );
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
}
