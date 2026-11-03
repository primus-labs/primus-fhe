use core::cmp::Ordering;

use primus_data::{Data, DataMut};
use primus_integer::BigUint;
use primus_ntt::NttTable;
use primus_reduce::{Reduce, ReduceNeg};
use primus_rns::Residues;

use crate::{BfvCiphertext, BfvContext, BfvQuadraticCiphertext};

use super::{add_words_assign, cmp_words, half, mul_scalar_to, shift_left, sub_words_assign};

/// Prepared exact integer schoolbook reference for BFV multiplication.
///
/// This separate owner stores full signed integer tensor coefficients and uses
/// exact binary long division. It needs no auxiliary basis and has no external
/// big-integer dependency. It is useful for small independent comparisons and
/// fallback execution, while [`super::BfvMultiplier`] is the default NTT path. Preparing
/// the default multiplier does not allocate this reference's extra buffers.
/// All online calls allocate nothing. Input/level/noise contracts are identical
/// to [`super::BfvMultiplier`]'s; Q must be odd.
pub(super) struct BfvReferenceMultiplier<'a> {
    context: &'a BfvContext,
    level: usize,
    half_q: Vec<u64>,
    coefficients: Vec<u64>,
    values: Vec<u64>,
    signs: Vec<bool>,
    tensor: Vec<u64>,
    tensor_signs: Vec<bool>,
    term: Vec<u64>,
    residues: Vec<u64>,
    value: Vec<u64>,
    numerator: Vec<u64>,
    quotient: Vec<u64>,
    remainder: Vec<u64>,
}

impl<'a> BfvReferenceMultiplier<'a> {
    /// Prepares the integer reference and all its reusable arithmetic storage.
    ///
    /// # Panics
    /// Panics for an unprepared level or overflowing complete storage length.
    #[must_use]
    pub fn new(context: &'a BfvContext, level: usize) -> Self {
        let base_q = context.codec(level).base_q();
        let n = context.parameters().poly_length().get();
        let words = base_q.big_uint_value_len();
        let tensor_words = words
            .checked_mul(2)
            .and_then(|x| x.checked_add(1))
            .expect("BFV reference tensor width overflow");
        let values_length = n
            .checked_mul(4)
            .and_then(|x| x.checked_mul(words))
            .expect("BFV reference input storage overflow");
        let tensor_length = n
            .checked_mul(3)
            .and_then(|x| x.checked_mul(tensor_words))
            .expect("BFV reference tensor storage overflow");
        let coefficient_length = context
            .rns_poly_len(level)
            .checked_mul(4)
            .expect("BFV reference coefficient storage overflow");
        Self {
            context,
            level,
            half_q: half(base_q.moduli_product().digits()),
            coefficients: vec![0; coefficient_length],
            values: vec![0; values_length],
            signs: vec![false; 4 * n],
            tensor: vec![0; tensor_length],
            tensor_signs: vec![false; 3 * n],
            term: vec![0; tensor_words],
            residues: vec![0; base_q.moduli_count()],
            value: vec![0; words],
            numerator: vec![0; tensor_words + 1],
            quotient: vec![0; tensor_words + 1],
            remainder: vec![0; words + 1],
        }
    }

    /// Writes the exact integer tensor followed by nearest t/Q scaling modulo Q.
    ///
    /// Both middle products are accumulated as signed integers before rounding.
    ///
    /// # Panics
    /// Rejects every complete input/output length before any writes. As with the
    /// default path, canonical NTT residues and actual identities are assumed.
    pub fn multiply_to<A, B, C>(
        &mut self,
        lhs: &BfvCiphertext<A>,
        rhs: &BfvCiphertext<B>,
        output: &mut BfvQuadraticCiphertext<C>,
    ) where
        A: Data<Elem = u64>,
        B: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        let n = self.context.parameters().poly_length().get();
        let base_q = self.context.codec(self.level).base_q();
        let q_length = self.context.rns_poly_len(self.level);
        assert_eq!(lhs.as_ref().len(), 2 * q_length);
        assert_eq!(rhs.as_ref().len(), 2 * q_length);
        assert_eq!(output.as_ref().len(), 3 * q_length);
        self.coefficients[..2 * q_length].copy_from_slice(lhs.as_ref());
        self.coefficients[2 * q_length..].copy_from_slice(rhs.as_ref());
        let words = base_q.big_uint_value_len();
        for (component_index, component) in self.coefficients.chunks_exact_mut(q_length).enumerate()
        {
            for (table, values) in self
                .context
                .table()
                .iter()
                .take(base_q.moduli_count())
                .zip(component.chunks_exact_mut(n))
            {
                table.inverse_transform_slice(values);
            }
            for coefficient in 0..n {
                for (i, residue) in self.residues.iter_mut().enumerate() {
                    *residue = component[i * n + coefficient];
                }
                base_q.compose_to(Residues(&self.residues), BigUint(self.value.as_mut_slice()));
                let index = component_index * n + coefficient;
                let negative = cmp_words(&self.value, &self.half_q) == Ordering::Greater;
                let destination = &mut self.values[index * words..(index + 1) * words];
                destination.copy_from_slice(&self.value);
                if negative {
                    sub_from_words(base_q.moduli_product().digits(), destination);
                }
                self.signs[index] = negative;
            }
        }
        self.tensor.fill(0);
        self.tensor_signs.fill(false);
        let tensor_words = self.term.len();
        for (destination_component, lhs_component, rhs_component) in
            [(0, 0, 2), (1, 0, 3), (1, 1, 2), (2, 1, 3)]
        {
            for i in 0..n {
                let lhs_index = lhs_component * n + i;
                let a = &self.values[lhs_index * words..(lhs_index + 1) * words];
                for j in 0..n {
                    let rhs_index = rhs_component * n + j;
                    let b = &self.values[rhs_index * words..(rhs_index + 1) * words];
                    mul_words_to(a, b, &mut self.term);
                    let index = destination_component * n + ((i + j) & (n - 1));
                    let negative = self.signs[lhs_index] ^ self.signs[rhs_index] ^ (i + j >= n);
                    accumulate_signed(
                        &mut self.tensor[index * tensor_words..(index + 1) * tensor_words],
                        &mut self.tensor_signs[index],
                        &self.term,
                        negative,
                    );
                }
            }
        }
        let t = self.context.codec(self.level).t();
        for (component_index, component) in output.as_mut().chunks_exact_mut(q_length).enumerate() {
            for coefficient in 0..n {
                let index = component_index * n + coefficient;
                let z = &self.tensor[index * tensor_words..(index + 1) * tensor_words];
                mul_scalar_to(z, t, &mut self.numerator);
                add_words_assign(&mut self.numerator, &self.half_q);
                divide_words_to(
                    &self.numerator,
                    base_q.moduli_product().digits(),
                    &mut self.quotient,
                    &mut self.remainder,
                );
                for (i, &q) in base_q.moduli().iter().enumerate() {
                    let value = q.reduce(self.quotient.as_slice());
                    component[i * n + coefficient] = if self.tensor_signs[index] {
                        q.reduce_neg(value)
                    } else {
                        value
                    };
                }
            }
            for (table, values) in self
                .context
                .table()
                .iter()
                .take(base_q.moduli_count())
                .zip(component.chunks_exact_mut(n))
            {
                table.transform_slice(values);
            }
        }
    }

    /// Writes a reference square using the same exact integer pipeline.
    ///
    /// Inherits [`Self::multiply_to`]'s contracts.
    pub fn square_to<A, C>(
        &mut self,
        input: &BfvCiphertext<A>,
        output: &mut BfvQuadraticCiphertext<C>,
    ) where
        A: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        self.multiply_to(input, input, output);
    }
}

fn sub_from_words(lhs: &[u64], rhs_and_output: &mut [u64]) {
    let mut borrow = false;
    for (index, destination) in rhs_and_output.iter_mut().enumerate() {
        let (difference, b0) = lhs
            .get(index)
            .copied()
            .unwrap_or(0)
            .overflowing_sub(*destination);
        let (difference, b1) = difference.overflowing_sub(u64::from(borrow));
        *destination = difference;
        borrow = b0 || b1;
    }
    debug_assert!(!borrow);
}

fn mul_words_to(lhs: &[u64], rhs: &[u64], output: &mut [u64]) {
    debug_assert!(output.len() >= lhs.len() + rhs.len());
    output.fill(0);
    for (i, &a) in lhs.iter().enumerate() {
        let mut carry = 0;
        for (j, &b) in rhs.iter().enumerate() {
            let value = a as u128 * b as u128 + output[i + j] as u128 + carry as u128;
            output[i + j] = value as u64;
            carry = (value >> 64) as u64;
        }
        output[i + rhs.len()] = carry;
    }
}

fn accumulate_signed(acc: &mut [u64], negative: &mut bool, term: &[u64], term_negative: bool) {
    if *negative == term_negative {
        add_words_assign(acc, term);
    } else {
        match cmp_words(acc, term) {
            Ordering::Less => {
                sub_from_words(term, acc);
                *negative = term_negative;
            }
            Ordering::Equal => {
                acc.fill(0);
                *negative = false;
            }
            Ordering::Greater => sub_words_assign(acc, term),
        }
    }
}

// Full multiword division is confined to the deliberately slow independent
// reference. Its remainder buffer has one extra word so every bit shift fits.
fn divide_words_to(
    numerator: &[u64],
    denominator: &[u64],
    quotient: &mut [u64],
    remainder: &mut [u64],
) {
    quotient.fill(0);
    remainder.fill(0);
    for (word_index, &word) in numerator.iter().enumerate().rev() {
        for bit in (0..64).rev() {
            let carry = shift_left(remainder, 1);
            debug_assert_eq!(carry, 0);
            remainder[0] |= (word >> bit) & 1;
            if cmp_words(remainder, denominator) != Ordering::Less {
                sub_words_assign(remainder, denominator);
                quotient[word_index] |= 1 << bit;
            }
        }
    }
}
