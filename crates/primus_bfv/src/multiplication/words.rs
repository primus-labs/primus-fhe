//! Little-endian words for BFV multiplication bounds and exact scaling.

use core::cmp::Ordering;

use primus_integer::BigUint;

pub(super) fn half(value: &[u64]) -> Vec<u64> {
    let mut result = value.to_vec();
    BigUint(result.as_mut_slice()).right_shift_assign(1);
    result
}

pub(super) fn cmp_words(a: &[u64], b: &[u64]) -> Ordering {
    for index in (0..a.len().max(b.len())).rev() {
        match a
            .get(index)
            .copied()
            .unwrap_or(0)
            .cmp(&b.get(index).copied().unwrap_or(0))
        {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    Ordering::Equal
}

pub(super) fn mul_scalar_to(input: &[u64], scalar: u64, output: &mut [u64]) {
    debug_assert!(output.len() > input.len());
    output.fill(0);
    let mut carry = 0;
    for (&value, destination) in input.iter().zip(output.iter_mut()) {
        let product = value as u128 * scalar as u128 + carry as u128;
        *destination = product as u64;
        carry = (product >> 64) as u64;
    }
    output[input.len()] = carry;
}

pub(super) fn add_words_assign(acc: &mut [u64], value: &[u64]) {
    let mut carry = false;
    for (index, destination) in acc.iter_mut().enumerate() {
        let (sum, c0) = destination.overflowing_add(value.get(index).copied().unwrap_or(0));
        let (sum, c1) = sum.overflowing_add(u64::from(carry));
        *destination = sum;
        carry = c0 || c1;
    }
    debug_assert!(!carry);
}

pub(super) fn sub_words_assign(acc: &mut [u64], value: &[u64]) {
    let mut borrow = false;
    for (index, destination) in acc.iter_mut().enumerate() {
        let (difference, b0) = destination.overflowing_sub(value.get(index).copied().unwrap_or(0));
        let (difference, b1) = difference.overflowing_sub(u64::from(borrow));
        *destination = difference;
        borrow = b0 || b1;
    }
    debug_assert!(!borrow);
}

pub(super) fn shift_left(value: &mut [u64], shift: u32) -> u64 {
    if shift == 0 {
        return 0;
    }
    let mut carry = 0;
    for word in value {
        let next = *word >> (64 - shift);
        *word = (*word << shift) | carry;
        carry = next;
    }
    carry
}
