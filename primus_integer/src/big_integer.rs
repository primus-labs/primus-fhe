use core::cmp::Ordering;
use std::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use primus_data::{Data, DataMut, RawData};
use serde::{Deserialize, Serialize};

use crate::{UnsignedInteger, impl_iters};

/// A big unsigned integer backed by externally provided limb storage.
///
/// `BigUint<S>` is designed to work as a lightweight view or container over an
/// existing limb buffer instead of as a normalized arbitrary-precision integer.
/// The storage backend `S` can therefore be borrowed or owned, for example:
///
/// - `BigUint<&[T]>`
/// - `BigUint<&mut [T]>`
/// - `BigUint<Vec<T>>`
/// - `BigUint<Box<[T]>>`
///
/// The limb order is little-endian: index `0` stores the least significant
/// limb.
///
/// # Design note
///
/// Most arithmetic and comparison methods in this type are intended for
/// buffer-based, fixed-width style usage in higher-level crates, where
/// operands are expected to have the same limb length. This type does not try
/// to canonicalize away leading zero limbs automatically.
///
/// In particular, [`PartialEq::eq`], [`cmp`](BigUint::cmp), and the arithmetic
/// in-place methods all require that all participating [`BigUint`]s share the
/// same storage length. Calling them on operands of differing length is a
/// programmer error and triggers a `debug_assert!` in debug builds; in release
/// builds the comparison/operation iterates the shorter common prefix and any
/// extra trailing limbs are ignored, so prefer to enforce length equality at
/// the call site.
#[derive(Debug, Serialize, Deserialize)]
#[repr(transparent)]
pub struct BigUint<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: UnsignedInteger;

impl_iters!(BigUint, bit_uint);

/// Owned [`BigUint`] backed by a [`Vec`].
pub type BigUintOwned<T> = BigUint<Vec<T>>;
/// Borrowed [`BigUint`] backed by an immutable slice.
pub type BigUintRef<'a, T> = BigUint<&'a [T]>;
/// Mutably borrowed [`BigUint`] backed by a mutable slice.
pub type BigUintMut<'a, T> = BigUint<&'a mut [T]>;

impl<S> Clone for BigUint<S>
where
    S: RawData + Clone,
    <S as RawData>::Elem: UnsignedInteger,
{
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S> Copy for BigUint<S>
where
    S: RawData + Copy,
    <S as RawData>::Elem: UnsignedInteger,
{
}

impl<S, T, I: SliceIndex<[T]>> Index<I> for BigUint<S>
where
    S: Data<Elem = T>,
    T: UnsignedInteger,
{
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(self.0.as_slice(), index)
    }
}

impl<S, T, I: SliceIndex<[T]>> IndexMut<I> for BigUint<S>
where
    S: RawData<Elem = T> + DataMut,
    T: UnsignedInteger,
{
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(self.0.as_mut_slice(), index)
    }
}

impl<S, A, T> PartialEq<BigUint<A>> for BigUint<S>
where
    S: Data<Elem = T>,
    A: Data<Elem = T>,
    T: UnsignedInteger,
{
    #[inline]
    fn eq(&self, other: &BigUint<A>) -> bool {
        debug_assert_eq!(self.len(), other.len());
        self.iter().zip(other.iter()).all(|(&a, &b)| a == b)
    }
}

impl<T> From<BigUint<&[T]>> for BigUint<Vec<T>>
where
    T: UnsignedInteger,
{
    #[inline]
    fn from(BigUint(value): BigUint<&[T]>) -> Self {
        BigUint(value.to_vec())
    }
}

impl<T> From<BigUint<&mut [T]>> for BigUint<Vec<T>>
where
    T: UnsignedInteger,
{
    #[inline]
    fn from(BigUint(value): BigUint<&mut [T]>) -> Self {
        BigUint(value.to_vec())
    }
}

impl<S, T> BigUint<S>
where
    S: Data<Elem = T>,
    T: UnsignedInteger,
{
    /// Returns the number of limbs in the backing storage.
    ///
    /// This is the storage length, not the effective mathematical bit length.
    #[allow(clippy::len_without_is_empty)]
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns the limbs as a slice in little-endian order.
    #[inline(always)]
    pub fn digits(&self) -> &[T] {
        self.0.as_slice()
    }

    /// Returns an iterator over the limbs from least significant to most
    /// significant.
    #[inline(always)]
    pub fn iter<'a>(&'a self) -> std::slice::Iter<'a, T> {
        self.0.iter()
    }

    /// Returns `true` if all limbs are zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.iter().all(T::is_zero)
    }

    /// Returns the effective bit width of the represented value.
    ///
    /// Leading zero limbs are ignored.
    #[must_use]
    #[inline]
    pub fn bits_count(&self) -> u32 {
        self.iter()
            .enumerate()
            .rev()
            .find(|(_, v)| !v.is_zero())
            .map_or(0, |(i, v)| T::BITS * (i as u32 + 1) - v.leading_zeros())
    }

    /// Borrows the same value as an immutable slice-backed [`BigUint`].
    #[inline(always)]
    pub fn view(&self) -> BigUint<&[T]> {
        BigUint(self.0.as_slice())
    }

    /// Adds a value to the big integer, returning true if there was a carry.
    #[must_use]
    #[inline]
    pub fn add_value_to<A>(&self, value: T, result: &mut BigUint<A>) -> bool
    where
        A: DataMut<Elem = T>,
    {
        debug_assert!(!self.0.as_slice().is_empty());
        debug_assert_eq!(self.len(), result.len());

        let mut carry;

        let mut a_iter = self.iter();
        let mut b_iter = result.iter_mut();

        let a_first = a_iter.next().unwrap();
        let b_first = b_iter.next().unwrap();

        (*b_first, carry) = a_first.overflowing_add(value);

        while carry {
            if let Some(a_next) = a_iter.next()
                && let Some(b_next) = b_iter.next()
            {
                (*b_next, carry) = a_next.overflowing_add(T::ONE);
            } else {
                return carry;
            }
        }

        for (a, b) in a_iter.zip(b_iter) {
            *b = *a;
        }

        carry
    }

    /// Subtracts a value to the big integer, returning true if there was a borrow.
    #[must_use]
    #[inline]
    pub fn sub_value_to<A>(&self, value: T, result: &mut BigUint<A>) -> bool
    where
        A: DataMut<Elem = T>,
    {
        debug_assert!(!self.0.as_slice().is_empty());
        debug_assert_eq!(self.len(), result.len());

        let mut borrow;

        let mut a_iter = self.iter();
        let mut b_iter = result.iter_mut();

        let a_first = a_iter.next().unwrap();
        let b_first = b_iter.next().unwrap();

        (*b_first, borrow) = a_first.overflowing_sub(value);

        while borrow {
            if let Some(a_next) = a_iter.next()
                && let Some(b_next) = b_iter.next()
            {
                (*b_next, borrow) = a_next.overflowing_sub(T::ONE);
            } else {
                return borrow;
            }
        }

        for (a, b) in a_iter.zip(b_iter) {
            *b = *a;
        }

        borrow
    }

    /// Multiplies the big integer by a value, storing the result in another big integer.
    #[must_use]
    #[inline]
    pub fn mul_value_to<A>(&self, value: T, result: &mut BigUint<A>) -> T
    where
        A: DataMut<Elem = T>,
    {
        debug_assert_eq!(result.len(), self.len());

        if value.is_zero() {
            result.set_zero();
            return T::ZERO;
        }

        let mut carry = T::ZERO;
        for (ele, res) in self.iter().zip(result.iter_mut()) {
            (*res, carry) = value.carrying_mul(*ele, carry);
        }

        carry
    }

    /// Multiplies the big integer by a value, then add to another big integer.
    #[must_use]
    #[inline]
    pub fn mul_value_add_to<A>(&self, value: T, acc: &mut BigUint<A>) -> T
    where
        A: DataMut<Elem = T>,
    {
        debug_assert_eq!(acc.len(), self.len());

        if value.is_zero() {
            return T::ZERO;
        }

        let mut carry = T::ZERO;
        for (ele, res) in self.iter().zip(acc.iter_mut()) {
            (*res, carry) = value.carrying_mul_add(*ele, *res, carry);
        }

        carry
    }

    /// Adds two big integers to the result, returning true if there was a carry.
    #[must_use]
    #[inline]
    pub fn add_to<A, B>(&self, other: &BigUint<A>, result: &mut BigUint<B>) -> bool
    where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        debug_assert_eq!(self.len(), other.len());
        debug_assert_eq!(self.len(), result.len());

        let mut carry = false;
        for ((xs, ys), zs) in self.iter().zip(other.iter()).zip(result.iter_mut()) {
            (*zs, carry) = xs.carrying_add(*ys, carry);
        }

        carry
    }

    /// Subtracts another big integer from this one, returning true if there was a borrow.
    #[must_use]
    #[inline]
    pub fn sub_to<A, B>(&self, other: &BigUint<A>, result: &mut BigUint<B>) -> bool
    where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        debug_assert_eq!(self.len(), other.len());
        debug_assert_eq!(self.len(), result.len());

        let mut borrow = false;
        for ((xs, ys), zs) in self.iter().zip(other.iter()).zip(result.iter_mut()) {
            (*zs, borrow) = xs.borrowing_sub(*ys, borrow);
        }

        borrow
    }

    /// Compares this big integer with another, returning an [`Ordering`].
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    #[inline]
    pub fn cmp<A>(&self, other: &BigUint<A>) -> Ordering
    where
        A: Data<Elem = T>,
    {
        debug_assert_eq!(self.len(), other.len());

        for (a, b) in self.iter().rev().zip(other.iter().rev()) {
            match a.cmp(b) {
                Ordering::Equal => continue,
                neq => return neq,
            }
        }

        Ordering::Equal
    }

    /// Adds two big integers to the result modulo a given modulus.
    #[inline]
    pub fn add_modulo_to<A, B, C>(
        &self,
        other: &BigUint<A>,
        result: &mut BigUint<B>,
        modulus: &BigUint<C>,
    ) where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
        C: Data<Elem = T>,
    {
        debug_assert!(
            self.len() == other.len() && self.len() == result.len() && self.len() == modulus.len()
        );
        debug_assert!(self.cmp(modulus).is_lt());
        debug_assert!(other.cmp(modulus).is_lt());

        let carry = self.add_to(other, result);
        if carry || result.cmp(modulus).is_ge() {
            let _ = result.sub_assign(modulus);
        }
    }

    /// Subs another big integer to this one modulo a given modulus.
    #[inline]
    pub fn sub_modulo_to<A, B, C>(
        &self,
        other: &BigUint<A>,
        result: &mut BigUint<B>,
        modulus: &BigUint<C>,
    ) where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
        C: Data<Elem = T>,
    {
        debug_assert!(
            self.len() == other.len() && self.len() == result.len() && self.len() == modulus.len()
        );
        debug_assert!(self.cmp(modulus).is_lt());
        debug_assert!(other.cmp(modulus).is_lt());

        if self.sub_to(other, result) {
            let _ = result.add_assign(modulus);
        }
    }

    /// Negates the big integer modulo a given modulus.
    #[inline]
    pub fn neg_modulo_to<A, B>(&self, result: &mut BigUint<A>, modulus: &BigUint<B>)
    where
        A: DataMut<Elem = T>,
        B: Data<Elem = T>,
    {
        debug_assert!(self.len() == result.len() && self.len() == modulus.len());
        debug_assert!(self.cmp(modulus).is_lt());

        if self.is_zero() {
            result.set_zero();
        } else {
            let mut borrow = false;
            for ((xs, ys), zs) in self.iter().zip(modulus.iter()).zip(result.iter_mut()) {
                (*zs, borrow) = ys.borrowing_sub(*xs, borrow);
            }
        }
    }
}

impl<S, T> BigUint<S>
where
    S: DataMut<Elem = T>,
    T: UnsignedInteger,
{
    /// Returns the limbs as a mutable slice in little-endian order.
    #[inline(always)]
    pub fn digits_mut(&mut self) -> &mut [T] {
        self.0.as_mut_slice()
    }

    /// Returns a mutable iterator over the limbs from least significant to most
    /// significant.
    #[inline(always)]
    pub fn iter_mut<'a>(&'a mut self) -> std::slice::IterMut<'a, T> {
        self.0.iter_mut()
    }

    /// Sets all limbs to zero.
    #[inline(always)]
    pub fn set_zero(&mut self) {
        self.0.fill(T::ZERO);
    }

    /// Borrows the same value as a mutable slice-backed [`BigUint`].
    #[inline(always)]
    pub fn view_mut(&mut self) -> BigUint<&mut [T]> {
        BigUint(self.0.as_mut_slice())
    }

    /// Left shifts the big integer.
    #[must_use]
    #[inline]
    pub fn left_shift_assign(&mut self, bits: u32) -> T {
        if bits != 0 {
            let mut pre = T::ZERO;
            let mut temp = T::ZERO;
            let right_shift_bits = T::BITS - bits;
            self.iter_mut().for_each(|value| {
                temp = *value;
                *value = *value << bits | pre >> right_shift_bits;
                pre = temp;
            });
            pre >> right_shift_bits
        } else {
            T::ZERO
        }
    }

    /// Right shifts the big integer.
    #[inline]
    pub fn right_shift_assign(&mut self, bits: u32) {
        if bits != 0 {
            let mut pre = T::ZERO;
            let mut temp = T::ZERO;
            let left_shift_bits = T::BITS - bits;
            self.iter_mut().rev().for_each(|value| {
                temp = *value;
                *value = pre << left_shift_bits | *value >> bits;
                pre = temp;
            });
        }
    }

    /// Adds a value to the big integer, returning true if there was a carry.
    #[must_use]
    #[inline]
    pub fn add_value_assign(&mut self, value: T) -> bool {
        let mut carry;
        match self.digits_mut() {
            [first, other @ ..] => {
                (*first, carry) = first.overflowing_add(value);
                for v in other.iter_mut() {
                    if !carry {
                        return false;
                    }
                    (*v, carry) = (*v).overflowing_add(T::ONE);
                }
                carry
            }
            _ => unreachable!(),
        }
    }

    /// Subtracts a value from the big integer, returning true if there was a borrow.
    #[must_use]
    #[inline]
    pub fn sub_value_assign(&mut self, value: T) -> bool {
        let mut borrow;
        match self.digits_mut() {
            [first, other @ ..] => {
                (*first, borrow) = first.overflowing_sub(value);
                for v in other.iter_mut() {
                    if !borrow {
                        return false;
                    }
                    (*v, borrow) = (*v).overflowing_sub(T::ONE);
                }
                borrow
            }
            _ => unreachable!(),
        }
    }

    /// Multiplies the big integer by a value, returning any carry that results.
    #[must_use]
    #[inline]
    pub fn mul_value_assign(&mut self, value: T) -> T {
        if value.is_zero() {
            self.set_zero();
            return T::ZERO;
        }

        let mut carry = T::ZERO;
        for ele in self.iter_mut() {
            (*ele, carry) = value.carrying_mul(*ele, carry);
        }

        carry
    }

    /// Adds another big integer to this one, returning true if there was a carry.
    #[must_use]
    #[inline]
    pub fn add_assign<A>(&mut self, other: &BigUint<A>) -> bool
    where
        A: Data<Elem = T>,
    {
        debug_assert_eq!(self.len(), other.len());

        let mut carry = false;

        for (xs, ys) in self.iter_mut().zip(other.iter()) {
            (*xs, carry) = xs.carrying_add(*ys, carry);
        }

        carry
    }

    /// Subtracts another big integer from this one, returning true if there was a borrow.
    #[must_use]
    #[inline]
    pub fn sub_assign<A>(&mut self, other: &BigUint<A>) -> bool
    where
        A: Data<Elem = T>,
    {
        debug_assert_eq!(self.len(), other.len());

        let mut borrow = false;

        for (xs, ys) in self.iter_mut().zip(other.iter()) {
            (*xs, borrow) = xs.borrowing_sub(*ys, borrow);
        }

        borrow
    }

    /// Adds another big integer to this one modulo a given modulus.
    #[inline]
    pub fn add_modulo_assign<A, B>(&mut self, other: &BigUint<A>, modulus: &BigUint<B>)
    where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        debug_assert!(self.len() == other.len() && self.len() == modulus.len());
        debug_assert!(self.cmp(modulus).is_lt());
        debug_assert!(other.cmp(modulus).is_lt());

        let carry = self.add_assign(other);
        if carry || self.cmp(modulus).is_ge() {
            let _ = self.sub_assign(modulus);
        }
    }

    /// Subs another big integer from this one modulo a given modulus.
    #[inline]
    pub fn sub_modulo_assign<A, B>(&mut self, other: &BigUint<A>, modulus: &BigUint<B>)
    where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        debug_assert!(self.len() == other.len() && self.len() == modulus.len());
        debug_assert!(
            self.cmp(modulus).is_lt(),
            "self: {:?}\nmodulus: {:?}",
            self.0.as_slice(),
            modulus.0.as_slice()
        );
        debug_assert!(
            other.cmp(modulus).is_lt(),
            "other: {:?}\nmodulus: {:?}",
            other.0.as_slice(),
            modulus.0.as_slice()
        );

        if self.sub_assign(other) {
            let _ = self.add_assign(modulus);
        }
    }

    /// Negates the big integer modulo a given modulus.
    #[inline]
    pub fn neg_modulo_assign<A>(&mut self, modulus: &BigUint<A>)
    where
        A: Data<Elem = T>,
    {
        debug_assert!(self.len() == modulus.len());
        debug_assert!(self.cmp(modulus).is_lt());

        if !self.is_zero() {
            let mut borrow = false;
            for (xs, ys) in self.iter_mut().zip(modulus.iter()) {
                (*xs, borrow) = ys.borrowing_sub(*xs, borrow);
            }
        }
    }
}
/// Multiplies many values together, returning the result as a big integer slice.
///
/// # Panics if
///
/// - `values` is empty
pub fn multiply_many_values<T: UnsignedInteger>(values: &[T]) -> BigUint<Vec<T>> {
    debug_assert!(!values.is_empty());
    let mut result = BigUint(Vec::with_capacity(values.len()));
    result.0.push(values[0]);
    for &v in values.iter().skip(1) {
        let carry = result.mul_value_assign(v);
        if !carry.is_zero() {
            result.0.push(carry);
        }
    }
    result
}

/// Multiplies many values together, except for one specified by index, returning the result as a big integer slice.
///
/// # Panics if
///
/// - `values` is empty
/// - `except >= values.len()`
pub fn multiply_many_values_except<T: UnsignedInteger>(values: &[T], except: usize) -> Vec<T> {
    debug_assert!(!values.is_empty() && except < values.len());
    let mut result = BigUint(Vec::with_capacity(values.len() - 1));
    result.0.push(T::ONE);

    for (_, &v) in values.iter().enumerate().filter(|(i, _)| *i != except) {
        let carry = result.mul_value_assign(v);
        if !carry.is_zero() {
            result.0.push(carry);
        }
    }

    result.0
}

/// Multiplies many values together, except for one specified by index, returning the result as a big integer slice.
///
/// # Panics if
///
/// - `values` is empty
/// - `except >= values.len()`
pub fn multiply_many_values_except_to<T: UnsignedInteger>(
    values: &[T],
    except: usize,
    result: &mut [T],
) {
    debug_assert!(!values.is_empty() && except < values.len());
    result.fill(T::ZERO);
    result[0] = T::ONE;
    let mut len = 1;

    for (_, &v) in values.iter().enumerate().filter(|(i, _)| *i != except) {
        let carry = BigUint(&mut result[0..len]).mul_value_assign(v);
        if !carry.is_zero() {
            result[len] = carry;
            len += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::RngExt;
    use rand::distr::{Distribution, Uniform};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    type ValueT = u32;

    fn compose(value: &[ValueT]) -> u128 {
        assert!(value.len() <= 4);
        let mut result = 0u128;
        for &r in value.iter().rev() {
            result <<= ValueT::BITS;
            result |= r as u128;
        }
        result
    }

    fn compose_u64(value: &[u64]) -> u128 {
        assert!(value.len() <= 2);
        let mut result = 0u128;
        for &r in value.iter().rev() {
            result <<= u64::BITS;
            result |= r as u128;
        }
        result
    }

    #[test]
    fn test_big_uint_ops() {
        let mut rng = rand::rng();
        let moduli: [ValueT; 3] = [134215681, 134176769, 132120577];
        let modulus = multiply_many_values(&moduli);
        let m_raw = compose(modulus.digits());

        assert_eq!(128 - m_raw.leading_zeros(), modulus.bits_count());

        let distr = moduli.map(|m| Uniform::new(0, m).unwrap());

        let a_residues = distr.map(|distr| distr.sample(&mut rng));
        let mut a = multiply_many_values(&a_residues);
        let mut a_raw = compose(a.digits());

        a.right_shift_assign(3);
        a_raw >>= 3;
        assert_eq!(a_raw, compose(a.digits()));

        let carry = a.left_shift_assign(3);
        assert_eq!(carry, 0);
        a_raw <<= 3;
        assert_eq!(a_raw, compose(a.digits()));

        let v: ValueT = rng.random();
        let _r = a.add_value_assign(v);
        a_raw += v as u128;
        assert_eq!(a_raw, compose(a.digits()));

        let _r = a.sub_value_assign(v);
        a_raw -= v as u128;
        assert_eq!(a_raw, compose(a.digits()));

        let r = a.mul_value_assign(v);
        let mut p = a.clone();
        p.0.push(r);
        a_raw *= v as u128;
        assert_eq!(a_raw, compose(p.digits()));

        let mut result = BigUint(vec![0; a.len()]);
        a_raw = compose(a.digits());
        let _carry = a.add_value_to(v, &mut result);
        assert_eq!(a_raw + v as u128, compose(result.digits()));

        let _borrow = a.sub_value_to(v, &mut result);
        assert_eq!(a_raw - v as u128, compose(result.digits()));

        let r = a.mul_value_to(v, &mut result);
        result.0.push(r);
        assert_eq!(a_raw * v as u128, compose(result.digits()));

        let a_residues = distr.map(|distr| distr.sample(&mut rng));
        let b_residues = distr.map(|distr| distr.sample(&mut rng));
        let mut a = multiply_many_values(&a_residues);
        let b = multiply_many_values(&b_residues);
        let a_raw = compose(a.digits());
        let b_raw = compose(b.digits());

        let mut result = b.clone();
        let carry = a.mul_value_add_to(v, &mut result);
        result.0.push(carry);
        assert_eq!(a_raw * v as u128 + b_raw, compose(result.digits()));

        let _r = a.add_assign(&b);
        assert_eq!(a_raw + b_raw, compose(a.digits()));

        let _r = a.sub_assign(&b);
        assert_eq!(a_raw, compose(a.digits()));

        a.add_modulo_assign(&b, &modulus);
        let r = (a_raw + b_raw) % m_raw;
        assert_eq!(r, compose(a.digits()));

        let a_residues = distr.map(|distr| distr.sample(&mut rng));
        let b_residues = distr.map(|distr| distr.sample(&mut rng));
        let mut a = multiply_many_values(&a_residues);
        let b = multiply_many_values(&b_residues);
        let a_raw = compose(a.digits());
        let b_raw = compose(b.digits());

        a.sub_modulo_assign(&b, &modulus);
        let r = (a_raw + m_raw - b_raw) % m_raw;
        assert_eq!(r, compose(a.digits()));

        let mut c = a.clone();
        c.neg_modulo_assign(&modulus);
        let r = a.add_assign(&c);
        assert!(!r);
        assert!(a.is_zero() || a == modulus);
    }

    #[test]
    fn add_value_to_stops_after_carry_chain() {
        let input = [u32::MAX, u32::MAX, 7, 9];
        let mut result = [0u32; 4];

        let carry = BigUint(&input[..]).add_value_to(1, &mut BigUint(&mut result[..]));

        assert!(!carry);
        assert_eq!(result, [0, 0, 8, 9]);
    }

    #[test]
    fn add_value_to_reports_final_carry() {
        let input = [u32::MAX, u32::MAX];
        let mut result = [1u32; 2];

        let carry = BigUint(&input[..]).add_value_to(1, &mut BigUint(&mut result[..]));

        assert!(carry);
        assert_eq!(result, [0, 0]);
    }

    #[test]
    fn sub_value_to_stops_after_borrow_chain() {
        let input = [0u32, 0, 7, 9];
        let mut result = [0u32; 4];

        let borrow = BigUint(&input[..]).sub_value_to(1, &mut BigUint(&mut result[..]));

        assert!(!borrow);
        assert_eq!(result, [u32::MAX, u32::MAX, 6, 9]);
    }

    #[test]
    fn sub_value_to_reports_final_borrow() {
        let input = [0u32, 0];
        let mut result = [1u32; 2];

        let borrow = BigUint(&input[..]).sub_value_to(1, &mut BigUint(&mut result[..]));

        assert!(borrow);
        assert_eq!(result, [u32::MAX, u32::MAX]);
    }

    // Coverage for u64 BigUint multi-limb operations.
    // Builds 2-limb u64 BigUints by decomposing u128 values, so we always
    // exercise the multi-limb path and can cross-check against u128 arithmetic.
    // `mul_value` is omitted because a 2-limb u64 * u64 value can exceed u128.
    #[test]
    fn test_big_uint_ops_u64_two_limbs() {
        let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_0000_0005);

        // Modulus: a 2-limb u64 value strictly less than 2^128.
        let m_raw: u128 = 0xc0ff_ee15_dead_beef_face_b00c_1337_4242;
        let modulus = BigUint::<Vec<u64>>(vec![m_raw as u64, (m_raw >> 64) as u64]);

        assert_eq!(128 - m_raw.leading_zeros(), modulus.bits_count());

        let split = |v: u128| -> Vec<u64> { vec![v as u64, (v >> 64) as u64] };

        let a_raw: u128 = rng.random_range(0..m_raw);
        let b_raw: u128 = rng.random_range(0..m_raw);

        let mut a = BigUint::<Vec<u64>>(split(a_raw));
        let b = BigUint::<Vec<u64>>(split(b_raw));

        // shift
        let mut a_shifted = a.clone();
        a_shifted.right_shift_assign(5);
        assert_eq!(a_raw >> 5, compose_u64(a_shifted.digits()));
        let carry = a_shifted.left_shift_assign(5);
        assert_eq!(carry, 0);
        assert_eq!((a_raw >> 5) << 5, compose_u64(a_shifted.digits()));

        // add_value / sub_value within range that doesn't overflow the BigUint
        let v: u64 = rng.random_range(0u64..(1 << 32));
        let mut a_av = a.clone();
        let _r = a_av.add_value_assign(v);
        assert_eq!(a_raw.wrapping_add(v as u128), compose_u64(a_av.digits()));
        let _r = a_av.sub_value_assign(v);
        assert_eq!(a_raw, compose_u64(a_av.digits()));

        // add_modulo / sub_modulo / neg_modulo
        // Compute expected results without intermediate u128 overflow.
        let (sum, sum_overflow) = a_raw.overflowing_add(b_raw);
        let expected_add = if sum_overflow || sum >= m_raw {
            sum.wrapping_sub(m_raw)
        } else {
            sum
        };
        let expected_sub = if a_raw >= b_raw {
            a_raw - b_raw
        } else {
            m_raw - (b_raw - a_raw)
        };

        let mut s = a.clone();
        s.add_modulo_assign(&b, &modulus);
        assert_eq!(expected_add, compose_u64(s.digits()));

        let mut s = a.clone();
        s.sub_modulo_assign(&b, &modulus);
        assert_eq!(expected_sub, compose_u64(s.digits()));

        let mut c = a.clone();
        c.neg_modulo_assign(&modulus);
        let r = a.add_assign(&c);
        assert!(!r);
        assert!(a.is_zero() || a == modulus);
    }
}
