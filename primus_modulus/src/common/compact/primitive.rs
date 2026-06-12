use primus_integer::UnsignedInteger;

pub use crate::common::uint::{
    reduce_inv, reduce_inv_assign, reduce_neg, reduce_neg_assign, reduce_once, reduce_once_assign,
    try_reduce_inv,
};

#[inline(always)]
pub fn reduce_add<T: UnsignedInteger>(modulus: T, a: T, b: T) -> T {
    let sum = a + b;
    sum.min(sum.wrapping_sub(modulus))
}

#[inline(always)]
pub fn reduce_add_assign<T: UnsignedInteger>(modulus: T, a: &mut T, b: T) {
    *a = reduce_add(modulus, *a, b);
}

#[inline(always)]
pub fn reduce_double<T: UnsignedInteger>(modulus: T, value: T) -> T {
    let double = value.wrapping_shl(1);
    double.min(double.wrapping_sub(modulus))
}

#[inline(always)]
pub fn reduce_double_assign<T: UnsignedInteger>(modulus: T, value: &mut T) {
    *value = reduce_double(modulus, *value);
}

#[inline(always)]
pub fn reduce_sub<T: UnsignedInteger>(modulus: T, a: T, b: T) -> T {
    let diff = a.wrapping_sub(b);
    diff.min(diff.wrapping_add(modulus))
}

#[inline(always)]
pub fn reduce_sub_assign<T: UnsignedInteger>(modulus: T, a: &mut T, b: T) {
    let diff = a.wrapping_sub(b);
    *a = diff.min(diff.wrapping_add(modulus));
}

#[inline(always)]
pub fn lazy_reduce_sub<T: UnsignedInteger>(modulus: T, a: T, b: T) -> T {
    a + (modulus - b)
}

#[inline(always)]
pub fn lazy_reduce_sub_assign<T: UnsignedInteger>(modulus: T, a: &mut T, b: T) {
    *a += modulus - b;
}

#[inline(always)]
pub fn lazy_reduce_neg<T: UnsignedInteger>(modulus: T, value: T) -> T {
    modulus - value
}

#[inline(always)]
pub fn lazy_reduce_neg_assign<T: UnsignedInteger>(modulus: T, value: &mut T) {
    *value = modulus - *value;
}
