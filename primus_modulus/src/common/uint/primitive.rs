use primus_gcd::Xgcd;
use primus_integer::UnsignedInteger;
use primus_reduce::ReduceError;

#[inline(always)]
pub fn reduce_once<T: UnsignedInteger>(modulus: T, value: T) -> T {
    value.min(value.wrapping_sub(modulus))
}

#[inline(always)]
pub fn reduce_once_assign<T: UnsignedInteger>(modulus: T, value: &mut T) {
    *value = reduce_once(modulus, *value);
}

#[inline(always)]
pub fn reduce_neg<T: UnsignedInteger>(modulus: T, value: T) -> T {
    if value.is_zero() {
        T::ZERO
    } else {
        modulus - value
    }
}

#[inline(always)]
pub fn reduce_neg_assign<T: UnsignedInteger>(modulus: T, value: &mut T) {
    if !value.is_zero() {
        *value = modulus - *value;
    }
}

#[inline(always)]
pub fn reduce_add<T: UnsignedInteger>(modulus: T, a: T, b: T) -> T {
    let threshold = modulus - b;
    if a >= threshold { a - threshold } else { a + b }
}

#[inline(always)]
pub fn reduce_add_assign<T: UnsignedInteger>(modulus: T, a: &mut T, b: T) {
    let threshold = modulus - b;
    if *a >= threshold {
        *a -= threshold;
    } else {
        *a += b;
    };
}

#[inline(always)]
pub fn reduce_double<T: UnsignedInteger>(modulus: T, value: T) -> T {
    reduce_add(modulus, value, value)
}

#[inline(always)]
pub fn reduce_double_assign<T: UnsignedInteger>(modulus: T, value: &mut T) {
    *value = reduce_double(modulus, *value);
}

#[inline(always)]
pub fn reduce_sub<T: UnsignedInteger>(modulus: T, a: T, b: T) -> T {
    if a >= b { a - b } else { modulus - b + a }
}

#[inline(always)]
pub fn reduce_sub_assign<T: UnsignedInteger>(modulus: T, a: &mut T, b: T) {
    if *a >= b {
        *a -= b;
    } else {
        *a += modulus - b;
    }
}

#[inline(always)]
pub fn reduce_inv<T: UnsignedInteger>(modulus: T, value: T) -> T {
    debug_assert!(modulus > value);

    let (inv, gcd) = Xgcd::gcdinv(value, modulus);
    assert_eq!(gcd, T::ONE, "No {value}^(-1) mod {}", modulus);

    inv
}

#[inline(always)]
pub fn reduce_inv_assign<T: UnsignedInteger>(modulus: T, value: &mut T) {
    *value = reduce_inv(modulus, *value);
}

#[inline(always)]
pub fn try_reduce_inv<T: UnsignedInteger>(modulus: T, value: T) -> Result<T, ReduceError<T>> {
    debug_assert!(modulus > value);

    let (inv, gcd) = Xgcd::gcdinv(value, modulus);

    if gcd.is_one() {
        Ok(inv)
    } else {
        Err(ReduceError::NoInverse { value, modulus })
    }
}
