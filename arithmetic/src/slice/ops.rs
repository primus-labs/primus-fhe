use num_integer::Integer;

const BITS: u8 = 64;
const HALF_BITS: u8 = BITS / 2;
const HALF: u64 = (1 << HALF_BITS) - 1;

/// Divide a two u64 numerator by a one u64 divisor, returns quotient and remainder:
///
/// Note: the caller must ensure that both the quotient and remainder will fit into a single u64.
/// This is _not_ true for an arbitrary numerator/denominator.
///
/// (This function also matches what the x86 divide instruction does).
#[inline]
fn div_wide(hi: u64, lo: u64, divisor: u64) -> (u64, u64) {
    debug_assert!(hi < divisor);

    let lhs = u128::from(lo) | (u128::from(hi) << BITS);
    let rhs = u128::from(divisor);
    ((lhs / rhs) as u64, (lhs % rhs) as u64)
}

/// For small divisors, we can divide without promoting to `u128` by
/// using half-size pieces of u64, like long-division.
#[inline]
fn div_half(rem: u64, digit: u64, divisor: u64) -> (u64, u64) {
    debug_assert!(rem < divisor && divisor <= HALF);
    let (hi, rem) = ((rem << HALF_BITS) | (digit >> HALF_BITS)).div_rem(&divisor);
    let (lo, rem) = ((rem << HALF_BITS) | (digit & HALF)).div_rem(&divisor);
    ((hi << HALF_BITS) | lo, rem)
}

/// Calculate the quotient and remainder of `slice / value`,
/// output the quotient back into `slice` and return the remainder.
///
/// Treat a [`u64`] slice as a big unsigned integer(in ascending order).
pub fn slice_div_value_inplace(slice: &mut [u64], value: u64) -> u64 {
    assert!(value != 0);

    let mut rem = 0;

    if value <= HALF {
        for d in slice.iter_mut().rev() {
            let (q, r) = div_half(rem, *d, value);
            *d = q;
            rem = r;
        }
    } else {
        for d in slice.iter_mut().rev() {
            let (q, r) = div_wide(rem, *d, value);
            *d = q;
            rem = r;
        }
    }

    rem
}
