use primus_integer::UnsignedInteger;
use primus_reduce::{ReduceError, prelude::*};

use crate::common::compact;

use super::BarrettModulus;

impl<T: UnsignedInteger> LazyReduce<T> for BarrettModulus<T> {
    type Output = T;

    /// Calculates `value (mod 2*modulus)`.
    #[inline(always)]
    fn lazy_reduce(self, value: T) -> T {
        // Step 1.
        //              ratio[1]  ratio[0]
        //         *               value
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //            +-------------------+
        //            |  tmp1   |         |    <-- value * ratio[0]
        //            +-------------------+
        //   +------------------+
        //   |      tmp2        |              <-- value * ratio[1]
        //   +------------------+
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //   +--------+
        //   |   q₃   |
        //   +--------+
        let tmp = value.widening_mul_hw(self.ratio[0]); // tmp1
        let q = value.carrying_mul_hw(self.ratio[1], tmp); // q₃

        // Step 2.
        value.wrapping_sub(q.wrapping_mul(self.value)) // r = r₁ - r₂
    }
}

impl<T: UnsignedInteger> LazyReduce<[T; 2]> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn lazy_reduce(self, value: [T; 2]) -> Self::Output {
        self.lazy_reduce_wide(value[0], value[1])
    }
}

impl<T: UnsignedInteger> LazyReduce<(T, T)> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn lazy_reduce(self, value: (T, T)) -> Self::Output {
        self.lazy_reduce_wide(value.0, value.1)
    }
}

impl<T: UnsignedInteger> LazyReduce<&[T]> for BarrettModulus<T> {
    type Output = T;

    /// Calculates `value (mod 2*modulus)` when value's length > 0.
    #[inline]
    fn lazy_reduce(self, value: &[T]) -> Self::Output {
        match value {
            &[] => unreachable!(),
            &[v] => {
                if v < self.value << 1u32 {
                    v
                } else {
                    self.lazy_reduce(v)
                }
            }
            [other @ .., last] => other
                .iter()
                .rfold(*last, |acc, &x| self.lazy_reduce_wide(x, acc)),
        }
    }
}

impl<T: UnsignedInteger> LazyReduceAssign<T> for BarrettModulus<T> {
    /// Calculates `value (mod 2*modulus)`.
    #[inline]
    fn lazy_reduce_assign(self, value: &mut T) {
        *value = self.lazy_reduce(*value);
    }
}

impl<T: UnsignedInteger> LazyReduceMul<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn lazy_reduce_mul(self, a: T, b: T) -> Self::Output {
        self.lazy_reduce(a.widening_mul(b))
    }
}

impl<T: UnsignedInteger> LazyReduceMulAssign<T> for BarrettModulus<T> {
    #[inline]
    fn lazy_reduce_mul_assign(self, a: &mut T, b: T) {
        *a = self.lazy_reduce(a.widening_mul(b));
    }
}

impl<T: UnsignedInteger> LazyReduceMulAdd<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn lazy_reduce_mul_add(self, a: T, b: T, c: T) -> Self::Output {
        self.lazy_reduce(a.carrying_mul(b, c))
    }
}

impl<T: UnsignedInteger> LazyReduceMulAddAssign<T> for BarrettModulus<T> {
    #[inline]
    fn lazy_reduce_mul_add_assign(self, a: &mut T, b: T, c: T) {
        *a = self.lazy_reduce(a.carrying_mul(b, c));
    }
}

impl<T: UnsignedInteger> LazyReduceSub<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn lazy_reduce_sub(self, a: T, b: T) -> Self::Output {
        compact::lazy_reduce_sub(self.value, a, b)
    }
}

impl<T: UnsignedInteger> LazyReduceSubAssign<T> for BarrettModulus<T> {
    #[inline]
    fn lazy_reduce_sub_assign(self, a: &mut T, b: T) {
        compact::lazy_reduce_sub_assign(self.value, a, b);
    }
}

impl<T: UnsignedInteger> LazyReduceNeg<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn lazy_reduce_neg(self, value: T) -> Self::Output {
        compact::lazy_reduce_neg(self.value, value)
    }
}

impl<T: UnsignedInteger> LazyReduceNegAssign<T> for BarrettModulus<T> {
    #[inline]
    fn lazy_reduce_neg_assign(self, value: &mut T) {
        compact::lazy_reduce_neg_assign(self.value, value);
    }
}

impl<T: UnsignedInteger> Reduce<T> for BarrettModulus<T> {
    type Output = T;

    /// Calculates `value (mod modulus)`.
    #[inline(always)]
    fn reduce(self, value: T) -> Self::Output {
        compact::reduce_once(self.value, self.lazy_reduce(value))
    }
}

impl<T: UnsignedInteger> Reduce<[T; 2]> for BarrettModulus<T> {
    type Output = T;

    /// Calculates `value (mod modulus)`.
    #[inline(always)]
    fn reduce(self, value: [T; 2]) -> Self::Output {
        compact::reduce_once(self.value, self.lazy_reduce(value))
    }
}

impl<T: UnsignedInteger> Reduce<(T, T)> for BarrettModulus<T> {
    type Output = T;

    /// Calculates `value (mod modulus)`.
    #[inline(always)]
    fn reduce(self, value: (T, T)) -> Self::Output {
        compact::reduce_once(self.value, self.lazy_reduce(value))
    }
}

impl<T: UnsignedInteger> Reduce<&[T]> for BarrettModulus<T> {
    type Output = T;

    /// Calculates `value (mod modulus)` when value's length > 0.
    #[inline(always)]
    fn reduce(self, value: &[T]) -> Self::Output {
        compact::reduce_once(self.value, self.lazy_reduce(value))
    }
}

impl<T: UnsignedInteger> ReduceAssign<T> for BarrettModulus<T> {
    /// Calculates `value (mod modulus)`.
    #[inline]
    fn reduce_assign(self, value: &mut T) {
        *value = self.reduce(*value);
    }
}

impl<T: UnsignedInteger> ReduceOnce<T> for BarrettModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_once(self, value: T) -> Self::Output {
        compact::reduce_once(self.value, value)
    }
}

impl<T: UnsignedInteger> ReduceOnceAssign<T> for BarrettModulus<T> {
    #[inline(always)]
    fn reduce_once_assign(self, value: &mut T) {
        compact::reduce_once_assign(self.value, value);
    }
}

impl<T: UnsignedInteger> ReduceAdd<T> for BarrettModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_add(self, a: T, b: T) -> Self::Output {
        compact::reduce_add(self.value, a, b)
    }
}

impl<T: UnsignedInteger> ReduceAddAssign<T> for BarrettModulus<T> {
    #[inline(always)]
    fn reduce_add_assign(self, a: &mut T, b: T) {
        compact::reduce_add_assign(self.value, a, b);
    }
}

impl<T: UnsignedInteger> ReduceDouble<T> for BarrettModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_double(self, value: T) -> Self::Output {
        compact::reduce_double(self.value, value)
    }
}

impl<T: UnsignedInteger> ReduceDoubleAssign<T> for BarrettModulus<T> {
    #[inline(always)]
    fn reduce_double_assign(self, value: &mut T) {
        compact::reduce_double_assign(self.value, value);
    }
}

impl<T: UnsignedInteger> ReduceSub<T> for BarrettModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_sub(self, a: T, b: T) -> Self::Output {
        compact::reduce_sub(self.value, a, b)
    }
}

impl<T: UnsignedInteger> ReduceSubAssign<T> for BarrettModulus<T> {
    #[inline(always)]
    fn reduce_sub_assign(self, a: &mut T, b: T) {
        compact::reduce_sub_assign(self.value, a, b);
    }
}

impl<T: UnsignedInteger> ReduceNeg<T> for BarrettModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_neg(self, value: T) -> Self::Output {
        compact::reduce_neg(self.value, value)
    }
}

impl<T: UnsignedInteger> ReduceNegAssign<T> for BarrettModulus<T> {
    #[inline(always)]
    fn reduce_neg_assign(self, value: &mut T) {
        compact::reduce_neg_assign(self.value, value);
    }
}

impl<T: UnsignedInteger> ReduceMul<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn reduce_mul(self, a: T, b: T) -> Self::Output {
        self.reduce(a.widening_mul(b))
    }
}

impl<T: UnsignedInteger> ReduceMulAssign<T> for BarrettModulus<T> {
    #[inline]
    fn reduce_mul_assign(self, a: &mut T, b: T) {
        *a = self.reduce(a.widening_mul(b));
    }
}

impl<T: UnsignedInteger> ReduceSquare<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn reduce_square(self, value: T) -> Self::Output {
        self.reduce(value.widening_mul(value))
    }
}

impl<T: UnsignedInteger> ReduceSquareAssign<T> for BarrettModulus<T> {
    #[inline]
    fn reduce_square_assign(self, value: &mut T) {
        *value = self.reduce(value.widening_mul(*value));
    }
}

impl<T: UnsignedInteger> ReduceMulAdd<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn reduce_mul_add(self, a: T, b: T, c: T) -> Self::Output {
        self.reduce(a.carrying_mul(b, c))
    }
}

impl<T: UnsignedInteger> ReduceMulAddAssign<T> for BarrettModulus<T> {
    #[inline]
    fn reduce_mul_add_assign(self, a: &mut T, b: T, c: T) {
        *a = self.reduce(a.carrying_mul(b, c));
    }
}

impl<T: UnsignedInteger> TryReduceInv<T> for BarrettModulus<T> {
    type Output = T;

    #[inline(always)]
    fn try_reduce_inv(self, value: T) -> Result<T, ReduceError<T>> {
        compact::try_reduce_inv(self.value, value)
    }
}

impl<T: UnsignedInteger> ReduceInv<T> for BarrettModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_inv(self, value: T) -> Self::Output {
        compact::reduce_inv(self.value, value)
    }
}

impl<T: UnsignedInteger> ReduceInvAssign<T> for BarrettModulus<T> {
    #[inline(always)]
    fn reduce_inv_assign(self, value: &mut T) {
        compact::reduce_inv_assign(self.value, value);
    }
}

impl<T: UnsignedInteger> ReduceDiv<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn reduce_div(self, a: T, b: T) -> Self::Output {
        self.reduce_mul(a, self.reduce_inv(b))
    }
}

impl<T: UnsignedInteger> ReduceDivAssign<T> for BarrettModulus<T> {
    #[inline]
    fn reduce_div_assign(self, a: &mut T, b: T) {
        self.reduce_mul_assign(a, self.reduce_inv(b));
    }
}

impl<T> ReduceExp<T> for BarrettModulus<T>
where
    T: UnsignedInteger,
{
    #[inline]
    fn reduce_exp<E: UnsignedInteger>(self, base: T, mut exp: E) -> T {
        if exp.is_zero() {
            return T::ONE;
        }

        if base.is_zero() {
            return T::ZERO;
        }

        debug_assert!(base < self.value);

        let mut power: T = base;

        let exp_trailing_zeros = exp.trailing_zeros();
        if exp_trailing_zeros > 0 {
            for _ in 0..exp_trailing_zeros {
                self.reduce_square_assign(&mut power);
            }
            exp >>= exp_trailing_zeros;
        }

        if exp.is_one() {
            return power;
        }

        let mut intermediate: T = power;
        for _ in 1..(E::BITS - exp.leading_zeros()) {
            exp >>= 1;
            self.reduce_square_assign(&mut power);
            if !(exp & E::ONE).is_zero() {
                self.reduce_mul_assign(&mut intermediate, power);
            }
        }
        intermediate
    }
}

impl<T: UnsignedInteger> ReduceExpPowOf2<T> for BarrettModulus<T> {
    #[inline]
    fn reduce_exp_power_of_2(self, base: T, exp_log: u32) -> T {
        if base.is_zero() {
            return T::ZERO;
        }

        let mut power = base;

        for _ in 0..exp_log {
            self.reduce_square_assign(&mut power);
        }

        power
    }
}
