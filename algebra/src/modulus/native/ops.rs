use crate::{integer::UnsignedInteger, reduce::*};

use super::NativeModulus;

impl<T: UnsignedInteger> Reduce<T> for NativeModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce(self, value: T) -> Self::Output {
        value
    }
}

impl<T: UnsignedInteger> ReduceAssign<T> for NativeModulus<T> {
    #[inline(always)]
    fn reduce_assign(self, _value: &mut T) {}
}

impl<T: UnsignedInteger> ReduceOnce<T> for NativeModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_once(self, value: T) -> Self::Output {
        value
    }
}

impl<T: UnsignedInteger> ReduceOnceAssign<T> for NativeModulus<T> {
    #[inline(always)]
    fn reduce_once_assign(self, _value: &mut T) {}
}

impl<T: UnsignedInteger> ReduceAdd<T> for NativeModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_add(self, a: T, b: T) -> Self::Output {
        a.wrapping_add(b)
    }
}

impl<T: UnsignedInteger> ReduceAddAssign<T> for NativeModulus<T> {
    #[inline(always)]
    fn reduce_add_assign(self, a: &mut T, b: T) {
        *a = a.wrapping_add(b);
    }
}

impl<T: UnsignedInteger> ReduceDouble<T> for NativeModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_double(self, value: T) -> Self::Output {
        value.wrapping_shl(1)
    }
}

impl<T: UnsignedInteger> ReduceDoubleAssign<T> for NativeModulus<T> {
    #[inline(always)]
    fn reduce_double_assign(self, value: &mut T) {
        *value = value.wrapping_shl(1);
    }
}

impl<T: UnsignedInteger> ReduceSub<T> for NativeModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_sub(self, a: T, b: T) -> Self::Output {
        a.wrapping_sub(b)
    }
}

impl<T: UnsignedInteger> ReduceSubAssign<T> for NativeModulus<T> {
    #[inline(always)]
    fn reduce_sub_assign(self, a: &mut T, b: T) {
        *a = a.wrapping_sub(b);
    }
}

impl<T: UnsignedInteger> ReduceNeg<T> for NativeModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_neg(self, value: T) -> Self::Output {
        value.wrapping_neg()
    }
}

impl<T: UnsignedInteger> ReduceNegAssign<T> for NativeModulus<T> {
    #[inline(always)]
    fn reduce_neg_assign(self, value: &mut T) {
        *value = value.wrapping_neg();
    }
}

impl<T: UnsignedInteger> ReduceMul<T> for NativeModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_mul(self, a: T, b: T) -> Self::Output {
        a.wrapping_mul(b)
    }
}

impl<T: UnsignedInteger> ReduceMulAssign<T> for NativeModulus<T> {
    #[inline(always)]
    fn reduce_mul_assign(self, a: &mut T, b: T) {
        *a = a.wrapping_mul(b);
    }
}

impl<T: UnsignedInteger> ReduceSquare<T> for NativeModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_square(self, value: T) -> Self::Output {
        value.wrapping_mul(value)
    }
}

impl<T: UnsignedInteger> ReduceSquareAssign<T> for NativeModulus<T> {
    #[inline(always)]
    fn reduce_square_assign(self, value: &mut T) {
        *value = value.wrapping_mul(*value);
    }
}

impl<T: UnsignedInteger> ReduceMulAdd<T> for NativeModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_mul_add(self, a: T, b: T, c: T) -> Self::Output {
        a.wrapping_mul(b).wrapping_add(c)
    }
}

impl<T: UnsignedInteger> ReduceMulAddAssign<T> for NativeModulus<T> {
    #[inline(always)]
    fn reduce_mul_add_assign(self, a: &mut T, b: T, c: T) {
        *a = a.wrapping_mul(b).wrapping_add(c);
    }
}

impl<T> ReduceExp<T> for NativeModulus<T>
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

        let mut intermediate = power;
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

impl<T: UnsignedInteger> ReduceExpPowOf2<T> for NativeModulus<T> {
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

impl<T: UnsignedInteger> ReduceDotProduct<T> for NativeModulus<T> {
    type Output = T;

    #[inline]
    fn reduce_dot_product(self, a: impl AsRef<[T]>, b: impl AsRef<[T]>) -> Self::Output {
        let a = a.as_ref();
        let b = b.as_ref();

        debug_assert_eq!(a.len(), b.len());

        a.iter()
            .zip(b)
            .fold(T::ZERO, |acc, (&x, &y)| x.wrapping_mul(y).wrapping_add(acc))
    }

    #[inline]
    fn reduce_dot_product2(
        self,
        a: impl IntoIterator<Item = T>,
        b: impl IntoIterator<Item = T>,
    ) -> Self::Output {
        std::iter::zip(a, b).fold(T::ZERO, |acc, (x, y)| x.wrapping_mul(y).wrapping_add(acc))
    }
}
