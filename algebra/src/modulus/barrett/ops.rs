use crate::integer::{AsInto, UnsignedInteger};
use crate::numeric::Numeric;
use crate::reduce::*;

use super::BarrettModulus;

impl<T: Numeric> LazyReduce<T> for BarrettModulus<T> {
    type Output = T;

    /// Calculates `value (mod 2*modulus)`.
    ///
    #[doc = include_str!("barrett_reduction.md")]
    #[inline]
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

impl<T: Numeric> LazyReduce<[T; 2]> for BarrettModulus<T> {
    type Output = T;

    /// Calculates `value (mod 2*modulus)`.
    ///
    #[doc = include_str!("barrett_reduction.md")]
    #[inline]
    fn lazy_reduce(self, value: [T; 2]) -> Self::Output {
        // Step 1.
        //                        ratio[1]  ratio[0]
        //                   *    value[1]  value[0]
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //                      +-------------------+
        //                      |         a         |    <-- value[0] * ratio[0]
        //                      +-------------------+
        //             +------------------+
        //             |        b         |              <-- value[0] * ratio[1]
        //             +------------------+
        //             +------------------+
        //             |        c         |              <-- value[1] * ratio[0]
        //             +------------------+
        //   +------------------+
        //   |        d         |                        <-- value[1] * ratio[1]
        //   +------------------+
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //             +--------+
        //             |   q₃   |
        //             +--------+
        let ah = value[0].widening_mul_hw(self.ratio[0]);

        let b = value[0].carrying_mul(self.ratio[1], ah);
        let c = value[1].widening_mul(self.ratio[0]);

        let d = value[1].wrapping_mul(self.ratio[1]);

        let bch = b.1 + c.1 + b.0.overflowing_add(c.0).1.as_into();

        let q = d.wrapping_add(bch);

        // Step 2.
        value[0].wrapping_sub(q.wrapping_mul(self.value))
    }
}

impl<T: Numeric> LazyReduce<(T, T)> for BarrettModulus<T> {
    type Output = T;

    /// Calculates `value (mod 2*modulus)`.
    ///
    #[doc = include_str!("barrett_reduction.md")]
    #[inline]
    fn lazy_reduce(self, value: (T, T)) -> Self::Output {
        // Step 1.
        //                        ratio[1]  ratio[0]
        //                   *    value.1   value.0
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //                      +-------------------+
        //                      |         a         |    <-- value.0 * ratio[0]
        //                      +-------------------+
        //             +------------------+
        //             |        b         |              <-- value.0 * ratio[1]
        //             +------------------+
        //             +------------------+
        //             |        c         |              <-- value.1 * ratio[0]
        //             +------------------+
        //   +------------------+
        //   |        d         |                        <-- value.1 * ratio[1]
        //   +------------------+
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //             +--------+
        //             |   q₃   |
        //             +--------+

        let ah = value.0.widening_mul_hw(self.ratio[0]);

        let b = value.0.carrying_mul(self.ratio[1], ah);
        let c = value.1.widening_mul(self.ratio[0]);

        let d = value.1.wrapping_mul(self.ratio[1]);

        let bch = b.1 + c.1 + b.0.overflowing_add(c.0).1.as_into();

        let q = d.wrapping_add(bch);

        // Step 2.
        value.0.wrapping_sub(q.wrapping_mul(self.value))
    }
}

impl<T: Numeric> LazyReduce<&[T]> for BarrettModulus<T> {
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
                .rfold(*last, |acc, &x| self.lazy_reduce([x, acc])),
        }
    }
}

impl<T: Numeric> LazyReduceAssign<T> for BarrettModulus<T> {
    /// Calculates `value (mod 2*modulus)`.
    ///
    #[doc = include_str!("barrett_reduction.md")]
    #[inline]
    fn lazy_reduce_assign(self, value: &mut T) {
        *value = self.lazy_reduce(*value);
    }
}

impl<T: Numeric> LazyReduceMul<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn lazy_reduce_mul(self, a: T, b: T) -> Self::Output {
        self.lazy_reduce(a.widening_mul(b))
    }
}

impl<T: Numeric> LazyReduceMulAssign<T> for BarrettModulus<T> {
    #[inline]
    fn lazy_reduce_mul_assign(self, a: &mut T, b: T) {
        *a = self.lazy_reduce(a.widening_mul(b));
    }
}

impl<T: Numeric> LazyReduceMulAdd<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn lazy_reduce_mul_add(self, a: T, b: T, c: T) -> Self::Output {
        self.lazy_reduce(a.carrying_mul(b, c))
    }
}

impl<T: Numeric> LazyReduceMulAddAssign<T> for BarrettModulus<T> {
    #[inline]
    fn lazy_reduce_mul_add_assign(self, a: &mut T, b: T, c: T) {
        *a = self.lazy_reduce(a.carrying_mul(b, c));
    }
}

impl<T: Numeric> Reduce<T> for BarrettModulus<T> {
    type Output = T;

    /// Calculates `value (mod modulus)`.
    ///
    #[doc = include_str!("barrett_reduction.md")]
    #[inline(always)]
    fn reduce(self, value: T) -> Self::Output {
        self.value.reduce_once(self.lazy_reduce(value))
    }
}

impl<T: Numeric> Reduce<[T; 2]> for BarrettModulus<T> {
    type Output = T;

    /// Calculates `value (mod modulus)`.
    ///
    #[doc = include_str!("barrett_reduction.md")]
    #[inline(always)]
    fn reduce(self, value: [T; 2]) -> Self::Output {
        self.value.reduce_once(self.lazy_reduce(value))
    }
}

impl<T: Numeric> Reduce<(T, T)> for BarrettModulus<T> {
    type Output = T;

    /// Calculates `value (mod modulus)`.
    ///
    #[doc = include_str!("barrett_reduction.md")]
    #[inline(always)]
    fn reduce(self, value: (T, T)) -> Self::Output {
        self.value.reduce_once(self.lazy_reduce(value))
    }
}

impl<T: Numeric> Reduce<&[T]> for BarrettModulus<T> {
    type Output = T;

    /// Calculates `value (mod modulus)` when value's length > 0.
    #[inline(always)]
    fn reduce(self, value: &[T]) -> Self::Output {
        self.value.reduce_once(self.lazy_reduce(value))
    }
}

impl<T: Numeric> ReduceAssign<T> for BarrettModulus<T> {
    /// Calculates `value (mod modulus)`.
    ///
    #[doc = include_str!("barrett_reduction.md")]
    #[inline]
    fn reduce_assign(self, value: &mut T) {
        *value = self.reduce(*value);
    }
}

impl<T: Numeric> ReduceOnce<T> for BarrettModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_once(self, value: T) -> Self::Output {
        self.value.reduce_once(value)
    }
}

impl<T: Numeric> ReduceOnceAssign<T> for BarrettModulus<T> {
    #[inline(always)]
    fn reduce_once_assign(self, value: &mut T) {
        self.value.reduce_once_assign(value);
    }
}

impl<T: Numeric> ReduceAdd<T> for BarrettModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_add(self, a: T, b: T) -> Self::Output {
        self.value.reduce_add(a, b)
    }
}

impl<T: Numeric> ReduceAddAssign<T> for BarrettModulus<T> {
    #[inline(always)]
    fn reduce_add_assign(self, a: &mut T, b: T) {
        self.value.reduce_add_assign(a, b);
    }
}

impl<T: Numeric> ReduceDouble<T> for BarrettModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_double(self, value: T) -> Self::Output {
        self.value.reduce_double(value)
    }
}

impl<T: Numeric> ReduceDoubleAssign<T> for BarrettModulus<T> {
    #[inline(always)]
    fn reduce_double_assign(self, value: &mut T) {
        self.value.reduce_double_assign(value);
    }
}

impl<T: Numeric> ReduceSub<T> for BarrettModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_sub(self, a: T, b: T) -> Self::Output {
        self.value.reduce_sub(a, b)
    }
}

impl<T: Numeric> ReduceSubAssign<T> for BarrettModulus<T> {
    #[inline(always)]
    fn reduce_sub_assign(self, a: &mut T, b: T) {
        self.value.reduce_sub_assign(a, b);
    }
}

impl<T: Numeric> ReduceNeg<T> for BarrettModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_neg(self, value: T) -> Self::Output {
        self.value.reduce_neg(value)
    }
}

impl<T: Numeric> ReduceNegAssign<T> for BarrettModulus<T> {
    #[inline(always)]
    fn reduce_neg_assign(self, value: &mut T) {
        self.value.reduce_neg_assign(value);
    }
}

impl<T: Numeric> ReduceMul<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn reduce_mul(self, a: T, b: T) -> Self::Output {
        self.reduce(a.widening_mul(b))
    }
}

impl<T: Numeric> ReduceMulAssign<T> for BarrettModulus<T> {
    #[inline]
    fn reduce_mul_assign(self, a: &mut T, b: T) {
        *a = self.reduce(a.widening_mul(b));
    }
}

impl<T: Numeric> ReduceSquare<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn reduce_square(self, value: T) -> Self::Output {
        self.reduce(value.widening_mul(value))
    }
}

impl<T: Numeric> ReduceSquareAssign<T> for BarrettModulus<T> {
    #[inline]
    fn reduce_square_assign(self, value: &mut T) {
        *value = self.reduce(value.widening_mul(*value));
    }
}

impl<T: Numeric> ReduceMulAdd<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn reduce_mul_add(self, a: T, b: T, c: T) -> Self::Output {
        self.reduce(a.carrying_mul(b, c))
    }
}

impl<T: Numeric> ReduceMulAddAssign<T> for BarrettModulus<T> {
    #[inline]
    fn reduce_mul_add_assign(self, a: &mut T, b: T, c: T) {
        *a = self.reduce(a.carrying_mul(b, c));
    }
}

impl<T: Numeric> ReduceInv<T> for BarrettModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_inv(self, value: T) -> Self::Output {
        self.value.reduce_inv(value)
    }
}

impl<T: Numeric> ReduceInvAssign<T> for BarrettModulus<T> {
    #[inline(always)]
    fn reduce_inv_assign(self, value: &mut T) {
        self.value.reduce_inv_assign(value);
    }
}

impl<T: Numeric> ReduceDiv<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn reduce_div(self, a: T, b: T) -> Self::Output {
        self.reduce_mul(a, self.reduce_inv(b))
    }
}

impl<T: Numeric> ReduceDivAssign<T> for BarrettModulus<T> {
    #[inline]
    fn reduce_div_assign(self, a: &mut T, b: T) {
        self.reduce_mul_assign(a, self.reduce_inv(b));
    }
}

impl<T> ReduceExp<T> for BarrettModulus<T>
where
    T: Numeric,
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

impl<T: Numeric> ReduceExpPowOf2<T> for BarrettModulus<T> {
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

impl<T: Numeric> ReduceDotProduct<T> for BarrettModulus<T> {
    type Output = T;

    #[inline]
    fn reduce_dot_product(self, a: impl AsRef<[T]>, b: impl AsRef<[T]>) -> Self::Output {
        /// `c += a * b`
        fn multiply_add<T: Numeric>(c: &mut [T; 2], a: T, b: T) {
            let (lw, hw) = a.widening_mul(b);
            let carry;
            (c[0], carry) = c[0].overflowing_add(lw);
            (c[1], _) = c[1].carrying_add(hw, carry);
        }

        let a = a.as_ref();
        let b = b.as_ref();

        debug_assert_eq!(a.len(), b.len());

        let mut a_iter = a.chunks_exact(16);
        let mut b_iter = b.chunks_exact(16);

        let inter = (&mut a_iter)
            .zip(&mut b_iter)
            .map(|(a_s, b_s)| {
                let mut c: [T; 2] = [T::ZERO, T::ZERO];
                for (&a, &b) in a_s.iter().zip(b_s) {
                    multiply_add(&mut c, a, b);
                }
                self.reduce(c)
            })
            .fold(T::ZERO, |acc: T, b| self.value.reduce_add(acc, b));

        let mut c: [T; 2] = [T::ZERO, T::ZERO];
        a_iter
            .remainder()
            .iter()
            .zip(b_iter.remainder())
            .for_each(|(&a, &b)| {
                multiply_add(&mut c, a, b);
            });
        self.reduce_add(self.reduce(c), inter)
    }

    #[inline]
    fn reduce_dot_product2(
        self,
        a: impl IntoIterator<Item = T>,
        b: impl IntoIterator<Item = T>,
    ) -> Self::Output {
        /// `c += a * b`
        fn multiply_add<T: Numeric>(c: &mut [T; 2], a: T, b: T) {
            let (lw, hw) = a.widening_mul(b);
            let carry;
            (c[0], carry) = c[0].overflowing_add(lw);
            (c[1], _) = c[1].carrying_add(hw, carry);
        }

        let mut a_iter = a.into_iter();
        let mut b_iter = b.into_iter();

        let mut a_temp_array = [T::ZERO; 16];
        let mut b_temp_array = [T::ZERO; 16];

        let mut i = 0;
        let mut result = T::ZERO;

        while let (Some(a_next), Some(b_next)) = (a_iter.next(), b_iter.next()) {
            if i < 16 {
                a_temp_array[i] = a_next;
                b_temp_array[i] = b_next;
                i += 1;
            } else {
                let mut c: [T; 2] = [T::ZERO, T::ZERO];
                for (&a, b) in a_temp_array.iter().zip(b_temp_array) {
                    multiply_add(&mut c, a, b);
                }
                self.reduce_add_assign(&mut result, self.reduce(c));

                a_temp_array.fill(T::ZERO);
                b_temp_array.fill(T::ZERO);
                a_temp_array[0] = a_next;
                b_temp_array[0] = b_next;
                i = 1;
            }
        }

        let mut c: [T; 2] = [T::ZERO, T::ZERO];
        for (&a, &b) in a_temp_array[..i].iter().zip(b_temp_array[..i].iter()) {
            multiply_add(&mut c, a, b);
        }
        self.reduce_add_assign(&mut result, self.reduce(c));

        result
    }
}

#[cfg(test)]
mod tests {
    use num_traits::{One, Zero};
    use rand::prelude::*;

    use super::*;

    type T = u32;
    type W = u64;

    #[test]
    fn test_pow_mod_simple() {
        const P: T = 1000000513;
        let modulus = BarrettModulus::<T>::new(P);

        let distr = rand::distributions::Uniform::new_inclusive(0, P - 1);
        let mut rng = thread_rng();

        for _ in 0..5 {
            let base = rng.sample(distr);
            let exp = random();

            assert_eq!(simple_pow(base, exp, P), modulus.reduce_exp(base, exp));
        }
    }

    fn simple_pow(base: T, mut exp: u32, modulus: T) -> T {
        if exp.is_zero() {
            return 1;
        }

        debug_assert!(base < modulus);

        if exp.is_one() {
            return base;
        }

        let mut power: T = base;
        let mut intermediate: T = 1;
        loop {
            if exp & 1 != 0 {
                intermediate = ((intermediate as W * power as W) % modulus as W) as T;
            }
            exp >>= 1;
            if exp.is_zero() {
                break;
            }
            power = ((power as W * power as W) % modulus as W) as T;
        }
        intermediate
    }

    #[test]
    fn test_inverse() {
        type Num = u64;
        let mut rng = thread_rng();

        let mut m = rng.gen_range(2..=(Num::MAX >> 2));

        if m & 1 == 0 {
            m |= 1;
        }

        let modulus = BarrettModulus::<Num>::new(m);

        let value: Num = rng.gen_range(2..modulus.value());
        if let Ok(inv) = modulus.value.try_reduce_inv(value) {
            assert_eq!(
                modulus.reduce_mul(inv, value),
                1,
                "\nval:{value}\ninv:{inv}\nmod:{}",
                modulus.value()
            );
        }
    }
}
