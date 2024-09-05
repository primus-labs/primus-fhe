use std::ops::ShrAssign;

use num_traits::PrimInt;

use crate::{reduce::*, Bits};

use super::{reduce128, try_inverse, GoldilocksModulus, EPSILON, P};

impl Reduce<GoldilocksModulus> for u64 {
    type Output = Self;

    #[inline]
    fn reduce(self, _: GoldilocksModulus) -> Self::Output {
        if self > P {
            self - P
        } else {
            self
        }
    }
}

impl ReduceAssign<GoldilocksModulus> for u64 {
    #[inline]
    fn reduce_assign(&mut self, _: GoldilocksModulus) {
        if *self > P {
            *self -= P;
        }
    }
}

impl AddReduce<GoldilocksModulus> for u64 {
    type Output = Self;

    #[inline]
    fn add_reduce(self, rhs: Self, _: GoldilocksModulus) -> Self::Output {
        let (sum, over) = self.overflowing_add(rhs);
        let (mut sum, over) = sum.overflowing_add((over as u64) * EPSILON);
        if over {
            sum += EPSILON; // Cannot overflow.
        }
        sum
    }
}

impl AddReduceAssign<GoldilocksModulus> for u64 {
    #[inline]
    fn add_reduce_assign(&mut self, rhs: Self, _: GoldilocksModulus) {
        *self = self.add_reduce(rhs, GoldilocksModulus);
    }
}

impl SubReduce<GoldilocksModulus> for u64 {
    type Output = Self;

    #[inline]
    fn sub_reduce(self, rhs: Self, _: GoldilocksModulus) -> Self::Output {
        let (diff, under) = self.overflowing_sub(rhs);
        let (mut diff, under) = diff.overflowing_sub((under as u64) * EPSILON);
        if under {
            diff -= EPSILON; // Cannot underflow.
        }
        diff
    }
}

impl SubReduceAssign<GoldilocksModulus> for u64 {
    #[inline]
    fn sub_reduce_assign(&mut self, rhs: Self, _: GoldilocksModulus) {
        *self = self.sub_reduce(rhs, GoldilocksModulus);
    }
}

impl NegReduce<GoldilocksModulus> for u64 {
    type Output = Self;

    #[inline]
    fn neg_reduce(self, _: GoldilocksModulus) -> Self::Output {
        if self == 0 {
            0
        } else {
            P - self
        }
    }
}

impl NegReduceAssign<GoldilocksModulus> for u64 {
    #[inline]
    fn neg_reduce_assign(&mut self, _: GoldilocksModulus) {
        *self = self.neg_reduce(GoldilocksModulus);
    }
}

impl MulReduce<GoldilocksModulus> for u64 {
    type Output = Self;

    #[inline]
    fn mul_reduce(self, rhs: Self, _: GoldilocksModulus) -> Self::Output {
        reduce128((self as u128) * (rhs as u128))
    }
}

impl MulReduceAssign<GoldilocksModulus> for u64 {
    #[inline]
    fn mul_reduce_assign(&mut self, rhs: Self, _: GoldilocksModulus) {
        *self = self.mul_reduce(rhs, GoldilocksModulus);
    }
}

impl<E> ExpReduce<GoldilocksModulus, E> for u64
where
    E: PrimInt + ShrAssign<u32> + Bits,
{
    fn exp_reduce(self, mut exp: E, _: GoldilocksModulus) -> Self {
        if exp.is_zero() {
            return 1;
        }

        debug_assert!(self < P);

        let mut power: Self = self;

        let exp_trailing_zeros = exp.trailing_zeros();
        if exp_trailing_zeros > 0 {
            for _ in 0..exp_trailing_zeros {
                power = power.mul_reduce(power, GoldilocksModulus);
            }
            exp >>= exp_trailing_zeros;
        }

        if exp.is_one() {
            return power;
        }

        let mut intermediate: Self = power;
        for _ in 1..(E::BITS - exp.leading_zeros()) {
            exp >>= 1;
            power = power.mul_reduce(power, GoldilocksModulus);
            if !(exp & E::one()).is_zero() {
                intermediate = intermediate.mul_reduce(power, GoldilocksModulus);
            }
        }
        intermediate
    }
}

impl ExpPowOf2Reduce<GoldilocksModulus> for u64 {
    #[inline]
    fn exp_power_of_2_reduce(self, exp_log: u32, _modulus: GoldilocksModulus) -> Self {
        let mut power: Self = self;

        for _ in 0..exp_log {
            power = power.mul_reduce(power, GoldilocksModulus);
        }

        power
    }
}

impl TryInvReduce<GoldilocksModulus> for u64 {
    #[inline]
    fn try_inv_reduce(self, _: GoldilocksModulus) -> Result<Self, crate::AlgebraError> {
        try_inverse(self).ok_or(crate::AlgebraError::NoReduceInverse {
            value: self.to_string(),
            modulus: P.to_string(),
        })
    }
}

impl InvReduce<GoldilocksModulus> for u64 {
    #[inline]
    fn inv_reduce(self, _: GoldilocksModulus) -> Self {
        try_inverse(self).unwrap()
    }
}

impl InvReduceAssign<GoldilocksModulus> for u64 {
    #[inline]
    fn inv_reduce_assign(&mut self, _: GoldilocksModulus) {
        *self = try_inverse(*self).unwrap();
    }
}

impl DivReduce<GoldilocksModulus> for u64 {
    type Output = Self;

    #[inline]
    fn div_reduce(self, rhs: Self, _: GoldilocksModulus) -> Self::Output {
        self.mul_reduce(rhs.inv_reduce(GoldilocksModulus), GoldilocksModulus)
    }
}

impl DivReduceAssign<GoldilocksModulus> for u64 {
    #[inline]
    fn div_reduce_assign(&mut self, rhs: Self, _: GoldilocksModulus) {
        *self = self.mul_reduce(rhs.inv_reduce(GoldilocksModulus), GoldilocksModulus);
    }
}

impl DotProductReduce<GoldilocksModulus> for u64 {
    type Output = Self;

    fn dot_product_reduce(
        a: impl AsRef<[Self]>,
        b: impl AsRef<[Self]>,
        _: GoldilocksModulus,
    ) -> Self::Output {
        let a = a.as_ref();
        let b = b.as_ref();
        debug_assert_eq!(a.len(), b.len());
        a.iter().zip(b).fold(0, |acc: Self, (&x, &y)| {
            x.mul_reduce(y, GoldilocksModulus)
                .add_reduce(acc, GoldilocksModulus)
        })
    }
}
