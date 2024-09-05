use std::ops::ShrAssign;

use num_traits::PrimInt;

use crate::{reduce::*, Bits};

use super::{from_monty, monty_reduce, try_inverse, BabyBearModulus, P};

impl AddReduce<BabyBearModulus> for u32 {
    type Output = Self;

    #[inline]
    fn add_reduce(self, rhs: Self, _: BabyBearModulus) -> Self::Output {
        let mut sum = self + rhs;
        let (corr_sum, over) = sum.overflowing_sub(P);
        if !over {
            sum = corr_sum;
        }
        sum
    }
}

impl AddReduceAssign<BabyBearModulus> for u32 {
    #[inline]
    fn add_reduce_assign(&mut self, rhs: Self, _: BabyBearModulus) {
        *self = self.add_reduce(rhs, BabyBearModulus);
    }
}

impl SubReduce<BabyBearModulus> for u32 {
    type Output = Self;

    #[inline]
    fn sub_reduce(self, rhs: Self, _: BabyBearModulus) -> Self::Output {
        let (mut diff, over) = self.overflowing_sub(rhs);
        let corr = if over { P } else { 0 };
        diff = diff.wrapping_add(corr);
        diff
    }
}

impl SubReduceAssign<BabyBearModulus> for u32 {
    #[inline]
    fn sub_reduce_assign(&mut self, rhs: Self, _: BabyBearModulus) {
        *self = self.sub_reduce(rhs, BabyBearModulus);
    }
}

impl NegReduce<BabyBearModulus> for u32 {
    type Output = Self;

    #[inline]
    fn neg_reduce(self, _: BabyBearModulus) -> Self::Output {
        0u32.sub_reduce(self, BabyBearModulus)
    }
}

impl NegReduceAssign<BabyBearModulus> for u32 {
    #[inline]
    fn neg_reduce_assign(&mut self, _: BabyBearModulus) {
        *self = self.neg_reduce(BabyBearModulus)
    }
}

impl MulReduce<BabyBearModulus> for u32 {
    type Output = Self;

    #[inline]
    fn mul_reduce(self, rhs: Self, _: BabyBearModulus) -> Self::Output {
        let long_prod = self as u64 * rhs as u64;
        monty_reduce(long_prod)
    }
}

impl MulReduceAssign<BabyBearModulus> for u32 {
    #[inline]
    fn mul_reduce_assign(&mut self, rhs: Self, _: BabyBearModulus) {
        *self = self.mul_reduce(rhs, BabyBearModulus)
    }
}

impl<E> ExpReduce<BabyBearModulus, E> for u32
where
    E: PrimInt + ShrAssign<u32> + Bits,
{
    fn exp_reduce(self, mut exp: E, _: BabyBearModulus) -> Self {
        if exp.is_zero() {
            return 1;
        }

        debug_assert!(self < P);

        let mut power: Self = self;

        let exp_trailing_zeros = exp.trailing_zeros();
        if exp_trailing_zeros > 0 {
            for _ in 0..exp_trailing_zeros {
                power = power.mul_reduce(power, BabyBearModulus);
            }
            exp >>= exp_trailing_zeros;
        }

        if exp.is_one() {
            return power;
        }

        let mut intermediate: Self = power;
        for _ in 1..(E::BITS - exp.leading_zeros()) {
            exp >>= 1;
            power = power.mul_reduce(power, BabyBearModulus);
            if !(exp & E::one()).is_zero() {
                intermediate = intermediate.mul_reduce(power, BabyBearModulus);
            }
        }
        intermediate
    }
}

impl ExpPowOf2Reduce<BabyBearModulus> for u32 {
    #[inline]
    fn exp_power_of_2_reduce(self, exp_log: u32, _modulus: BabyBearModulus) -> Self {
        let mut power: Self = self;

        for _ in 0..exp_log {
            power = power.mul_reduce(power, BabyBearModulus);
        }

        power
    }
}

impl InvReduce<BabyBearModulus> for u32 {
    #[inline]
    fn inv_reduce(self, _: BabyBearModulus) -> Self {
        try_inverse(self).unwrap()
    }
}

impl InvReduceAssign<BabyBearModulus> for u32 {
    #[inline]
    fn inv_reduce_assign(&mut self, _: BabyBearModulus) {
        *self = try_inverse(*self).unwrap();
    }
}

impl TryInvReduce<BabyBearModulus> for u32 {
    #[inline]
    fn try_inv_reduce(self, _: BabyBearModulus) -> Result<Self, crate::AlgebraError> {
        try_inverse(self).ok_or(crate::AlgebraError::NoReduceInverse {
            value: from_monty(self).to_string(),
            modulus: P.to_string(),
        })
    }
}

impl DivReduce<BabyBearModulus> for u32 {
    type Output = Self;

    #[inline]
    fn div_reduce(self, rhs: Self, _: BabyBearModulus) -> Self::Output {
        self.mul_reduce(rhs.inv_reduce(BabyBearModulus), BabyBearModulus)
    }
}

impl DivReduceAssign<BabyBearModulus> for u32 {
    #[inline]
    fn div_reduce_assign(&mut self, rhs: Self, _: BabyBearModulus) {
        *self = self.mul_reduce(rhs.inv_reduce(BabyBearModulus), BabyBearModulus);
    }
}

impl DotProductReduce<BabyBearModulus> for u32 {
    type Output = Self;

    fn dot_product_reduce(
        a: impl AsRef<[Self]>,
        b: impl AsRef<[Self]>,
        _: BabyBearModulus,
    ) -> Self::Output {
        let a = a.as_ref();
        let b = b.as_ref();
        debug_assert_eq!(a.len(), b.len());
        a.iter().zip(b).fold(0, |acc: Self, (&x, &y)| {
            x.mul_reduce(y, BabyBearModulus)
                .add_reduce(acc, BabyBearModulus)
        })
    }
}
