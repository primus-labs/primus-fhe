use crate::reduce::{
    AddReduce, AddReduceAssign, MulReduce, MulReduceAssign, NegReduce, NegReduceAssign, SubReduce,
    SubReduceAssign,
};

use super::{monty_reduce, BabyBearModulus, P};

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
