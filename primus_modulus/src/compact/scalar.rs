use primus_integer::UnsignedInteger;
use primus_reduce::{ReduceError, prelude::*};

use crate::common::compact;

use super::CompactModulus;

impl<T: UnsignedInteger> ReduceOnce<T> for CompactModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_once(self, value: T) -> Self::Output {
        compact::reduce_once(self.0, value)
    }
}

impl<T: UnsignedInteger> ReduceOnceAssign<T> for CompactModulus<T> {
    #[inline(always)]
    fn reduce_once_assign(self, value: &mut T) {
        compact::reduce_once_assign(self.0, value);
    }
}

impl<T: UnsignedInteger> ReduceAdd<T> for CompactModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_add(self, a: T, b: T) -> Self::Output {
        compact::reduce_add(self.0, a, b)
    }
}

impl<T: UnsignedInteger> ReduceAddAssign<T> for CompactModulus<T> {
    #[inline(always)]
    fn reduce_add_assign(self, a: &mut T, b: T) {
        compact::reduce_add_assign(self.0, a, b);
    }
}

impl<T: UnsignedInteger> ReduceDouble<T> for CompactModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_double(self, value: T) -> Self::Output {
        compact::reduce_double(self.0, value)
    }
}

impl<T: UnsignedInteger> ReduceDoubleAssign<T> for CompactModulus<T> {
    #[inline(always)]
    fn reduce_double_assign(self, value: &mut T) {
        compact::reduce_double_assign(self.0, value);
    }
}

impl<T: UnsignedInteger> ReduceSub<T> for CompactModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_sub(self, a: T, b: T) -> Self::Output {
        compact::reduce_sub(self.0, a, b)
    }
}

impl<T: UnsignedInteger> ReduceSubAssign<T> for CompactModulus<T> {
    #[inline(always)]
    fn reduce_sub_assign(self, a: &mut T, b: T) {
        compact::reduce_sub_assign(self.0, a, b);
    }
}

impl<T: UnsignedInteger> ReduceNeg<T> for CompactModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_neg(self, value: T) -> Self::Output {
        compact::reduce_neg(self.0, value)
    }
}

impl<T: UnsignedInteger> ReduceNegAssign<T> for CompactModulus<T> {
    #[inline(always)]
    fn reduce_neg_assign(self, value: &mut T) {
        compact::reduce_neg_assign(self.0, value);
    }
}

impl<T: UnsignedInteger> ReduceInv<T> for CompactModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_inv(self, value: T) -> Self::Output {
        compact::reduce_inv(self.0, value)
    }
}

impl<T: UnsignedInteger> ReduceInvAssign<T> for CompactModulus<T> {
    #[inline(always)]
    fn reduce_inv_assign(self, value: &mut T) {
        compact::reduce_inv_assign(self.0, value);
    }
}

impl<T: UnsignedInteger> TryReduceInv<T> for CompactModulus<T> {
    type Output = T;

    #[inline(always)]
    fn try_reduce_inv(self, value: T) -> Result<Self::Output, ReduceError<T>> {
        compact::try_reduce_inv(self.0, value)
    }
}
