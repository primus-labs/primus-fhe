use std::fmt::Debug;

use primus_integer::UnsignedInteger;

use super::Modulus;
use super::prelude::*;

/// A marker trait indicating the modulus can perform ring operations
/// (reduce, add, sub, double, neg, mul, mul-add, square, exp, dot-product).
///
/// Granted automatically (blanket impl) when the type implements every
/// listed `Reduce*` trait with `Output = T`.
pub trait RingContext<T>:
    Sized
    + Debug
    + Clone
    + Copy
    + Send
    + Sync
    + Modulus<ValueT = T>
    + Reduce<T, Output = T>
    + ReduceAssign<T>
    + ReduceOnce<T>
    + ReduceOnceAssign<T>
    + ReduceOnceSlice<T>
    + ReduceAdd<T, Output = T>
    + ReduceAddAssign<T>
    + ReduceAddSlice<T>
    + ReduceSub<T, Output = T>
    + ReduceSubAssign<T>
    + ReduceSubSlice<T>
    + ReduceDouble<T, Output = T>
    + ReduceDoubleAssign<T>
    + ReduceDoubleSlice<T>
    + ReduceNeg<T, Output = T>
    + ReduceNegAssign<T>
    + ReduceNegSlice<T>
    + ReduceMul<T, Output = T>
    + ReduceMulAssign<T>
    + ReduceMulSlice<T>
    + ReduceMulAdd<T, Output = T>
    + ReduceMulAddAssign<T>
    + ReduceMulAddSlice<T>
    + ReduceSquare<T, Output = T>
    + ReduceSquareAssign<T>
    + ReduceExp<T>
    + ReduceExpPowOf2<T>
    + ReduceDotProduct<T, Output = T>
{
}

impl<T: UnsignedInteger, M> RingContext<T> for M where
    M: Sized
        + Debug
        + Clone
        + Copy
        + Send
        + Sync
        + Modulus<ValueT = T>
        + Reduce<T, Output = T>
        + ReduceAssign<T>
        + ReduceOnce<T>
        + ReduceOnceAssign<T>
        + ReduceOnceSlice<T>
        + ReduceAdd<T, Output = T>
        + ReduceAddAssign<T>
        + ReduceAddSlice<T>
        + ReduceSub<T, Output = T>
        + ReduceSubAssign<T>
        + ReduceSubSlice<T>
        + ReduceDouble<T, Output = T>
        + ReduceDoubleAssign<T>
        + ReduceDoubleSlice<T>
        + ReduceNeg<T, Output = T>
        + ReduceNegAssign<T>
        + ReduceNegSlice<T>
        + ReduceMul<T, Output = T>
        + ReduceMulAssign<T>
        + ReduceMulSlice<T>
        + ReduceMulAdd<T, Output = T>
        + ReduceMulAddAssign<T>
        + ReduceMulAddSlice<T>
        + ReduceSquare<T, Output = T>
        + ReduceSquareAssign<T>
        + ReduceExp<T>
        + ReduceExpPowOf2<T>
        + ReduceDotProduct<T, Output = T>
{
}

/// A marker trait indicating the modulus can perform field operations
/// (ring + lazy reduce, multiplicative inverse, division).
///
/// Granted automatically (blanket impl) when the type already satisfies
/// [`RingContext`] and additionally implements the listed
/// `LazyReduce*` / inverse / division / slice traits.
pub trait FieldContext<T>:
    RingContext<T>
    + LazyReduce<T, Output = T>
    + LazyReduceAssign<T>
    + LazyReduceSub<T, Output = T>
    + LazyReduceSubAssign<T>
    + LazyReduceSubSlice<T>
    + LazyReduceNeg<T, Output = T>
    + LazyReduceNegAssign<T>
    + LazyReduceNegSlice<T>
    + LazyReduceMul<T, Output = T>
    + LazyReduceMulAssign<T>
    + LazyReduceMulSlice<T>
    + LazyReduceMulAdd<T, Output = T>
    + LazyReduceMulAddAssign<T>
    + LazyReduceMulAddSlice<T>
    + for<'a> LazyReduce<&'a [T], Output = T>
    + for<'a> Reduce<&'a [T], Output = T>
    + TryReduceInv<T, Output = T>
    + ReduceInv<T, Output = T>
    + ReduceInvAssign<T>
    + ReduceInvSlice<T>
    + TryReduceInvSlice<T>
    + ReduceDiv<T, Output = T>
    + ReduceDivAssign<T>
{
}

impl<T: UnsignedInteger, M> FieldContext<T> for M where
    M: RingContext<T>
        + LazyReduce<T, Output = T>
        + LazyReduceAssign<T>
        + LazyReduceSub<T, Output = T>
        + LazyReduceSubAssign<T>
        + LazyReduceSubSlice<T>
        + LazyReduceNeg<T, Output = T>
        + LazyReduceNegAssign<T>
        + LazyReduceNegSlice<T>
        + LazyReduceMul<T, Output = T>
        + LazyReduceMulAssign<T>
        + LazyReduceMulSlice<T>
        + LazyReduceMulAdd<T, Output = T>
        + LazyReduceMulAddAssign<T>
        + LazyReduceMulAddSlice<T>
        + for<'a> LazyReduce<&'a [T], Output = T>
        + for<'a> Reduce<&'a [T], Output = T>
        + TryReduceInv<T, Output = T>
        + ReduceInv<T, Output = T>
        + ReduceInvAssign<T>
        + ReduceInvSlice<T>
        + TryReduceInvSlice<T>
        + ReduceDiv<T, Output = T>
        + ReduceDivAssign<T>
{
}
