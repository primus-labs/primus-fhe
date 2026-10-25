use primus_integer::FheUint;

use super::prelude::*;
use super::{ExplicitModulus, Modulus};

/// A marker trait indicating the modulus can perform ring operations
/// (reduce, add, sub, double, neg, mul, mul-add, square, exp, dot-product),
/// bounded signed encoding/dot products via [`EncodeSigned`] and
/// [`ReduceDotProductSigned`], and modulus-switch preparation via
/// [`PrepareModulusSwitch`].
///
/// Granted automatically (blanket impl) when the type implements every
/// listed capability trait. Prepared conversions are separate concrete objects.
pub trait RingContext<T: FheUint>:
    Modulus<ValueT = T>
    + PrepareModulusSwitch
    + EncodeSigned<T>
    + Reduce<T, Output = T>
    + ReduceAssign<T>
    + ReduceOnce<T, Output = T>
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
    + ReduceExpPowerOf2<T>
    + ReduceDotProduct<T>
    + ReduceDotProductSigned<T>
{
}

impl<T: FheUint, M> RingContext<T> for M where
    M: Modulus<ValueT = T>
        + PrepareModulusSwitch
        + EncodeSigned<T>
        + Reduce<T, Output = T>
        + ReduceAssign<T>
        + ReduceOnce<T, Output = T>
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
        + ReduceExpPowerOf2<T>
        + ReduceDotProduct<T>
        + ReduceDotProductSigned<T>
{
}

/// A marker trait indicating the modulus has an explicit value and can perform
/// field operations (ring + lazy reduce, multiplicative inverse, division).
///
/// Granted automatically (blanket impl) when the type already satisfies
/// [`RingContext`] and [`ExplicitModulus`], and additionally implements the
/// listed `LazyReduce*` / inverse / division / slice traits.
///
/// This is a capability marker, not proof that the residues form a mathematical
/// field. In particular, it does not guarantee that the modulus is prime or
/// that every nonzero residue is invertible. Callers must validate any such
/// algebraic requirements; inverse and division operations retain the failure
/// behavior documented by their individual traits.
pub trait FieldContext<T: FheUint>:
    RingContext<T>
    + ExplicitModulus<ValueT = T>
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

impl<T: FheUint, M> FieldContext<T> for M where
    M: RingContext<T>
        + ExplicitModulus<ValueT = T>
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
