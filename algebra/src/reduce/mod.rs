//! Defines some reduce operation.

mod lazy_ops;
mod ops;

mod macros;

use std::fmt::Debug;

pub use lazy_ops::*;
pub use ops::*;

use crate::{integer::UnsignedInteger, numeric::Numeric};

/// An abstract over modulus.
pub trait Modulus<T> {
    /// Returns the modulus monius one.
    fn modulus_minus_one(self) -> T;
}

/// An trait indicate the modulus can perform operation like a ring.
pub trait RingReduce<T>:
    Sized
    + Debug
    + Clone
    + Copy
    + Send
    + Sync
    + Modulus<T>
    + Reduce<T, Output = T>
    + ReduceAssign<T>
    + ReduceAdd<T, Output = T>
    + ReduceAddAssign<T>
    + ReduceSub<T, Output = T>
    + ReduceSubAssign<T>
    + ReduceDouble<T, Output = T>
    + ReduceDoubleAssign<T>
    + ReduceNeg<T, Output = T>
    + ReduceNegAssign<T>
    + ReduceMul<T, Output = T>
    + ReduceMulAssign<T>
    + ReduceMulAdd<T, Output = T>
    + ReduceMulAddAssign<T>
    + ReduceExp<T>
    + ReduceExpPowOf2<T>
    + ReduceDotProduct<T, Output = T>
{
}

impl<T: UnsignedInteger, M> RingReduce<T> for M where
    M: Sized
        + Debug
        + Clone
        + Copy
        + Send
        + Sync
        + Modulus<T>
        + Reduce<T, Output = T>
        + ReduceAssign<T>
        + ReduceAdd<T, Output = T>
        + ReduceAddAssign<T>
        + ReduceSub<T, Output = T>
        + ReduceSubAssign<T>
        + ReduceDouble<T, Output = T>
        + ReduceDoubleAssign<T>
        + ReduceNeg<T, Output = T>
        + ReduceNegAssign<T>
        + ReduceMul<T, Output = T>
        + ReduceMulAssign<T>
        + ReduceMulAdd<T, Output = T>
        + ReduceMulAddAssign<T>
        + ReduceExp<T>
        + ReduceExpPowOf2<T>
        + ReduceDotProduct<T, Output = T>
{
}

/// An trait indicate the modulus can perform operation like a field.
pub trait FieldReduce<T>:
    RingReduce<T>
    + LazyReduce<T, Output = T>
    + LazyReduceAssign<T>
    + LazyReduceMul<T, Output = T>
    + LazyReduceMulAssign<T>
    + LazyReduceMulAdd<T, Output = T>
    + LazyReduceMulAddAssign<T>
    + ReduceInv<T, Output = T>
    + ReduceInvAssign<T>
    + ReduceDiv<T, Output = T>
    + ReduceDivAssign<T>
{
}

impl<T: Numeric, M> FieldReduce<T> for M where
    M: RingReduce<T>
        + LazyReduce<T, Output = T>
        + LazyReduceAssign<T>
        + LazyReduceMul<T, Output = T>
        + LazyReduceMulAssign<T>
        + LazyReduceMulAdd<T, Output = T>
        + LazyReduceMulAddAssign<T>
        + ReduceInv<T, Output = T>
        + ReduceInvAssign<T>
        + ReduceDiv<T, Output = T>
        + ReduceDivAssign<T>
{
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use super::*;

    type ValueT = u32;
    type WideT = u64;

    #[test]
    fn test_reduce() {
        let mut rng = thread_rng();
        let m: ValueT = rng.gen_range(2..(ValueT::MAX >> 1));
        let m_d = WideT::from(m);

        let a = rng.gen_range(0..m);
        let b = rng.gen_range(0..m);

        let a_d = WideT::from(a);
        let b_d = WideT::from(b);

        let c = m.reduce_add(a, b);
        assert_eq!(WideT::from(c), (a_d + b_d) % m_d, "reduce_add");

        let c = m.reduce_double(a);
        assert_eq!(WideT::from(c), (a_d + a_d) % m_d, "reduce_double");

        let c = m.reduce_sub(a, b);
        assert_eq!(WideT::from(c), (m_d + a_d - b_d) % m_d, "reduce_sub");

        let c = m.reduce_neg(a);
        assert_eq!(0, (WideT::from(c) + a_d) % m_d, "reduce_neg");

        if let Ok(c) = m.try_reduce_inv(a) {
            assert_eq!(1, (WideT::from(c) * a_d) % m_d, "reduce_sub");
        }
    }
}
