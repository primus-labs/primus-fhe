//! Defines some reduce operation.

mod lazy_ops;
mod ops;

mod macros;

use std::fmt::Debug;

pub use lazy_ops::*;
use num_traits::ConstOne;
pub use ops::*;

use crate::{arith::PrimitiveRoot, integer::UnsignedInteger, numeric::Numeric};

/// Represents different types of modulus values.
///
/// # Type Parameters
///
/// * `C` - An unsigned integer type that represents the coefficients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModulusValue<C> {
    /// Native modulus.
    Native,
    /// Power of 2 modulus.
    PowerOf2(C),
    /// Prime modulus.
    Prime(C),
    /// Other types of modulus.
    Others(C),
}

impl<C: UnsignedInteger> ModulusValue<C> {
    /// Returns modulus minus one.
    #[inline]
    pub fn modulus_minus_one(self) -> C {
        match self {
            ModulusValue::Native => C::MAX,
            ModulusValue::PowerOf2(value)
            | ModulusValue::Prime(value)
            | ModulusValue::Others(value) => value - <C as ConstOne>::ONE,
        }
    }

    /// Returns log modulus, also known as modulus bits.
    #[inline]
    pub fn log_modulus(self) -> u32 {
        match self {
            ModulusValue::Native => C::BITS,
            ModulusValue::PowerOf2(q) => q.trailing_zeros(),
            ModulusValue::Prime(q) | ModulusValue::Others(q) => C::BITS - q.leading_zeros(),
        }
    }

    /// Returns `true` if the modulus value is [`Native`].
    ///
    /// [`Native`]: ModulusValue::Native
    #[must_use]
    #[inline]
    pub fn is_native(&self) -> bool {
        matches!(self, Self::Native)
    }

    /// Returns `true` if the modulus value is [`PowerOf2`].
    ///
    /// [`PowerOf2`]: ModulusValue::PowerOf2
    #[must_use]
    #[inline]
    pub fn is_power_of2(&self) -> bool {
        matches!(self, Self::PowerOf2(..))
    }

    /// Returns an `Option` containing a reference to the value
    /// if the modulus value is [`PowerOf2`].
    ///
    /// [`PowerOf2`]: ModulusValue::PowerOf2
    #[inline]
    pub fn as_power_of2(&self) -> Option<&C> {
        if let Self::PowerOf2(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

/// An abstract over modulus.
pub trait Modulus<T> {
    /// Converts a modulus value to a modulus.
    fn from_value(value: ModulusValue<T>) -> Self;

    /// Returns the modulus value.
    fn modulus_value(&self) -> ModulusValue<T>;

    /// Returns the modulus minus one.
    fn modulus_minus_one(&self) -> T;
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
    + ReduceSquare<T, Output = T>
    + ReduceSquareAssign<T>
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
        + ReduceSquare<T, Output = T>
        + ReduceSquareAssign<T>
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
    + PrimitiveRoot<T>
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
        + PrimitiveRoot<T>
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
