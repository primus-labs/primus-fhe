#[macro_use]
mod internal_macros;

/// A number used for fast modular multiplication.
///
/// This is efficient if many operations are multiplied by
/// the same number and then reduced with the same modulus.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShoupFactor<T: Copy> {
    /// value
    value: T,

    /// quotient
    quotient: T,
}

impl<T: Copy> ShoupFactor<T> {
    /// Returns the value of this [`ShoupFactor<T>`].
    #[inline]
    pub const fn value(self) -> T {
        self.value
    }

    /// Returns the quotient of this [`ShoupFactor<T>`].
    #[inline]
    pub const fn quotient(self) -> T {
        self.quotient
    }
}

impl_shoup_factor!(impl ShoupFactor<u8>; WideType: u16);
impl_shoup_factor!(impl ShoupFactor<u16>; WideType: u32);
impl_shoup_factor!(impl ShoupFactor<u32>; WideType: u64);
impl_shoup_factor!(impl ShoupFactor<u64>; WideType: u128);

impl_shoup_factor_ops!(impl ShoupFactor<u8>);
impl_shoup_factor_ops!(impl ShoupFactor<u16>);
impl_shoup_factor_ops!(impl ShoupFactor<u32>);
impl_shoup_factor_ops!(impl ShoupFactor<u64>);

#[cfg(test)]
mod tests {
    use crate::{
        modulus::BarrettModulus,
        reduce::{MulReduce, Reduce},
    };

    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_shoup_factor() {
        let mut rng = thread_rng();

        let modulus_value: u64 = rng.gen_range(2..=(u64::MAX >> 2));
        let modulus = BarrettModulus::<u64>::new(modulus_value);

        let a = rng.gen_range(0..modulus_value);
        let factor = <ShoupFactor<u64>>::new(a, modulus_value);

        let b: u64 = rng.gen();

        assert_eq!(
            a.mul_reduce(b.reduce(modulus), modulus),
            factor.mul_reduce(b, modulus_value)
        );
    }
}
