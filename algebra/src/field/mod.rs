use crate::integer::UnsignedInteger;
use crate::numeric::Numeric;
use crate::reduce::*;

#[macro_use]
mod macros;
mod impls;
mod ntt;

pub use impls::f32::U32FieldEval;
pub use impls::f64::U64FieldEval;
pub use ntt::NttField;

/// An abstract for field evaluator.
pub trait Field: Sized + Clone + Copy {
    /// The field elements value type.
    type ValueT: Numeric;

    /// The field modulus type.
    type Modulus: FieldReduce<Self::ValueT>;

    /// The field modulus value.
    const MODULUS_VALUE: Self::ValueT;

    /// The field modulus.
    const MODULUS: Self::Modulus;

    /// 0
    const ZERO: Self::ValueT;
    /// 1
    const ONE: Self::ValueT;
    /// -1
    const MINUS_ONE: Self::ValueT;

    /// Returns the field modulus.
    #[inline]
    fn modulus() -> Self::Modulus {
        Self::MODULUS
    }

    /// Calculates `a + b`.
    #[inline]
    fn add(a: Self::ValueT, b: Self::ValueT) -> Self::ValueT {
        Self::MODULUS.reduce_add(a, b)
    }

    /// Calculates `a += b`.
    #[inline]
    fn add_assign(a: &mut Self::ValueT, b: Self::ValueT) {
        Self::MODULUS.reduce_add_assign(a, b);
    }

    /// Calculates `2*value`.
    #[inline]
    fn double(value: Self::ValueT) -> Self::ValueT {
        Self::MODULUS.reduce_double(value)
    }

    /// Calculates `value = 2*value`.
    #[inline]
    fn double_assign(value: &mut Self::ValueT) {
        Self::MODULUS.reduce_double_assign(value);
    }

    /// Calculates `a - b`.
    #[inline]
    fn sub(a: Self::ValueT, b: Self::ValueT) -> Self::ValueT {
        Self::MODULUS.reduce_sub(a, b)
    }

    /// Calculates `a -= b`.
    #[inline]
    fn sub_assign(a: &mut Self::ValueT, b: Self::ValueT) {
        Self::MODULUS.reduce_sub_assign(a, b);
    }

    /// Calculates `-value`.
    #[inline]
    fn neg(value: Self::ValueT) -> Self::ValueT {
        Self::MODULUS.reduce_neg(value)
    }

    /// Calculates `-value`.
    #[inline]
    fn neg_assign(value: &mut Self::ValueT) {
        Self::MODULUS.reduce_neg_assign(value);
    }

    /// Calculates `a * b`.
    #[inline]
    fn mul(a: Self::ValueT, b: Self::ValueT) -> Self::ValueT {
        Self::MODULUS.reduce_mul(a, b)
    }

    /// Calculates `a *= b`.
    #[inline]
    fn mul_assign(a: &mut Self::ValueT, b: Self::ValueT) {
        Self::MODULUS.reduce_mul_assign(a, b);
    }

    /// Calculates `(a * b) + c`.
    #[inline]
    fn mul_add(a: Self::ValueT, b: Self::ValueT, c: Self::ValueT) -> Self::ValueT {
        Self::MODULUS.reduce_mul_add(a, b, c)
    }

    /// Calculates `a = (a * b) + c`.
    #[inline]
    fn mul_add_assign(a: &mut Self::ValueT, b: Self::ValueT, c: Self::ValueT) {
        Self::MODULUS.reduce_mul_add_assign(a, b, c);
    }

    /// Calculates `base^exp`.
    #[inline]
    fn exp<E: UnsignedInteger>(base: Self::ValueT, exp: E) -> Self::ValueT {
        Self::MODULUS.reduce_exp(base, exp)
    }

    /// Calculates `base^(2^exp_log)`.
    #[inline]
    fn exp_power_of_2(base: Self::ValueT, exp_log: u32) -> Self::ValueT {
        Self::MODULUS.reduce_exp_power_of_2(base, exp_log)
    }

    /// Calculate `∑a_i×b_i`.
    #[inline]
    fn dot_product(a: impl AsRef<[Self::ValueT]>, b: impl AsRef<[Self::ValueT]>) -> Self::ValueT {
        Self::MODULUS.reduce_dot_product(a, b)
    }

    /// Calculate the multiplicative inverse of `value`.
    #[inline]
    fn inv(value: Self::ValueT) -> Self::ValueT {
        Self::MODULUS.reduce_inv(value)
    }

    /// Calculates `value^(-1)`.
    #[inline]
    fn inv_assign(value: &mut Self::ValueT) {
        Self::MODULUS.reduce_inv_assign(value);
    }

    /// Calculates `a / b`.
    #[inline]
    fn div(a: Self::ValueT, b: Self::ValueT) -> Self::ValueT {
        Self::MODULUS.reduce_div(a, b)
    }

    /// Calculates `a /= b`.
    #[inline]
    fn div_assign(a: &mut Self::ValueT, b: Self::ValueT) {
        Self::MODULUS.reduce_div_assign(a, b);
    }
}

impl_barrett_field!(#[derive(Clone, Copy)] impl pub U8FieldEval<u8>);
impl_barrett_field!(#[derive(Clone, Copy)] impl pub U16FieldEval<u16>);
