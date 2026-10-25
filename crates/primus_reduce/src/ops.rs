use primus_integer::UnsignedInteger;

use crate::ReduceError;

/// The reduce operation.
pub trait Reduce<T> {
    /// Output type.
    type Output;

    /// Calculates `value (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// The legal input range and representation for `value` are defined by
    /// each implementation for its concrete input type. The same modulus type
    /// may support scalar, fixed-width multi-limb, and arbitrary-length limb
    /// inputs with different requirements. Consult the concrete
    /// implementation's documentation.
    ///
    /// The `Reduce<&[U]>` implementation required by
    /// [`FieldContext`](crate::FieldContext) conventionally interprets the
    /// slice as a little-endian multi-limb integer to be reduced into `U`.
    /// Its accepted lengths and empty-slice behavior remain
    /// implementation-defined.
    #[must_use]
    fn reduce(self, value: T) -> Self::Output;
}

/// The reduce assignment operation.
pub trait ReduceAssign<T> {
    /// Calculates `value (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// Input range is implementation-defined; see [`Reduce::reduce`].
    fn reduce_assign(self, value: &mut T);
}

/// A single-correction modular reduction.
pub trait ReduceOnce<T> {
    /// Output type.
    type Output;

    /// Calculates `value - modulus` if `value >= modulus`.
    ///
    /// # Correctness
    ///
    /// - `value < 2 * modulus`
    /// - Result is `< modulus`
    #[must_use]
    fn reduce_once(self, value: T) -> Self::Output;
}

/// In-place single-correction modular reduction.
pub trait ReduceOnceAssign<T> {
    /// Calculates `value - modulus` if `value >= modulus`.
    ///
    /// # Correctness
    ///
    /// - `value < 2 * modulus`
    /// - Result is `< modulus`
    fn reduce_once_assign(self, value: &mut T);
}

/// The modular addition.
pub trait ReduceAdd<T> {
    /// Output type.
    type Output;

    /// Calculates `a + b (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    #[must_use]
    fn reduce_add(self, a: T, b: T) -> Self::Output;
}

/// The modular addition assignment.
pub trait ReduceAddAssign<T> {
    /// Calculates `a += b (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    fn reduce_add_assign(self, a: &mut T, b: T);
}

/// The modular double.
pub trait ReduceDouble<T> {
    /// Output type.
    type Output;

    /// Calculates `2*value (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `value < modulus`
    #[must_use]
    fn reduce_double(self, value: T) -> Self::Output;
}

/// The modular double assignment.
pub trait ReduceDoubleAssign<T> {
    /// Calculates `value = 2*value (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `value < modulus`
    fn reduce_double_assign(self, value: &mut T);
}

/// The modular subtraction.
pub trait ReduceSub<T> {
    /// Output type.
    type Output;

    /// Calculates `a - b (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    #[must_use]
    fn reduce_sub(self, a: T, b: T) -> Self::Output;
}

/// The modular subtraction assignment.
pub trait ReduceSubAssign<T> {
    /// Calculates `a -= b (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    fn reduce_sub_assign(self, a: &mut T, b: T);
}

/// The modular negation.
pub trait ReduceNeg<T> {
    /// Output type.
    type Output;

    /// Calculates `-value (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `value < modulus`
    #[must_use]
    fn reduce_neg(self, value: T) -> Self::Output;
}

/// The modular negation assignment.
pub trait ReduceNegAssign<T> {
    /// Calculates `-value (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `value < modulus`
    fn reduce_neg_assign(self, value: &mut T);
}

/// The modular multiplication.
pub trait ReduceMul<T> {
    /// Output type.
    type Output;

    /// Calculates `a * b (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a*b < modulus²`
    #[must_use]
    fn reduce_mul(self, a: T, b: T) -> Self::Output;
}

/// The modular multiplication assignment.
pub trait ReduceMulAssign<T> {
    /// Calculates `a *= b (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a*b < modulus²`
    fn reduce_mul_assign(self, a: &mut T, b: T);
}

/// The modular square.
pub trait ReduceSquare<T> {
    /// Output type.
    type Output;

    /// Calculates `value² (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `value < modulus`
    #[must_use]
    fn reduce_square(self, value: T) -> Self::Output;
}

/// The modular square assignment.
pub trait ReduceSquareAssign<T> {
    /// Calculates `value = value² (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `value < modulus`
    fn reduce_square_assign(self, value: &mut T);
}

/// The modular multiply-add.
pub trait ReduceMulAdd<T> {
    /// Output type.
    type Output;

    /// Calculates `(a * b) + c (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    /// - `c < modulus`
    #[must_use]
    fn reduce_mul_add(self, a: T, b: T, c: T) -> Self::Output;
}

/// The modular multiply-add assignment.
pub trait ReduceMulAddAssign<T> {
    /// Calculates `(a * b) + c (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    /// - `c < modulus`
    fn reduce_mul_add_assign(self, a: &mut T, b: T, c: T);
}

/// Modular multiplicative inversion.
pub trait ReduceInv<T> {
    /// Output type.
    type Output;

    /// Calculate the multiplicative inverse of `value (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `value < modulus`
    /// - `value` and `modulus` must be coprime
    ///
    /// # Panics
    ///
    /// Panics if `value` has no inverse modulo `modulus`. Use
    /// [`TryReduceInv`] for a non-panicking variant.
    #[must_use]
    fn reduce_inv(self, value: T) -> Self::Output;
}

/// In-place modular multiplicative inversion.
pub trait ReduceInvAssign<T> {
    /// Calculates `value^(-1) (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `value < modulus`
    /// - `value` and `modulus` must be coprime
    ///
    /// # Panics
    ///
    /// Panics if `value` has no inverse modulo `modulus`. Use
    /// [`TryReduceInv`] for a non-panicking variant.
    fn reduce_inv_assign(self, value: &mut T);
}

/// Fallible modular multiplicative inversion.
pub trait TryReduceInv<T> {
    /// Output type.
    type Output;

    /// Attempts to calculate the multiplicative inverse of `value` modulo `self`.
    ///
    /// # Preconditions
    ///
    /// - `value < modulus`
    ///
    /// # Errors
    ///
    /// Returns [`ReduceError::NoInverse`] for an explicit modulus, or
    /// [`ReduceError::NoInverseImplicitModulus`] for an implicit native
    /// modulus, if `value` has no inverse.
    fn try_reduce_inv(self, value: T) -> Result<Self::Output, ReduceError<T>>;
}

/// The modular division.
pub trait ReduceDiv<T> {
    /// Output type.
    type Output;

    /// Calculates `a / b (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    /// - `b` and `modulus` must be coprime
    ///
    /// # Panics
    ///
    /// Panics if `b` has no inverse modulo `modulus`.
    #[must_use]
    fn reduce_div(self, a: T, b: T) -> Self::Output;
}

/// The modular division assignment.
pub trait ReduceDivAssign<T> {
    /// Calculates `a /= b (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `a < modulus`
    /// - `b < modulus`
    /// - `b` and `modulus` must be coprime
    ///
    /// # Panics
    ///
    /// Panics if `b` has no inverse modulo `modulus`.
    fn reduce_div_assign(self, a: &mut T, b: T);
}

/// The modular exponentiation.
pub trait ReduceExp<T> {
    /// Calculates `base^exp (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `base < modulus`
    #[must_use]
    fn reduce_exp<Exponent: UnsignedInteger>(self, base: T, exp: Exponent) -> T;
}

/// The modular power-of-two exponentiation.
pub trait ReduceExpPowerOf2<T> {
    /// Calculates `base^(2^exp_log) (mod modulus)` where `self` is modulus.
    ///
    /// # Correctness
    ///
    /// - `base < modulus`
    #[must_use]
    fn reduce_exp_power_of_2(self, base: T, exp_log: u32) -> T;
}
