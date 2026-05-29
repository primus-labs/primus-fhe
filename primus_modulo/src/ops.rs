use primus_integer::UnsignedInteger;
use primus_reduce::ReduceError;
use primus_reduce::prelude::*;

/// The modulo operation.
pub trait Modulo<M> {
    /// Output type.
    type Output;

    /// Calculates `self (mod modulus)`.
    fn modulo(self, modulus: M) -> Self::Output;
}

impl<T, M> Modulo<M> for T
where
    M: Reduce<T>,
{
    type Output = <M as Reduce<T>>::Output;

    #[inline(always)]
    fn modulo(self, modulus: M) -> Self::Output {
        modulus.reduce(self)
    }
}

/// The modulo assignment operation.
pub trait ModuloAssign<M> {
    /// Calculates `self = self (mod modulus)`.
    fn modulo_assign(&mut self, modulus: M);
}

impl<T, M> ModuloAssign<M> for T
where
    M: ReduceAssign<T>,
{
    #[inline(always)]
    fn modulo_assign(&mut self, modulus: M) {
        modulus.reduce_assign(self)
    }
}

/// At most one minus operation.
pub trait ModuloOnce<M> {
    /// Output type.
    type Output;

    /// Calculates `self - modulus` if `self >= modulus`.
    fn modulo_once(self, modulus: M) -> Self::Output;
}

impl<T, M> ModuloOnce<M> for T
where
    M: ReduceOnce<T>,
{
    type Output = <M as ReduceOnce<T>>::Output;

    #[inline(always)]
    fn modulo_once(self, modulus: M) -> Self::Output {
        modulus.reduce_once(self)
    }
}

/// At most one minus operation assignment.
pub trait ModuloOnceAssign<M> {
    /// Calculates `self -= modulus` if `self >= modulus`.
    fn modulo_once_assign(&mut self, modulus: M);
}

impl<T, M> ModuloOnceAssign<M> for T
where
    M: ReduceOnceAssign<T>,
{
    #[inline(always)]
    fn modulo_once_assign(&mut self, modulus: M) {
        modulus.reduce_once_assign(self)
    }
}

/// The modular addition.
pub trait AddModulo<M, B = Self> {
    /// Output type.
    type Output;

    /// Calculates `self + b (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    fn add_modulo(self, b: B, modulus: M) -> Self::Output;
}

impl<T, M, B> AddModulo<M, B> for T
where
    M: ReduceAdd<T, B>,
{
    type Output = <M as ReduceAdd<T, B>>::Output;

    #[inline(always)]
    fn add_modulo(self, b: B, modulus: M) -> Self::Output {
        modulus.reduce_add(self, b)
    }
}

/// The modular addition assignment.
pub trait AddModuloAssign<M, B = Self> {
    /// Calculates `self += b (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    fn add_modulo_assign(&mut self, b: B, modulus: M);
}

impl<T, M, B> AddModuloAssign<M, B> for T
where
    M: ReduceAddAssign<T, B>,
{
    #[inline(always)]
    fn add_modulo_assign(&mut self, b: B, modulus: M) {
        modulus.reduce_add_assign(self, b)
    }
}

/// The modular double.
pub trait DoubleModulo<M> {
    /// Output type.
    type Output;

    /// Calculates `2*self (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn double_modulo(self, modulus: M) -> Self::Output;
}

impl<T, M> DoubleModulo<M> for T
where
    M: ReduceDouble<T>,
{
    type Output = <M as ReduceDouble<T>>::Output;

    #[inline(always)]
    fn double_modulo(self, modulus: M) -> Self::Output {
        modulus.reduce_double(self)
    }
}

/// The modular double assignment.
pub trait DoubleModuloAssign<M> {
    /// Calculates `self = 2*self (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn double_modulo_assign(&mut self, modulus: M);
}

impl<T, M> DoubleModuloAssign<M> for T
where
    M: ReduceDoubleAssign<T>,
{
    #[inline(always)]
    fn double_modulo_assign(&mut self, modulus: M) {
        modulus.reduce_double_assign(self)
    }
}

/// The modular subtraction.
pub trait SubModulo<M, B = Self> {
    /// Output type.
    type Output;

    /// Calculates `self - b (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    fn sub_modulo(self, b: B, modulus: M) -> Self::Output;
}

impl<T, M, B> SubModulo<M, B> for T
where
    M: ReduceSub<T, B>,
{
    type Output = <M as ReduceSub<T, B>>::Output;

    #[inline(always)]
    fn sub_modulo(self, b: B, modulus: M) -> Self::Output {
        modulus.reduce_sub(self, b)
    }
}

/// The modular subtraction assignment.
pub trait SubModuloAssign<M, B = Self> {
    /// Calculates `self -= b (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    fn sub_modulo_assign(&mut self, b: B, modulus: M);
}

impl<T, M, B> SubModuloAssign<M, B> for T
where
    M: ReduceSubAssign<T, B>,
{
    #[inline(always)]
    fn sub_modulo_assign(&mut self, b: B, modulus: M) {
        modulus.reduce_sub_assign(self, b)
    }
}

/// The modular negation.
pub trait NegModulo<M> {
    /// Output type.
    type Output;

    /// Calculates `-self (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn neg_modulo(self, modulus: M) -> Self::Output;
}

impl<T, M> NegModulo<M> for T
where
    M: ReduceNeg<T>,
{
    type Output = <M as ReduceNeg<T>>::Output;

    #[inline(always)]
    fn neg_modulo(self, modulus: M) -> Self::Output {
        modulus.reduce_neg(self)
    }
}

/// The modular negation assignment.
pub trait NegModuloAssign<M> {
    /// Calculates `-self (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn neg_modulo_assign(&mut self, modulus: M);
}

impl<T, M> NegModuloAssign<M> for T
where
    M: ReduceNegAssign<T>,
{
    #[inline(always)]
    fn neg_modulo_assign(&mut self, modulus: M) {
        modulus.reduce_neg_assign(self)
    }
}

/// The modular multiplication.
pub trait MulModulo<M, B = Self> {
    /// Output type.
    type Output;

    /// Calculates `self * b (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self*b < modulus²`
    fn mul_modulo(self, b: B, modulus: M) -> Self::Output;
}

impl<T, M, B> MulModulo<M, B> for T
where
    M: ReduceMul<T, B>,
{
    type Output = <M as ReduceMul<T, B>>::Output;

    #[inline(always)]
    fn mul_modulo(self, b: B, modulus: M) -> Self::Output {
        modulus.reduce_mul(self, b)
    }
}

/// The modular multiplication assignment.
pub trait MulModuloAssign<M, B = Self> {
    /// Calculates `self *= b (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self*b < modulus²`
    fn mul_modulo_assign(&mut self, b: B, modulus: M);
}

impl<T, M, B> MulModuloAssign<M, B> for T
where
    M: ReduceMulAssign<T, B>,
{
    #[inline(always)]
    fn mul_modulo_assign(&mut self, b: B, modulus: M) {
        modulus.reduce_mul_assign(self, b)
    }
}

/// The modular square.
pub trait SquareModulo<M> {
    /// Output type.
    type Output;

    /// Calculates `self² (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn square_modulo(self, modulus: M) -> Self::Output;
}

impl<T, M> SquareModulo<M> for T
where
    M: ReduceSquare<T>,
{
    type Output = <M as ReduceSquare<T>>::Output;

    #[inline(always)]
    fn square_modulo(self, modulus: M) -> Self::Output {
        modulus.reduce_square(self)
    }
}

/// The modular square assignment.
pub trait SquareModuloAssign<M> {
    /// Calculates `self = self² (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn square_modulo_assign(&mut self, modulus: M);
}

impl<T, M> SquareModuloAssign<M> for T
where
    M: ReduceSquareAssign<T>,
{
    #[inline(always)]
    fn square_modulo_assign(&mut self, modulus: M) {
        modulus.reduce_square_assign(self)
    }
}

/// The modular multiply-add.
pub trait MulAddModulo<M, B = Self, C = Self> {
    /// Output type.
    type Output;

    /// Calculates `(self * b) + c (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    /// - `c < modulus`
    fn mul_add_modulo(self, b: B, c: C, modulus: M) -> Self::Output;
}

impl<T, M, B, C> MulAddModulo<M, B, C> for T
where
    M: ReduceMulAdd<T, B, C>,
{
    type Output = <M as ReduceMulAdd<T, B, C>>::Output;

    #[inline(always)]
    fn mul_add_modulo(self, b: B, c: C, modulus: M) -> Self::Output {
        modulus.reduce_mul_add(self, b, c)
    }
}

/// The modular multiply-add assignment.
pub trait MulAddModuloAssign<M, B = Self, C = Self> {
    /// Calculates `(self * b) + c (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    /// - `c < modulus`
    fn mul_add_modulo_assign(&mut self, b: B, c: C, modulus: M);
}

impl<T, M, B, C> MulAddModuloAssign<M, B, C> for T
where
    M: ReduceMulAddAssign<T, B, C>,
{
    #[inline(always)]
    fn mul_add_modulo_assign(&mut self, b: B, c: C, modulus: M) {
        modulus.reduce_mul_add_assign(self, b, c)
    }
}

/// Calculate the inverse element for a field.
pub trait InvModulo<M> {
    /// Output type.
    type Output;

    /// Calculate the multiplicative inverse of `self (mod modulus)`.
    fn inv_modulo(self, modulus: M) -> Self::Output;
}

impl<T, M> InvModulo<M> for T
where
    M: ReduceInv<T>,
{
    type Output = <M as ReduceInv<T>>::Output;

    #[inline(always)]
    fn inv_modulo(self, modulus: M) -> Self::Output {
        modulus.reduce_inv(self)
    }
}

/// The modular inversion assignment for a field.
pub trait InvModuloAssign<M> {
    /// Calculates `self^(-1) (mod modulus)`.
    fn inv_modulo_assign(&mut self, modulus: M);
}

impl<T, M> InvModuloAssign<M> for T
where
    M: ReduceInvAssign<T>,
{
    #[inline(always)]
    fn inv_modulo_assign(&mut self, modulus: M) {
        modulus.reduce_inv_assign(self)
    }
}

/// Try to calculate the inverse element when there may be not a field.
pub trait TryInvModulo<M>
where
    Self: Sized,
{
    /// Output type.
    type Output;

    /// Try to calculate the multiplicative inverse of `self modulo modulus`.
    ///
    /// # Errors
    ///
    /// If there does not exist such an inverse, a [`ReduceError`] will be returned.
    fn try_inv_modulo(self, modulus: M) -> Result<Self::Output, ReduceError<Self>>;
}

impl<T, M> TryInvModulo<M> for T
where
    M: TryReduceInv<T>,
{
    type Output = <M as TryReduceInv<T>>::Output;

    #[inline(always)]
    fn try_inv_modulo(self, modulus: M) -> Result<Self::Output, ReduceError<Self>> {
        modulus.try_reduce_inv(self)
    }
}

/// The modular division.
pub trait DivModulo<M, B = Self> {
    /// Output type.
    type Output;

    /// Calculates `self / b (mod modulus)`.
    fn div_modulo(self, b: B, modulus: M) -> Self::Output;
}

impl<T, M, B> DivModulo<M, B> for T
where
    M: ReduceDiv<T, B>,
{
    type Output = <M as ReduceDiv<T, B>>::Output;

    #[inline(always)]
    fn div_modulo(self, b: B, modulus: M) -> Self::Output {
        modulus.reduce_div(self, b)
    }
}

/// The modular division assignment.
pub trait DivModuloAssign<M, B = Self> {
    /// Calculates `self /= b (mod modulus)`.
    fn div_modulo_assign(&mut self, b: B, modulus: M);
}

impl<T, M, B> DivModuloAssign<M, B> for T
where
    M: ReduceDivAssign<T, B>,
{
    #[inline(always)]
    fn div_modulo_assign(&mut self, b: B, modulus: M) {
        modulus.reduce_div_assign(self, b)
    }
}

/// The modular exponentiation.
pub trait ExpModulo<M> {
    /// Calculates `self^exp (mod modulus)`.
    fn exp_modulo<Exponent: UnsignedInteger>(self, exp: Exponent, modulus: M) -> Self;
}

impl<T, M> ExpModulo<M> for T
where
    M: ReduceExp<T>,
{
    #[inline(always)]
    fn exp_modulo<Exponent: UnsignedInteger>(self, exp: Exponent, modulus: M) -> Self {
        modulus.reduce_exp(self, exp)
    }
}

/// The modular power-of-two exponentiation.
pub trait ExpPowOf2Modulo<M> {
    /// Calculates `self^(2^exp_log) (mod modulus)`.
    fn exp_power_of_2_modulo(self, exp_log: u32, modulus: M) -> Self;
}

impl<T, M> ExpPowOf2Modulo<M> for T
where
    M: ReduceExpPowOf2<T>,
{
    #[inline(always)]
    fn exp_power_of_2_modulo(self, exp_log: u32, modulus: M) -> Self {
        modulus.reduce_exp_power_of_2(self, exp_log)
    }
}
