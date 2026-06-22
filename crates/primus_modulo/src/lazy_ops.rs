use primus_reduce::prelude::*;

/// The lazy modulo operation.
pub trait LazyModulo<M> {
    /// Output type.
    type Output;

    /// Calculates `self (mod 2*modulus)`.
    ///
    /// # Correctness
    ///
    /// The result is only guaranteed to be in `[0, 2*modulus)`, not the
    /// canonical `[0, modulus)`.
    ///
    /// If the modulus type does not natively support lazy reduction,
    /// implementations should fall back to [`Modulo`](crate::ops::Modulo).
    fn lazy_modulo(self, modulus: M) -> Self::Output;
}

impl<T, M> LazyModulo<M> for T
where
    M: LazyReduce<T>,
{
    type Output = <M as LazyReduce<T>>::Output;

    #[inline(always)]
    fn lazy_modulo(self, modulus: M) -> Self::Output {
        modulus.lazy_reduce(self)
    }
}

/// The lazy modulo assignment operation.
pub trait LazyModuloAssign<M> {
    /// Calculates `self (mod 2*modulus)`.
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ops::ModuloAssign] trait.
    fn lazy_modulo_assign(&mut self, modulus: M);
}

impl<T, M> LazyModuloAssign<M> for T
where
    M: LazyReduceAssign<T>,
{
    #[inline(always)]
    fn lazy_modulo_assign(&mut self, modulus: M) {
        modulus.lazy_reduce_assign(self)
    }
}

/// The lazy modular multiplication.
pub trait LazyMulModulo<M, B = Self> {
    /// Output type.
    type Output;

    /// Calculates `self * b (mod 2*modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self * b < modulus²`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ops::MulModulo] trait.
    fn lazy_mul_modulo(self, b: B, modulus: M) -> Self::Output;
}

impl<T, M, B> LazyMulModulo<M, B> for T
where
    M: LazyReduceMul<T, B>,
{
    type Output = <M as LazyReduceMul<T, B>>::Output;

    #[inline(always)]
    fn lazy_mul_modulo(self, b: B, modulus: M) -> Self::Output {
        modulus.lazy_reduce_mul(self, b)
    }
}

/// The lazy modular multiplication assignment.
pub trait LazyMulModuloAssign<M, B = Self> {
    /// Calculates `self *= b (mod 2*modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self * b < modulus²`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ops::MulModuloAssign] trait.
    fn lazy_mul_modulo_assign(&mut self, b: B, modulus: M);
}

impl<T, M, B> LazyMulModuloAssign<M, B> for T
where
    M: LazyReduceMulAssign<T, B>,
{
    #[inline(always)]
    fn lazy_mul_modulo_assign(&mut self, b: B, modulus: M) {
        modulus.lazy_reduce_mul_assign(self, b)
    }
}

/// The lazy modular multiply-add.
pub trait LazyMulAddModulo<M, B = Self, C = Self> {
    /// Output type.
    type Output;

    /// Calculates `self * b + c (mod 2*modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    /// - `c < modulus`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ops::MulAddModulo] trait.
    fn lazy_mul_add_modulo(self, b: B, c: C, modulus: M) -> Self::Output;
}

impl<T, M, B, C> LazyMulAddModulo<M, B, C> for T
where
    M: LazyReduceMulAdd<T, B, C>,
{
    type Output = <M as LazyReduceMulAdd<T, B, C>>::Output;

    #[inline(always)]
    fn lazy_mul_add_modulo(self, b: B, c: C, modulus: M) -> Self::Output {
        modulus.lazy_reduce_mul_add(self, b, c)
    }
}

/// The lazy modular multiply-add assignment.
pub trait LazyMulAddModuloAssign<M, B = Self, C = Self> {
    /// Calculates `self * b + c (mod 2*modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    /// - `c < modulus`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ops::MulAddModuloAssign] trait.
    fn lazy_mul_add_modulo_assign(&mut self, b: B, c: C, modulus: M);
}

impl<T, M, B, C> LazyMulAddModuloAssign<M, B, C> for T
where
    M: LazyReduceMulAddAssign<T, B, C>,
{
    #[inline(always)]
    fn lazy_mul_add_modulo_assign(&mut self, b: B, c: C, modulus: M) {
        modulus.lazy_reduce_mul_add_assign(self, b, c)
    }
}

/// The lazy modular subtraction.
pub trait LazySubModulo<M, B = Self> {
    /// Output type.
    type Output;

    /// Calculates `self - b (mod 2*modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ops::SubModulo] trait.
    fn lazy_sub_modulo(self, b: B, modulus: M) -> Self::Output;
}

impl<T, M, B> LazySubModulo<M, B> for T
where
    M: LazyReduceSub<T, B>,
{
    type Output = <M as LazyReduceSub<T, B>>::Output;

    #[inline(always)]
    fn lazy_sub_modulo(self, b: B, modulus: M) -> Self::Output {
        modulus.lazy_reduce_sub(self, b)
    }
}

/// The lazy modular subtraction assignment.
pub trait LazySubModuloAssign<M, B = Self> {
    /// Calculates `self -= b (mod 2*modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ops::SubModuloAssign] trait.
    fn lazy_sub_modulo_assign(&mut self, b: B, modulus: M);
}

impl<T, M, B> LazySubModuloAssign<M, B> for T
where
    M: LazyReduceSubAssign<T, B>,
{
    #[inline(always)]
    fn lazy_sub_modulo_assign(&mut self, b: B, modulus: M) {
        modulus.lazy_reduce_sub_assign(self, b)
    }
}

/// The lazy modular negation.
pub trait LazyNegModulo<M> {
    /// Output type.
    type Output;

    /// Calculates `-self (mod 2*modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ops::NegModulo] trait.
    fn lazy_neg_modulo(self, modulus: M) -> Self::Output;
}

impl<T, M> LazyNegModulo<M> for T
where
    M: LazyReduceNeg<T>,
{
    type Output = <M as LazyReduceNeg<T>>::Output;

    #[inline(always)]
    fn lazy_neg_modulo(self, modulus: M) -> Self::Output {
        modulus.lazy_reduce_neg(self)
    }
}

/// The lazy modular negation assignment.
pub trait LazyNegModuloAssign<M> {
    /// Calculates `self = -self (mod 2*modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    ///
    /// If modulus doesn't support this special case,
    /// just fall back to [crate::ops::NegModuloAssign] trait.
    fn lazy_neg_modulo_assign(&mut self, modulus: M);
}

impl<T, M> LazyNegModuloAssign<M> for T
where
    M: LazyReduceNegAssign<T>,
{
    #[inline(always)]
    fn lazy_neg_modulo_assign(&mut self, modulus: M) {
        modulus.lazy_reduce_neg_assign(self)
    }
}
