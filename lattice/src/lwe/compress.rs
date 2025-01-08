use algebra::{
    integer::UnsignedInteger,
    reduce::{
        ReduceAdd, ReduceAddAssign, ReduceMulAdd, ReduceMulAssign, ReduceNegAssign, ReduceSub,
        ReduceSubAssign,
    },
};
use num_traits::Zero;

use super::Lwe;

/// Represents a cryptographic structure based on the Learning with Errors (LWE) problem.
///
/// This structure encrypts several messages like a rlwe but truncated `b`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmLwe<T: Copy> {
    a: Vec<T>,
    b: Vec<T>,
}

impl<T: Copy> CmLwe<T> {
    /// Creates a new [`CmLwe<T>`].
    #[inline]
    pub fn new(a: Vec<T>, b: Vec<T>) -> Self {
        Self { a, b }
    }

    /// Returns a reference to the a of this [`CmLwe<T>`].
    #[inline]
    pub fn a(&self) -> &[T] {
        &self.a
    }

    /// Returns a reference to the b of this [`CmLwe<T>`].
    #[inline]
    pub fn b(&self) -> &[T] {
        &self.b
    }

    /// Returns a mutable reference to the a of this [`CmLwe<T>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut Vec<T> {
        &mut self.a
    }

    /// Returns a mutable reference to the b of this [`CmLwe<T>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut Vec<T> {
        &mut self.b
    }

    /// Returns the message count of this [`CmLwe<T>`].
    #[inline]
    pub fn msg_count(&self) -> usize {
        self.b.len()
    }
}

impl<T: UnsignedInteger> CmLwe<T> {
    /// Generates a [`CmLwe<T>`] with all values are `0`.
    #[inline]
    pub fn zero(dimension: usize, msg_count: usize) -> Self {
        Self {
            a: vec![T::ZERO; dimension],
            b: vec![T::ZERO; msg_count],
        }
    }

    /// Sets all values to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.a.fill(T::ZERO);
        self.b.fill(T::ZERO);
    }

    /// Perform component-wise reduce addition of two [`CmLwe<T>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `add_reduce_component_wise`.
    #[inline]
    pub fn add_reduce_component_wise_ref<M>(&self, rhs: &Self, modulus: M) -> Self
    where
        M: Copy + ReduceAdd<T, Output = T>,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        debug_assert_eq!(self.b.len(), rhs.b.len());
        Self::new(
            self.a
                .iter()
                .zip(rhs.a())
                .map(|(&a, &b)| modulus.reduce_add(a, b))
                .collect(),
            self.b
                .iter()
                .zip(rhs.b())
                .map(|(&a, &b)| modulus.reduce_add(a, b))
                .collect(),
        )
    }

    /// Perform component-wise reduce addition of two [`CmLwe<T>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is not a reference.
    /// If your `self` is a reference, you can use function `add_reduce_component_wise_ref`.
    #[inline]
    pub fn add_reduce_component_wise<M>(mut self, rhs: &Self, modulus: M) -> Self
    where
        M: Copy + ReduceAddAssign<T>,
    {
        self.add_reduce_assign_component_wise(rhs, modulus);
        self
    }

    /// Performs an in-place component-wise reduce addition
    /// on the `self` [`CmLwe<T>`] with another `rhs` [`CmLwe<T>`].
    #[inline]
    pub fn add_reduce_assign_component_wise<M>(&mut self, rhs: &Self, modulus: M)
    where
        M: Copy + ReduceAddAssign<T>,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        debug_assert_eq!(self.b.len(), rhs.b.len());
        self.a
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(a, &b)| modulus.reduce_add_assign(a, b));
        self.b
            .iter_mut()
            .zip(rhs.b())
            .for_each(|(a, &b)| modulus.reduce_add_assign(a, b));
    }

    /// Perform component-wise subtraction of two [`CmLwe<T>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `sub_reduce_component_wise`.
    #[inline]
    pub fn sub_reduce_component_wise_ref<M>(&self, rhs: &Self, modulus: M) -> Self
    where
        M: Copy + ReduceSub<T, Output = T>,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        debug_assert_eq!(self.b.len(), rhs.b.len());
        Self::new(
            self.a
                .iter()
                .zip(rhs.a())
                .map(|(&a, &b)| modulus.reduce_sub(a, b))
                .collect(),
            self.b
                .iter()
                .zip(rhs.b())
                .map(|(&a, &b)| modulus.reduce_sub(a, b))
                .collect(),
        )
    }

    /// Perform component-wise subtraction of two [`CmLwe<T>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is not a reference.
    /// If your `self` is a reference, you can use function `sub_reduce_component_wise_ref`.
    #[inline]
    pub fn sub_reduce_component_wise<M>(mut self, rhs: &Self, modulus: M) -> Self
    where
        M: Copy + ReduceSubAssign<T>,
    {
        self.sub_reduce_assign_component_wise(rhs, modulus);
        self
    }

    /// Performs an in-place component-wise subtraction
    /// on the `self` [`CmLwe<T>`] with another `rhs` [`CmLwe<T>`].
    #[inline]
    pub fn sub_reduce_assign_component_wise<M>(&mut self, rhs: &Self, modulus: M)
    where
        M: Copy + ReduceSubAssign<T>,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        self.a
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(a, &b)| modulus.reduce_sub_assign(a, b));
        self.b
            .iter_mut()
            .zip(rhs.b())
            .for_each(|(a, &b)| modulus.reduce_sub_assign(a, b));
    }

    /// Performs an in-place scalar multiplication
    /// on the `self` [`CmLwe<T>`] with scalar `T`.
    #[inline]
    pub fn mul_scalar_reduce_inplace<M>(&mut self, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulAssign<T>,
    {
        self.a
            .iter_mut()
            .for_each(|v| modulus.reduce_mul_assign(v, scalar));
        self.b
            .iter_mut()
            .for_each(|v| modulus.reduce_mul_assign(v, scalar));
    }

    /// Performs an in-place scalar multiplication
    /// on the `rhs` [`CmLwe<T>`] with `scalar` `T`,
    /// then add to `self`.
    #[inline]
    pub fn add_assign_rhs_mul_scalar_reduce<M>(&mut self, rhs: &Self, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulAdd<T, Output = T>,
    {
        self.a
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v, &r)| *v = modulus.reduce_mul_add(r, scalar, *v));
        self.b
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v, &r)| *v = modulus.reduce_mul_add(r, scalar, *v));
    }

    /// Sample extract [Lwe<T>].
    #[inline]
    pub fn extract_rlwe_mode<M>(&self, index: usize, modulus: M) -> Lwe<T>
    where
        M: Copy + ReduceNegAssign<T>,
    {
        let mut a = self.a.clone();
        if index.is_zero() {
            Lwe::new(a, self.b[0])
        } else {
            a.rotate_right(index);
            a[..index]
                .iter_mut()
                .for_each(|v| modulus.reduce_neg_assign(v));
            Lwe::new(a, self.b[index])
        }
    }
}
