use std::ops::{Add, AddAssign, Sub, SubAssign};

use algebra::{
    reduce::{AddReduce, AddReduceAssign, MulReduce, SubReduce, SubReduceAssign},
    AsFrom,
};
use num_traits::ConstZero;
use rand::{CryptoRng, Rng};
use rand_distr::{uniform::SampleUniform, Distribution, Uniform};

use crate::DiscreteGaussian;

/// Represents a cryptographic structure based on the Learning with Errors (LWE) problem.
/// The LWE problem is a fundamental component in modern cryptography, often used to build
/// secure cryptographic systems that are considered hard to crack by quantum computers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LWE<T: Copy> {
    /// A vector of elements of `T`, representing the public vector part of the LWE instance.
    a: Vec<T>,
    /// An element of `T`, representing the value which is computed as
    /// the dot product of `a` with a secret vector, plus message and some noise.
    b: T,
}

impl<T: Copy> LWE<T> {
    /// Creates a new [`LWE<T>`].
    #[inline]
    pub fn new(a: Vec<T>, b: T) -> Self {
        Self { a, b }
    }

    /// Creates a new [`LWE<T>`] with reference.
    #[inline]
    pub fn from_ref(a: &[T], b: T) -> Self {
        Self { a: a.to_vec(), b }
    }

    /// Returns a reference to the `a` of this [`LWE<T>`].
    #[inline]
    pub fn a(&self) -> &[T] {
        self.a.as_ref()
    }

    /// Returns a mutable reference to the `a` of this [`LWE<T>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut Vec<T> {
        &mut self.a
    }

    /// Returns the `b` of this [`LWE<T>`].
    #[inline]
    pub fn b(&self) -> T {
        self.b
    }

    /// Returns a mutable reference to the `b` of this [`LWE<T>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut T {
        &mut self.b
    }

    /// Perform component-wise addition of two [`LWE<T>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `add_component_wise`.
    #[inline]
    pub fn add_component_wise_ref(&self, rhs: &Self) -> Self
    where
        T: Add<T, Output = T>,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        Self::new(
            self.a.iter().zip(rhs.a()).map(|(&x, &y)| x + y).collect(),
            self.b + rhs.b,
        )
    }

    /// Perform component-wise addition of two [`LWE<T>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is not a reference.
    /// If your `self` is a reference, you can use function `add_component_wise_ref`.
    #[inline]
    pub fn add_component_wise(mut self, rhs: &Self) -> Self
    where
        T: AddAssign<T>,
    {
        self.add_inplace_component_wise(rhs);
        self
    }

    /// Performs an in-place component-wise addition
    /// on the `self` [`LWE<T>`] with another `rhs` [`LWE<T>`].
    #[inline]
    pub fn add_inplace_component_wise(&mut self, rhs: &Self)
    where
        T: AddAssign<T>,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        self.a
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v0, &v1)| *v0 += v1);
        self.b += rhs.b;
    }

    /// Perform component-wise subtraction of two [`LWE<T>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `sub_component_wise`.
    #[inline]
    pub fn sub_component_wise_ref(&self, rhs: &Self) -> Self
    where
        T: Sub<T, Output = T>,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        Self::new(
            self.a.iter().zip(rhs.a()).map(|(&x, &y)| x - y).collect(),
            self.b - rhs.b,
        )
    }

    /// Perform component-wise subtraction of two [`LWE<T>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is not a reference.
    /// If your `self` is a reference, you can use function `sub_component_wise_ref`.
    #[inline]
    pub fn sub_component_wise(mut self, rhs: &Self) -> Self
    where
        T: SubAssign<T>,
    {
        self.sub_inplace_component_wise(rhs);
        self
    }

    /// Performs an in-place component-wise subtraction
    /// on the `self` [`LWE<T>`] with another `rhs` [`LWE<T>`].
    #[inline]
    pub fn sub_inplace_component_wise(&mut self, rhs: &Self)
    where
        T: SubAssign<T>,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        self.a
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v0, &v1)| *v0 -= v1);
        self.b -= rhs.b;
    }

    /// Perform component-wise reduce addition of two [`LWE<T>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `add_reduce_component_wise`.
    #[inline]
    pub fn add_reduce_component_wise_ref<M>(&self, rhs: &Self, modulus: M) -> Self
    where
        T: AddReduce<M, Output = T>,
        M: Copy,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        Self::new(
            self.a
                .iter()
                .zip(rhs.a())
                .map(|(&x, &y)| x.add_reduce(y, modulus))
                .collect(),
            self.b.add_reduce(rhs.b, modulus),
        )
    }

    /// Perform component-wise reduce addition of two [`LWE<T>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is not a reference.
    /// If your `self` is a reference, you can use function `add_reduce_component_wise_ref`.
    #[inline]
    pub fn add_reduce_component_wise<M>(mut self, rhs: &Self, modulus: M) -> Self
    where
        T: AddReduceAssign<M>,
        M: Copy,
    {
        self.add_reduce_inplace_component_wise(rhs, modulus);
        self
    }

    /// Performs an in-place component-wise reduce addition
    /// on the `self` [`LWE<T>`] with another `rhs` [`LWE<T>`].
    #[inline]
    pub fn add_reduce_inplace_component_wise<M>(&mut self, rhs: &Self, modulus: M)
    where
        T: AddReduceAssign<M>,
        M: Copy,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        self.a
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v0, &v1)| v0.add_reduce_assign(v1, modulus));
        self.b.add_reduce_assign(rhs.b, modulus);
    }

    /// Perform component-wise subtraction of two [`LWE<T>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is a reference.
    /// If your `self` is not a reference, you can use function `sub_reduce_component_wise`.
    #[inline]
    pub fn sub_reduce_component_wise_ref<M>(&self, rhs: &Self, modulus: M) -> Self
    where
        T: SubReduce<M, Output = T>,
        M: Copy,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        Self::new(
            self.a
                .iter()
                .zip(rhs.a())
                .map(|(&x, &y)| x.sub_reduce(y, modulus))
                .collect(),
            self.b.sub_reduce(rhs.b, modulus),
        )
    }

    /// Perform component-wise subtraction of two [`LWE<T>`].
    ///
    /// # Attention
    ///
    /// In this function, `self` is not a reference.
    /// If your `self` is a reference, you can use function `sub_reduce_component_wise_ref`.
    #[inline]
    pub fn sub_reduce_component_wise<M>(mut self, rhs: &Self, modulus: M) -> Self
    where
        T: SubReduceAssign<M>,
        M: Copy,
    {
        self.sub_reduce_inplace_component_wise(rhs, modulus);
        self
    }

    /// Performs an in-place component-wise subtraction
    /// on the `self` [`LWE<R>`] with another `rhs` [`LWE<R>`].
    #[inline]
    pub fn sub_reduce_inplace_component_wise<M>(&mut self, rhs: &Self, modulus: M)
    where
        T: SubReduceAssign<M>,
        M: Copy,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        self.a
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v0, &v1)| v0.sub_reduce_assign(v1, modulus));
        self.b.sub_reduce_assign(rhs.b, modulus);
    }
}

impl<T: Copy> LWE<T> {
    /// Generate a `LWE<T>` sample which encrypts `0`.
    pub fn generate_zero_sample<M, R>(
        secret_key: &[T],
        modulus_value: T,
        modulus: M,
        error_sampler: DiscreteGaussian<T>,
        mut rng: R,
    ) -> Self
    where
        T: SampleUniform
            + ConstZero
            + MulReduce<M, Output = T>
            + AddReduce<M, Output = T>
            + AsFrom<f64>
            + Sub<Output = T>,
        M: Copy,
        R: Rng + CryptoRng,
    {
        let len = secret_key.len();
        let uniform = Uniform::new(T::ZERO, modulus_value);

        let a: Vec<T> = uniform.sample_iter(&mut rng).take(len).collect();
        let b = a
            .iter()
            .zip(secret_key)
            .fold(T::ZERO, |acc, (&x, &y)| {
                x.mul_reduce(y, modulus).add_reduce(acc, modulus)
            })
            .add_reduce(error_sampler.sample(&mut rng), modulus);
        LWE { a, b }
    }
}
