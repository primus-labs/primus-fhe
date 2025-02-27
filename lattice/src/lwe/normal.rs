use algebra::{
    integer::UnsignedInteger,
    random::DiscreteGaussian,
    reduce::{
        Modulus, ReduceAdd, ReduceAddAssign, ReduceDotProduct, ReduceMulAdd, ReduceMulAssign,
        ReduceNeg, ReduceNegAssign, ReduceSub, ReduceSubAssign,
    },
};
use rand::{distributions::Uniform, prelude::Distribution};

/// Represents a cryptographic structure based on the Learning with Errors (LWE) problem.
/// The LWE problem is a fundamental component in modern cryptography, often used to build
/// secure cryptographic systems that are considered hard to crack by quantum computers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lwe<T: Copy> {
    /// A vector of elements of `T`, representing the public vector part of the LWE instance.
    a: Vec<T>,
    /// An element of `T`, representing the value which is computed as
    /// the dot product of `a` with a secret vector, plus message and some noise.
    b: T,
}

impl<T: Copy> Lwe<T> {
    /// Creates a new [`Lwe<T>`].
    #[inline]
    pub fn new(a: Vec<T>, b: T) -> Self {
        Self { a, b }
    }

    /// Creates a new [`Lwe<T>`] with reference.
    #[inline]
    pub fn from_ref(a: &[T], b: T) -> Self {
        Self { a: a.to_vec(), b }
    }

    /// Returns a reference to the `a` of this [`Lwe<T>`].
    #[inline]
    pub fn a(&self) -> &[T] {
        self.a.as_ref()
    }

    /// Returns a mutable reference to the `a` of this [`Lwe<T>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut Vec<T> {
        &mut self.a
    }

    /// Returns the `b` of this [`Lwe<T>`].
    #[inline]
    pub fn b(&self) -> T {
        self.b
    }

    /// Returns a mutable reference to the `b` of this [`Lwe<T>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut T {
        &mut self.b
    }

    /// Returns the dimension of this [`Lwe<T>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.a.len()
    }

    /// Returns a slice reference to the a of this [`Lwe<T>`].
    #[inline]
    pub fn a_slice(&self) -> &[T] {
        self.a.as_slice()
    }

    /// Returns a mutable slice reference to the a of this [`Lwe<T>`].
    #[inline]
    pub fn a_mut_slice(&mut self) -> &mut [T] {
        self.a.as_mut_slice()
    }
}

impl<T: UnsignedInteger> Lwe<T> {
    /// Generates a [`Lwe<T>`] with all values are `0`.
    #[inline]
    pub fn zero(dimension: usize) -> Self {
        Self {
            a: vec![T::ZERO; dimension],
            b: T::ZERO,
        }
    }

    /// Sets all values to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.a.fill(T::ZERO);
        self.b = T::ZERO;
    }

    /// Perform component-wise reduce addition of two [`Lwe<T>`].
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
        Self::new(
            self.a
                .iter()
                .zip(rhs.a())
                .map(|(&a, &b)| modulus.reduce_add(a, b))
                .collect(),
            modulus.reduce_add(self.b, rhs.b),
        )
    }

    /// Perform component-wise reduce addition of two [`Lwe<T>`].
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
    /// on the `self` [`Lwe<T>`] with another `rhs` [`Lwe<T>`].
    #[inline]
    pub fn add_reduce_assign_component_wise<M>(&mut self, rhs: &Self, modulus: M)
    where
        M: Copy + ReduceAddAssign<T>,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        self.a
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(a, &b)| modulus.reduce_add_assign(a, b));
        modulus.reduce_add_assign(&mut self.b, rhs.b);
    }

    /// Perform component-wise subtraction of two [`Lwe<T>`].
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
        Self::new(
            self.a
                .iter()
                .zip(rhs.a())
                .map(|(&a, &b)| modulus.reduce_sub(a, b))
                .collect(),
            modulus.reduce_sub(self.b, rhs.b),
        )
    }

    /// Perform component-wise subtraction of two [`Lwe<T>`].
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
    /// on the `self` [`Lwe<T>`] with another `rhs` [`Lwe<T>`].
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
        modulus.reduce_sub_assign(&mut self.b, rhs.b);
    }

    /// Performs an in-place scalar multiplication
    /// on the `self` [`Lwe<T>`] with scalar `T`.
    #[inline]
    pub fn mul_scalar_reduce_assign<M>(&mut self, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulAssign<T>,
    {
        self.a
            .iter_mut()
            .for_each(|v| modulus.reduce_mul_assign(v, scalar));
        modulus.reduce_mul_assign(&mut self.b, scalar);
    }

    /// Performs an in-place scalar multiplication
    /// on the `rhs` [`Lwe<T>`] with `scalar` `T`,
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
        self.b = modulus.reduce_mul_add(rhs.b, scalar, self.b);
    }

    /// Performs an negation on the `self` [`Lwe<T>`].
    #[inline]
    pub fn neg_reduce<M>(&self, modulus: M) -> Self
    where
        M: Copy + ReduceNeg<T, Output = T>,
    {
        let a = self.a.iter().map(|&v| modulus.reduce_neg(v)).collect();
        Self::new(a, modulus.reduce_neg(self.b))
    }

    /// Performs an negation on the `self` [`Lwe<T>`].
    #[inline]
    pub fn neg_reduce_assign<M>(&mut self, modulus: M)
    where
        M: Copy + ReduceNegAssign<T>,
    {
        self.a.iter_mut().for_each(|v| modulus.reduce_neg_assign(v));
        modulus.reduce_neg_assign(&mut self.b)
    }

    /// Generate a [`Lwe<T>`] sample which encrypts `0`.
    #[inline]
    pub fn generate_random_zero_sample<M, R>(
        secret_key: &[T],
        modulus: M,
        gaussian: DiscreteGaussian<T>,
        rng: &mut R,
    ) -> Self
    where
        M: Copy + Modulus<T> + ReduceDotProduct<T, Output = T> + ReduceAdd<T, Output = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let len = secret_key.len();
        let uniform = Uniform::new_inclusive(T::ZERO, modulus.modulus_minus_one());

        let a: Vec<T> = uniform.sample_iter(&mut *rng).take(len).collect();
        let e = gaussian.sample(rng);

        let b = modulus.reduce_dot_product(a.as_slice(), secret_key);
        let b = modulus.reduce_add(b, e);

        Lwe { a, b }
    }
}
