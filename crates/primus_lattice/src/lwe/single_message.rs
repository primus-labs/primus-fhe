use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::{FheUint, Size};
use primus_reduce::prelude::*;

/// An LWE ciphertext with mask `a` followed by one scalar body `b`.
///
/// Storage has length `n + 1`; its phase under a length-`n` secret `s` is
/// `b - <a, s>`. The body is required even for a zero-dimensional raw sample.
///
/// The optional `serde` feature serializes the backing storage `S` only.
/// Deserialization does not validate the layout or supply parameter/key metadata.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Lwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(Lwe);
impl_iters!(Lwe);
impl_bytes_io!(Lwe);

impl_basic_operation_single_modulus!(Lwe);
impl_neg_single_modulus!(Lwe);
impl_mul_scalar_single_modulus!(Lwe);
impl_mul_factor_single_modulus!(Lwe);

impl<S, T> Lwe<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Generates a [`Lwe`] with all values are `0`.
    ///
    /// # Correctness
    ///
    /// `dimension + 1` must fit in `usize`. This allocates zero storage; it does
    /// not sample a randomized encryption.
    #[must_use]
    #[inline]
    pub fn zero(dimension: usize) -> Self {
        Self(S::from_vec(vec![T::ZERO; dimension + 1]))
    }
}

impl<S, T> Lwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Returns a mutable reference to the `a` of this [`Lwe`].
    ///
    /// # Panics
    ///
    /// Panics if storage is empty (the body is missing).
    #[inline]
    pub fn a_mut(&mut self) -> &mut [T] {
        self.0.as_mut_slice().split_last_mut().unwrap().1
    }

    /// Returns a mutable reference to the `b` of this [`Lwe`].
    ///
    /// # Panics
    ///
    /// Panics if storage is empty (the body is missing).
    #[inline]
    pub fn b_mut(&mut self) -> &mut T {
        self.0.as_mut_slice().last_mut().unwrap()
    }

    /// Returns mutable references to `a` and `b` of this [`Lwe`].
    ///
    /// # Panics
    ///
    /// Panics if storage is empty (the body is missing).
    #[inline]
    pub fn a_b_mut(&mut self) -> (&mut [T], &mut T) {
        let (b, a) = self.0.as_mut_slice().split_last_mut().unwrap();
        (a, b)
    }

    /// Sets all values to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.0.fill(T::ZERO);
    }
}

impl<S, T> Lwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Returns a reference to the `a` of this [`Lwe`].
    ///
    /// # Panics
    ///
    /// Panics if storage is empty (the body is missing).
    #[inline]
    pub fn a(&self) -> &[T] {
        self.0.as_slice().split_last().unwrap().1
    }

    /// Returns the `b` of this [`Lwe`].
    ///
    /// # Panics
    ///
    /// Panics if storage is empty (the body is missing).
    #[inline]
    pub fn b(&self) -> T {
        *self.0.as_slice().last().unwrap()
    }

    /// Returns a reference to `a` and the value of `b` of this LWE sample.
    ///
    /// # Panics
    ///
    /// Panics if storage is empty (the body is missing).
    pub fn a_b(&self) -> (&[T], T) {
        let (b, a) = self.0.as_slice().split_last().unwrap();
        (a, *b)
    }

    /// Returns the dimension of this [`Lwe`].
    ///
    /// # Correctness
    ///
    /// Storage must contain at least the body element. Empty raw storage is not
    /// a valid LWE ciphertext.
    #[inline]
    pub fn dimension(&self) -> usize {
        self.0.len() - 1
    }

    /// Returns the stored coefficient count, including the body.
    /// For a valid ciphertext this is `dimension() + 1`, suitable for
    /// [`super::LweIter::new`] and [`super::LweIterMut::new`].
    #[must_use]
    #[inline]
    pub fn lwe_len(&self) -> usize {
        self.0.len()
    }
}

impl<S, T> Lwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Consumes this ciphertext and negates it, reusing its backing storage.
    ///
    /// # Correctness
    ///
    /// Coefficients must satisfy the input range required by `modulus`.
    #[must_use]
    #[inline]
    pub fn neg<M>(mut self, modulus: M) -> Self
    where
        M: Copy + ReduceNegSlice<T>,
    {
        self.neg_assign(modulus);
        self
    }
}

impl<S, T> Size for Lwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    #[inline]
    fn byte_count(&self) -> usize {
        self.0.len() * T::BYTES
    }
}

impl<S, T> Lwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Adds an already encoded canonical plaintext to `b`, preserving the mask.
    ///
    /// # Correctness
    ///
    /// The plaintext must use the ciphertext modulus and scale; no encoding occurs.
    ///
    /// # Panics
    ///
    /// Panics if storage is empty (the body is missing).
    #[inline]
    pub fn add_plaintext_assign<M>(&mut self, plaintext: T, modulus: M)
    where
        M: ReduceAddAssign<T>,
    {
        modulus.reduce_add_assign(self.b_mut(), plaintext);
    }

    /// Subtracts an already encoded canonical plaintext from `b`, preserving the mask.
    ///
    /// # Correctness
    ///
    /// The plaintext must use the ciphertext modulus and scale; no encoding occurs.
    ///
    /// # Panics
    ///
    /// Panics if storage is empty (the body is missing).
    #[inline]
    pub fn sub_plaintext_assign<M>(&mut self, plaintext: T, modulus: M)
    where
        M: ReduceSubAssign<T>,
    {
        modulus.reduce_sub_assign(self.b_mut(), plaintext);
    }

    /// Overwrites the ciphertext with a zero mask and an already encoded body.
    ///
    /// # Correctness
    ///
    /// The plaintext must be canonical in the ciphertext modulus and scale.
    /// This performs no encoding, random sampling or allocation.
    ///
    /// # Panics
    ///
    /// Panics if storage is empty (the body is missing).
    #[inline]
    pub fn set_trivial(&mut self, plaintext: T) {
        let (a, b) = self.a_b_mut();
        a.fill(T::ZERO);
        *b = plaintext;
    }
}
