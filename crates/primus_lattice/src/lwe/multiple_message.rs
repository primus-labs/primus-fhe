use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::{FheUint, Size};
use primus_reduce::prelude::*;

use super::Lwe;

/// Packed LWE samples sharing publicly signed rotations of one mask.
///
/// Storage contains a length-`N` mask followed by bodies `b[0..count]`.
/// Sample j uses its signed right rotation by j positions. This includes RLWE
/// samples whose mask is in constant-term extraction order, as well as directly
/// encrypted packed LWE samples. The dimension and body count are supplied by
/// the caller; direct LWE use does not require a power-of-two dimension. This
/// layout cannot represent multiple GLWE masks.
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
pub struct MultiMsgLwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(MultiMsgLwe);
impl_iters!(MultiMsgLwe);
impl_bytes_io!(MultiMsgLwe);

impl_basic_operation_single_modulus!(MultiMsgLwe);
impl_neg_single_modulus!(MultiMsgLwe);
impl_mul_scalar_single_modulus!(MultiMsgLwe);
impl_mul_factor_single_modulus!(MultiMsgLwe);

impl<S, T> MultiMsgLwe<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Generates a [`MultiMsgLwe`] with all values are `0`.
    ///
    /// # Correctness
    ///
    /// `dimension` is the shared nonzero LWE mask length; for RLWE-derived
    /// samples it equals the original polynomial length. `msg_count` is at most
    /// `dimension`, and their sum must fit in `usize`. This allocates zero
    /// storage without sampling a randomized encryption.
    #[must_use]
    #[inline]
    pub fn zero(dimension: usize, msg_count: usize) -> Self {
        Self(S::from_vec(vec![T::ZERO; dimension + msg_count]))
    }
}

impl<S, T> MultiMsgLwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Returns mutable references to `a` and `b` of this [`MultiMsgLwe`].
    ///
    /// # Correctness
    ///
    /// `dimension` is the shared LWE mask length, separating it from the bodies.
    /// For RLWE-derived samples it equals the original polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if `dimension` exceeds the total storage length.
    #[inline]
    pub fn a_b_mut(&mut self, dimension: usize) -> (&mut [T], &mut [T]) {
        self.0.split_at_mut(dimension)
    }

    /// Sets all values to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.0.fill(T::ZERO);
    }
}

impl<S, T> MultiMsgLwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Returns references to `a` and `b` of this [`MultiMsgLwe`].
    ///
    /// # Correctness
    ///
    /// `dimension` is the shared LWE mask length, separating it from the bodies.
    /// For RLWE-derived samples it equals the original polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if `dimension` exceeds the total storage length.
    #[inline]
    pub fn a_b(&self, dimension: usize) -> (&[T], &[T]) {
        self.0.split_at(dimension)
    }

    /// Allocates the sample for body coefficient `index`.
    /// `dimension` is the common mask length; `index` must be less than both
    /// `dimension` and the retained body count. For RLWE-derived samples the
    /// stored mask must already be in constant-term extraction order.
    ///
    /// # Correctness
    ///
    /// The stored values must be canonical under `modulus` and satisfy the
    /// shared-secret signed-rotation layout described on the type. For
    /// RLWE-derived samples the key is the original ring secret coefficient vector.
    /// The strict `index < dimension` requirement is not validated in release;
    /// `index == dimension` can produce an incorrect sample without panicking.
    ///
    /// # Panics
    ///
    /// Panics if the requested mask/body slice is out of bounds or the
    /// rotation exceeds `dimension`. These checks do not validate the
    /// shared-mask layout.
    #[must_use]
    #[inline]
    pub fn extract_lwe_at<M>(&self, index: usize, dimension: usize, modulus: M) -> Lwe<Vec<T>>
    where
        M: Copy + ReduceNegSlice<T>,
    {
        let mut data = self.as_ref()[..dimension + 1].to_vec();
        if index != 0 {
            data[..dimension].rotate_right(index);
            modulus.reduce_neg_slice_assign(&mut data[..index]);
            data[dimension] = self.as_ref()[dimension + index];
        }
        Lwe::new(data)
    }

    /// Allocates all samples, with `msg_count` specifying the exact retained
    /// body count. The remaining storage is the shared mask.
    ///
    /// # Correctness
    ///
    /// `msg_count` must be the actual retained body count. The remaining
    /// storage is the shared mask in the type's signed-rotation layout. Values
    /// must be canonical under `modulus`. All output samples use the same
    /// LWE secret (the original ring secret coefficient vector for RLWE extraction).
    ///
    /// # Panics
    ///
    /// Panics if `msg_count` is zero or exceeds the LWE dimension.
    #[must_use]
    #[inline]
    pub fn extract_all<M>(&self, msg_count: usize, modulus: M) -> Vec<Lwe<Vec<T>>>
    where
        M: Copy + ReduceNegAssign<T>,
    {
        assert!(
            (1..=self.0.len() / 2).contains(&msg_count),
            "message count must be positive and not exceed the LWE dimension"
        );

        let dimension = self.0.len() - msg_count;
        let mut output = Vec::with_capacity(msg_count);

        let mut data = self.as_ref()[..dimension + 1].to_vec();
        self.as_ref()[dimension + 1..].iter().for_each(|&b| {
            let lwe = Lwe::new(data.clone());
            output.push(lwe);

            data[..dimension].rotate_right(1);
            modulus.reduce_neg_assign(&mut data[0]);
            data[dimension] = b;
        });
        output.push(Lwe::new(data));

        output
    }
}

impl<S, T> Size for MultiMsgLwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    #[inline]
    fn byte_count(&self) -> usize {
        self.0.len() * T::BYTES
    }
}
