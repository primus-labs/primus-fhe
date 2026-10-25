//! Hybrid RNS basis extension, decomposition, and reduction.
//!
//! [`HybridRNS`] splits the ciphertext basis `Q` into non-empty contiguous
//! partitions. Each [`HybridRNSPartition`] owns the precomputation for the
//! approximate basis extension from that partition to its complement and the
//! auxiliary basis `P`. The resulting digits live in the combined `QP` basis.
//! `decomposition_count` (`dnum`) is the exact number of digits in the full
//! `Q` basis, `partition_moduli_count` (`alpha`) is the fixed maximum number of
//! `Q` moduli in a digit, and `partition_count` (`beta`) is the number of
//! non-empty digits at the active level.
//!
//! [`HybridRNSPartitioning`] fixes `alpha` from the full `Q` basis so shorter
//! levels in the same modulus chain keep a key-compatible partition layout.
//! A [`HybridRNS`] instance contains the bases and conversion precomputations
//! for exactly one active `Q` level.
//!
//! The polynomial APIs use modulus-major storage and caller-owned scratch
//! buffers. The streaming ModUp API lets higher-level key-switching code reuse
//! partition limbs and consume converted complement limbs without allocating a
//! complete `QP` digit.
//!
//! # References
//!
//! - OpenFHE `KeySwitchHYBRID` and `DCRTPoly::ApproxModDown`
//! - SEAL `BaseConverter`

use core::{num::NonZeroUsize, range::Range};

mod construction;
mod mod_down;
mod mod_up;

use primus_integer::FheUint;
use primus_reduce::FieldContext;

use crate::{BaseConverter, RNSBase, RnsError};

/// A partitioning rule shared by compatible hybrid-RNS levels.
///
/// Hybrid key-switching keys fix the maximum number of full-`Q` moduli in one
/// partition (`alpha`). Active modulus-chain levels must reuse that value
/// instead of recomputing it from their shorter `Q` basis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HybridRNSPartitioning {
    full_q_moduli_count: NonZeroUsize,
    decomposition_count: NonZeroUsize,
    partition_moduli_count: NonZeroUsize,
}

impl HybridRNSPartitioning {
    /// Derives a fixed partitioning rule from a full `Q` basis and requested
    /// decomposition digit count (`dnum`).
    ///
    /// The fixed partition size is
    /// `ceil(full_q_moduli_count / decomposition_count)`. As in OpenFHE, the
    /// requested count must produce exactly that many non-empty, contiguous
    /// partitions; unsupported counts are rejected rather than silently
    /// producing fewer partitions.
    ///
    /// # Errors
    ///
    /// Returns [`RnsError::EmptyBase`] when `full_q_moduli_count` is zero.
    /// Returns [`RnsError::InvalidDecompositionCount`] when
    /// `decomposition_count` is zero, or
    /// [`RnsError::IncompatibleDecompositionCount`] when the fixed partition
    /// size cannot produce exactly the requested number of digits.
    pub fn new(full_q_moduli_count: usize, decomposition_count: usize) -> Result<Self, RnsError> {
        let full_q_moduli_count =
            NonZeroUsize::new(full_q_moduli_count).ok_or(RnsError::EmptyBase)?;
        let decomposition_count =
            NonZeroUsize::new(decomposition_count).ok_or(RnsError::InvalidDecompositionCount)?;
        let partition_moduli_count = full_q_moduli_count.div_ceil(decomposition_count);
        let actual_partition_count = full_q_moduli_count.div_ceil(partition_moduli_count);
        if actual_partition_count != decomposition_count {
            return Err(RnsError::IncompatibleDecompositionCount {
                q_moduli_count: full_q_moduli_count.get(),
                decomposition_count: decomposition_count.get(),
            });
        }

        Ok(Self {
            full_q_moduli_count,
            decomposition_count,
            partition_moduli_count,
        })
    }

    /// Returns the full-`Q` modulus count used to derive this rule.
    #[must_use]
    #[inline]
    pub fn full_q_moduli_count(self) -> usize {
        self.full_q_moduli_count.get()
    }

    /// Returns the exact number of decomposition digits in the full `Q` basis.
    #[must_use]
    #[inline]
    pub fn decomposition_count(self) -> usize {
        self.decomposition_count.get()
    }

    /// Returns the fixed maximum number of `Q` moduli per partition (`alpha`).
    #[must_use]
    #[inline]
    pub fn partition_moduli_count(self) -> usize {
        self.partition_moduli_count.get()
    }
}

/// One non-empty, contiguous partition of the ciphertext basis `Q`.
#[derive(Clone)]
pub struct HybridRNSPartition<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    q_range: Range<usize>,
    q_moduli_count: usize,
    mod_up_converter: BaseConverter<T, M>,
}

/// Precomputed bases and converters for one active hybrid-RNS level.
#[derive(Clone)]
pub struct HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    q_base: RNSBase<T, M>,
    p_base: RNSBase<T, M>,
    qp_base: RNSBase<T, M>,
    partitioning: HybridRNSPartitioning,
    partitions: Vec<HybridRNSPartition<T, M>>,
    p_mod_q: Vec<T>,
    inv_p_mod_q: Vec<T>,
    mod_down_converter: BaseConverter<T, M>,
}

impl<T, M> HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Returns the ciphertext basis `Q`.
    #[inline]
    pub fn q_base(&self) -> &RNSBase<T, M> {
        &self.q_base
    }

    /// Returns the auxiliary basis `P`.
    #[inline]
    pub fn p_base(&self) -> &RNSBase<T, M> {
        &self.p_base
    }

    /// Returns the combined basis in `Q || P` order.
    #[inline]
    pub fn qp_base(&self) -> &RNSBase<T, M> {
        &self.qp_base
    }

    /// Returns the number of moduli in `Q`.
    #[inline]
    pub fn q_moduli_count(&self) -> usize {
        self.q_base.moduli_count()
    }

    /// Returns the number of moduli in `P`.
    #[inline]
    pub fn p_moduli_count(&self) -> usize {
        self.p_base.moduli_count()
    }

    /// Returns the number of moduli in `QP`.
    #[inline]
    pub fn qp_moduli_count(&self) -> usize {
        self.qp_base.moduli_count()
    }

    /// Returns the partitioning rule shared by compatible modulus-chain levels.
    #[must_use]
    #[inline]
    pub fn partitioning(&self) -> HybridRNSPartitioning {
        self.partitioning
    }

    /// Returns the exact full-`Q` decomposition digit count (`dnum`).
    ///
    /// [`partition_count`](Self::partition_count) equals this value at the full
    /// level and can be smaller at a shorter active level.
    #[inline]
    pub fn decomposition_count(&self) -> usize {
        self.partitioning.decomposition_count()
    }

    /// Returns the maximum number of `Q` moduli per partition (`alpha`).
    #[inline]
    pub fn partition_moduli_count(&self) -> usize {
        self.partitioning.partition_moduli_count()
    }

    /// Iterates over the non-empty `Q` partitions in basis order.
    #[inline]
    pub fn partitions(&self) -> impl ExactSizeIterator<Item = &HybridRNSPartition<T, M>> {
        self.partitions.iter()
    }

    /// Returns the actual number of non-empty partitions.
    #[inline]
    pub fn partition_count(&self) -> usize {
        self.partitions.len()
    }

    /// Returns the largest minimum ModUp scratch length among all partitions.
    #[inline]
    pub fn max_mod_up_scratch_len(&self, poly_length: usize) -> usize {
        self.partitions
            .iter()
            .map(|partition| partition.mod_up_scratch_len(poly_length))
            .max()
            .unwrap_or(0)
    }

    /// Returns the minimum scratch length required by polynomial ModDown.
    #[inline]
    pub fn mod_down_scratch_len(&self, poly_length: usize) -> usize {
        self.mod_down_converter
            .fast_convert_array_scratch_len(poly_length)
    }

    /// Returns `P mod q_i` in `Q`-basis order.
    #[inline]
    pub fn p_mod_q(&self) -> &[T] {
        &self.p_mod_q
    }

    /// Returns `P^-1 mod q_i` in `Q`-basis order.
    #[inline]
    pub fn inv_p_mod_q(&self) -> &[T] {
        &self.inv_p_mod_q
    }
}

impl<T, M> HybridRNSPartition<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Returns the indices of this partition in the active `Q` basis.
    #[must_use]
    #[inline]
    pub fn q_range(&self) -> Range<usize> {
        self.q_range
    }

    /// Returns the number of active `Q` moduli in this partition.
    #[must_use]
    #[inline]
    pub fn moduli_count(&self) -> usize {
        self.q_range.end - self.q_range.start
    }
}
