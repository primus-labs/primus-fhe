//! Shared coefficient storage for sparse GLWE bootstrapping.

use primus_glwe::GgswParameters;
use primus_integer::FheUint;
use primus_lattice::{LweDimension, ggsw::GgswIter};
use primus_reduce::{Modulus, RingContext};
use primus_tfhe::sparse::BucketMap;

use crate::{GlweBlindRotationControls, SparseBootstrappingKeyError};

/// Coefficient-domain GGSW selections for sparse blind rotation shared by the GLWE backends.
///
/// Each input index appears in `copy_count` distinct public buckets. Encrypted
/// selections cover each nonzero small-LWE coefficient exactly once and select
/// at most one entry per bucket. Every bucket also contains an independently
/// encrypted dummy: one for an unoccupied bucket, zero otherwise.
///
/// Generation retains only the public mapping and ciphertexts, never the support
/// or matching. Input modulus q is retained as numerical metadata; the accumulator uses `M`. NTT backends
/// use explicit residues and Fourier backends use native-torus coefficients.
/// These domains are not interchangeable. Fourier generation constructs exact
/// native coefficient rows directly; rounding starts when evaluation transforms them.
///
/// Successful mapping conditions the joint distribution of the public map and
/// secret. Fixed-weight security and complete PBS noise bounds need independent
/// assessment; eight retries do not establish a security level.
pub struct SparseGlweBootstrappingKey<T: FheUint, M: RingContext<T>> {
    controls: GlweBlindRotationControls<T, M>,
    map: BucketMap,
    hamming_weight: usize,
}

impl<T: FheUint, M: RingContext<T>> SparseGlweBootstrappingKey<T, M> {
    /// Takes ownership of coefficient GGSWs and their already validated public map.
    /// Retains the parameters' layout, modulus and a copy of their gadget basis;
    /// no sampler state, secret assignment or transform table is retained.
    /// The coefficient buffer is moved without copying or transforming it.
    ///
    /// # Correctness
    /// Coefficients must be canonical under the parameters' modulus.
    /// Each GGSW must use these parameters' modulus, gadget scales and accumulator
    /// secret. The private assignment must cover every nonzero input exactly once,
    /// with one additional encrypted dummy last in every bucket.
    ///
    /// # Errors
    /// Rejects a weight outside 0<h<n, too few buckets, an overflowing storage
    /// size, 2N not representable by T, or a coefficient count different from
    /// the map and GGSW layout.
    pub fn try_new<LM: Modulus<ValueT = T>>(
        data: Vec<T>,
        map: BucketMap,
        hamming_weight: usize,
        parameters: &GgswParameters<T, M>,
        input_modulus: LM,
    ) -> Result<Self, SparseBootstrappingKeyError> {
        use SparseBootstrappingKeyError as Error;
        let dimension = map.input_dimension();
        if hamming_weight == 0 || hamming_weight >= dimension {
            return Err(Error::InvalidHammingWeight);
        }
        if hamming_weight > map.bucket_count() {
            return Err(primus_tfhe::sparse::BucketMapError::InvalidBucketParameters.into());
        }
        let control_count = map
            .input_indices()
            .len()
            .checked_add(map.bucket_count())
            .ok_or(Error::StorageSizeOverflow)?;
        let controls = GlweBlindRotationControls::try_new(
            data,
            LweDimension::new(dimension),
            control_count,
            parameters,
            input_modulus,
        )?;
        Ok(Self {
            controls,
            map,
            hamming_weight,
        })
    }

    /// Borrows coefficient controls and their common numerical layout.
    #[must_use]
    #[inline]
    pub fn controls(&self) -> &GlweBlindRotationControls<T, M> {
        &self.controls
    }

    /// Returns the dimension of the actual blind-rotation input secret.
    #[must_use]
    #[inline]
    pub fn input_dimension(&self) -> LweDimension {
        self.controls.input_dimension()
    }

    /// Returns the public, fixed weight of the input binary secret.
    #[must_use]
    pub fn hamming_weight(&self) -> usize {
        self.hamming_weight
    }

    /// Returns the number of distinct buckets containing each input index.
    #[must_use]
    pub fn copy_count(&self) -> usize {
        self.map.copy_count()
    }

    /// Returns the total number of buckets, including unoccupied buckets.
    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.map.bucket_count()
    }

    /// Borrows one bucket's increasing input indices and coefficient GGSWs.
    ///
    /// Ciphertexts follow the indices, with **one additional dummy last**.
    /// A bucket without public entries still returns its dummy ciphertext.
    /// This view contains no plaintext selection or occupancy information.
    ///
    /// # Panics
    ///
    /// Panics if `bucket_index >= self.bucket_count()`.
    #[must_use]
    pub fn bucket(&self, bucket_index: usize) -> (&[usize], GgswIter<'_, T>) {
        let (indices, ciphertexts) = self.bucket_data(bucket_index);
        (
            indices,
            GgswIter::new(ciphertexts, self.controls.size().ggsw_len()),
        )
    }

    /// Borrows a bucket's indices and contiguous GGSW storage, including its final
    /// dummy. Splitting the dummy off allows aggregation to start with a copy.
    ///
    /// # Panics
    /// Panics if `bucket_index >= self.bucket_count()`.
    #[must_use]
    pub fn bucket_data(&self, bucket_index: usize) -> (&[usize], &[T]) {
        assert!(
            bucket_index < self.bucket_count(),
            "sparse bucket index out of bounds"
        );
        let start = self.map.bucket_offsets()[bucket_index];
        let end = self.map.bucket_offsets()[bucket_index + 1];
        let ggsw_len = self.controls.size().ggsw_len();
        let ciphertexts = &self.controls.as_slice()
            [(start + bucket_index) * ggsw_len..(end + bucket_index + 1) * ggsw_len];
        (&self.map.input_indices()[start..end], ciphertexts)
    }
}
