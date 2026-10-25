//! Shared coefficient storage for sparse NTRU bootstrapping.

use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_ntru::NlevParameters;
use primus_tfhe::sparse::BucketMap;
use std::alloc::Layout;

use crate::SparseBootstrappingKeyError;

/// Coefficient selectors and public buckets for a fixed-weight binary client.
/// Bucket zero uses NLEV bits for public-LUT lifting; later buckets use NGSW bits.
///
/// Each nonzero input is privately assigned to exactly one of its public copies.
/// Each bucket has an independently encrypted dummy, one when unoccupied and zero
/// otherwise. Only ciphertexts and the public map remain after generation.
/// The backend BR owner carries the common basis and modulus; this storage does
/// not make NTT and native-torus coefficients interchangeable.
/// Sparse evaluation needs no separate NLEV initializer.
///
/// The external secret is sampled without NTRU rejection; only the accumulator
/// secret undergoes invertibility (and Fourier stability) screening. The public
/// map is conditioned on successful matching to the fixed external secret.
/// These conditions need independent security analysis; no failure rate is certified.
pub struct SparseNtruBootstrappingKey<T: FheUint> {
    data: Vec<T>,
    map: BucketMap,
    input_dimension: LweDimension,
    hamming_weight: usize,
    control_len: usize,
}

impl<T: FheUint> SparseNtruBootstrappingKey<T> {
    /// Takes ownership of coefficient controls and their already validated public map.
    /// Uses the parameters' N*L layout without retaining or copying their basis.
    /// No encryption, transform, coefficient scan or allocation is performed.
    ///
    /// # Correctness
    /// Coefficients must be canonical under the parameters' modulus.
    /// Controls must use these parameters' modulus, gadget scales and accumulator
    /// secret: NLEV bits in bucket zero, NGSW bits thereafter, with a dummy last.
    /// Their private assignment must cover each nonzero input exactly once.
    /// The backend BR owner must retain the same basis and modulus. Fourier keys
    /// recovered to coefficients retain their conversion and rounding error.
    ///
    /// # Errors
    /// Rejects a weight outside 0<h<n, too few buckets, an overflowing storage
    /// size or a coefficient count different from the map and N*L layout.
    pub fn try_new<M: primus_reduce::RingContext<T>>(
        data: Vec<T>,
        map: BucketMap,
        hamming_weight: usize,
        parameters: &NlevParameters<T, M>,
    ) -> Result<Self, SparseBootstrappingKeyError> {
        use SparseBootstrappingKeyError as Error;
        let dimension = map.input_dimension();
        if hamming_weight == 0 || hamming_weight >= dimension {
            return Err(Error::InvalidHammingWeight);
        }
        if hamming_weight > map.bucket_count() {
            return Err(primus_tfhe::sparse::BucketMapError::InvalidBucketParameters.into());
        }
        let control_len = parameters.nlev_len();
        let expected = map
            .input_indices()
            .len()
            .checked_add(map.bucket_count())
            .and_then(|count| count.checked_mul(control_len))
            .ok_or(Error::StorageSizeOverflow)?;
        Layout::array::<T>(expected).map_err(|_| Error::StorageSizeOverflow)?;
        if data.len() != expected {
            return Err(Error::StorageLengthMismatch {
                expected,
                actual: data.len(),
            });
        }
        Ok(Self {
            data,
            map,
            input_dimension: LweDimension::new(dimension),
            hamming_weight,
            control_len,
        })
    }

    /// Returns N*L coefficient values per NLEV or NGSW control.
    #[must_use]
    pub fn control_len(&self) -> usize {
        self.control_len
    }

    /// Returns the external LWE dimension.
    #[must_use]
    pub fn input_dimension(&self) -> LweDimension {
        self.input_dimension
    }

    /// Returns the declared number of nonzero binary input coefficients.
    #[must_use]
    pub fn hamming_weight(&self) -> usize {
        self.hamming_weight
    }

    /// Returns the number of distinct buckets containing every input index.
    #[must_use]
    pub fn copy_count(&self) -> usize {
        self.map.copy_count()
    }

    /// Returns the number of public buckets, including empty ones.
    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.map.bucket_count()
    }

    /// Returns `[bucket][entry...,dummy][level][coefficient]` storage.
    /// Bucket zero contains NLEV controls; later buckets contain NGSW controls.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Borrows raw coefficient controls for aggregation, with a dummy last.
    /// Bucket zero is NLEV and later buckets are NGSW; their coefficient layouts
    /// agree, so aggregation can consume the same contiguous view.
    ///
    /// # Panics
    /// Panics if `bucket >= self.bucket_count()`.
    #[must_use]
    pub fn bucket_data(&self, bucket: usize) -> (&[usize], &[T]) {
        assert!(
            bucket < self.bucket_count(),
            "sparse bucket index out of bounds"
        );
        let start = self.map.bucket_offsets()[bucket];
        let end = self.map.bucket_offsets()[bucket + 1];
        (
            &self.map.input_indices()[start..end],
            &self.data[(start + bucket) * self.control_len..(end + bucket + 1) * self.control_len],
        )
    }
}
