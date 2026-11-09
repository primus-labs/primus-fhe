//! Public bucket maps and private matching for fixed-weight sparse PBS.
//!
//! This module only assigns input indices to buckets; ciphertext layout, secret
//! distribution validation and encryption belong to the consuming backend.

use std::alloc::Layout;

use rand::distr::{Distribution, Uniform};
use zeroize::Zeroizing;

/// Failure to sample and match a sparse bucket map.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BucketMapError {
    /// At least one copy and enough buckets for copies and nonzero inputs are required.
    #[error("mapping requires copy_count >= 1 and bucket_count >= max(copy_count, nonzero_count)")]
    InvalidBucketParameters,
    /// Nonzero input indices must be strictly increasing and below the input dimension.
    #[error("nonzero indices must be strictly increasing and less than input_dimension")]
    InvalidNonzeroIndices,
    /// Mapping buffers exceed addressable allocation sizes.
    #[error("bucket-map storage size overflow")]
    StorageSizeOverflow,
    /// None of eight independently sampled maps admitted a complete matching.
    #[error("sparse support matching failed after eight attempts")]
    MatchingFailed,
}

/// No assignment or no visited predecessor. Valid indices fit checked allocations.
const EMPTY: usize = usize::MAX;
const MAX_ATTEMPTS: usize = 8;

/// Public mapping from buckets to input coefficient indices.
///
/// Each input index occurs in `copy_count` distinct buckets, including indices
/// whose secret coefficient is zero. No private matching information is retained.
pub struct BucketMap {
    /// Bucket `j` occupies `input_indices[bucket_offsets[j]..bucket_offsets[j+1]]`.
    /// There are `bucket_count + 1` offsets; the last is `input_indices.len()`.
    bucket_offsets: Vec<usize>,
    /// Original input coefficient indices, increasing within each bucket.
    input_indices: Vec<usize>,
    /// Each input occurs this many times; also recovers the original dimension.
    copy_count: usize,
}

impl BucketMap {
    /// Sentinel in the private assignment for a bucket with no selected input.
    pub const UNASSIGNED: usize = EMPTY;

    /// Returns the original input dimension, including zero-secret coefficients.
    /// Generation checks the complete input-by-copy product, so this quotient is exact.
    #[must_use]
    pub fn input_dimension(&self) -> usize {
        self.input_indices.len() / self.copy_count
    }

    /// Returns the number of distinct public buckets containing each input index.
    #[must_use]
    pub fn copy_count(&self) -> usize {
        self.copy_count
    }

    /// Returns the number of public buckets, including empty ones.
    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.bucket_offsets.len() - 1
    }

    /// Returns offsets delimiting each bucket in [`Self::input_indices`].
    /// Bucket `j` occupies `offsets[j]..offsets[j + 1]`; the final offset equals
    /// the number of entries. Empty buckets have equal consecutive offsets.
    #[must_use]
    pub fn bucket_offsets(&self) -> &[usize] {
        &self.bucket_offsets
    }

    /// Returns the original input indices, increasing within each bucket.
    #[must_use]
    pub fn input_indices(&self) -> &[usize] {
        &self.input_indices
    }

    /// Samples a public bucket map and privately assigns every nonzero coefficient.
    ///
    /// `nonzero_indices` contains the increasing indices `i` where the binary
    /// input secret has `s[i] == 1`; its length is the Hamming weight. Each input
    /// index, including those outside this list, samples `copy_count` distinct
    /// buckets uniformly. Only the map is resampled on matching failure.
    ///
    /// Returns the public map and a private array indexed by bucket: each entry
    /// is the selected original input index, or [`Self::UNASSIGNED`] for an
    /// unoccupied bucket. This array contains secret information and is erased
    /// on drop; do not retain it in a public key.
    /// Returns an error after eight failed maps; the input secret is unchanged.
    ///
    /// Success conditions the public map on the supplied secret indices. This
    /// local key-generation procedure is not constant-time; successful matching
    /// and the retry bound do not certify security or a PBS failure probability.
    ///
    /// # Errors
    ///
    /// Rejects invalid copy/bucket counts, unordered, duplicate or out-of-range
    /// nonzero indices, and storage overflow before sampling. Eight failed maps
    /// return [`BucketMapError::MatchingFailed`] without a partial assignment.
    pub fn try_generate<R>(
        input_dimension: usize,
        copy_count: usize,
        bucket_count: usize,
        nonzero_indices: &[usize],
        rng: &mut R,
    ) -> Result<(Self, Zeroizing<Vec<usize>>), BucketMapError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        if copy_count == 0 || bucket_count < copy_count.max(nonzero_indices.len()) {
            return Err(BucketMapError::InvalidBucketParameters);
        }
        if nonzero_indices
            .last()
            .is_some_and(|&index| index >= input_dimension)
            || nonzero_indices.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(BucketMapError::InvalidNonzeroIndices);
        }
        let entry_count = input_dimension
            .checked_mul(copy_count)
            .ok_or(BucketMapError::StorageSizeOverflow)?;
        let offsets_len = bucket_count
            .checked_add(1)
            .ok_or(BucketMapError::StorageSizeOverflow)?;
        Layout::array::<usize>(entry_count).map_err(|_| BucketMapError::StorageSizeOverflow)?;
        Layout::array::<usize>(offsets_len).map_err(|_| BucketMapError::StorageSizeOverflow)?;

        let bucket_distribution = Uniform::new(0, bucket_count).expect("validated bucket count");
        Self::generate_with(
            input_dimension,
            copy_count,
            bucket_count,
            nonzero_indices,
            |candidate_buckets| {
                for input_buckets in candidate_buckets.chunks_exact_mut(copy_count) {
                    for copy_index in 0..copy_count {
                        loop {
                            let bucket_index = bucket_distribution.sample(rng);
                            if !input_buckets[..copy_index].contains(&bucket_index) {
                                input_buckets[copy_index] = bucket_index;
                                break;
                            }
                        }
                    }
                }
            },
        )
    }

    /// Tries up to eight sampled graphs using one matching workspace and fixed
    /// nonzero coefficient indices. Converts the successful graph to bucket-major
    /// storage only after all nonzero coefficients have been assigned.
    ///
    /// The sampler overwrites an input-major `[input_index][copy_index]` array:
    /// each row has `copy_count` distinct bucket IDs in `0..bucket_count`.
    /// Production sampling must be independent across inputs and attempts; the
    /// callback also lets tests supply graphs with known matching failures.
    /// Other input requirements and the returned private array match [`Self::try_generate`].
    fn generate_with(
        input_dimension: usize,
        copy_count: usize,
        bucket_count: usize,
        nonzero_indices: &[usize],
        mut sample: impl FnMut(&mut [usize]),
    ) -> Result<(Self, Zeroizing<Vec<usize>>), BucketMapError> {
        let mut candidate_buckets = vec![0; input_dimension * copy_count];
        let mut matching = Matching::new(nonzero_indices.len(), bucket_count);
        for _ in 0..MAX_ATTEMPTS {
            sample(&mut candidate_buckets);
            if matching.assign(&candidate_buckets, copy_count, nonzero_indices) {
                let map = Self::from_input_buckets(&candidate_buckets, copy_count, bucket_count);
                return Ok((map, matching.selected_input_indices));
            }
        }
        Err(BucketMapError::MatchingFailed)
    }

    /// Transposes input-major candidate buckets into the public bucket map.
    ///
    /// Count entries per bucket, take prefix sums, then fill each bucket while
    /// scanning input indices in order. This produces increasing bucket entries
    /// without sorting and never reads the secret or private matching.
    ///
    /// `candidate_buckets` contains complete rows of `copy_count` distinct valid
    /// bucket IDs. Counts and allocation lengths satisfy [`Self::try_generate`]'s
    /// checked bounds, so prefix sums fit and retain every input copy exactly once.
    fn from_input_buckets(
        candidate_buckets: &[usize],
        copy_count: usize,
        bucket_count: usize,
    ) -> Self {
        let mut bucket_offsets = vec![0; bucket_count + 1];
        for &bucket_index in candidate_buckets {
            bucket_offsets[bucket_index + 1] += 1;
        }
        for bucket_index in 0..bucket_count {
            bucket_offsets[bucket_index + 1] += bucket_offsets[bucket_index];
        }
        let mut write_offsets = bucket_offsets[..bucket_count].to_vec();
        let mut input_indices = vec![0; candidate_buckets.len()];
        for (input_index, input_buckets) in candidate_buckets.chunks_exact(copy_count).enumerate() {
            for &bucket_index in input_buckets {
                input_indices[write_offsets[bucket_index]] = input_index;
                write_offsets[bucket_index] += 1;
            }
        }
        Self {
            bucket_offsets,
            input_indices,
            copy_count,
        }
    }
}

/// Private matching between nonzero input coefficients and candidate buckets.
///
/// Buckets store original input indices directly. Searching records a path of
/// buckets whose occupants can move to make room for a new input. All private
/// buffers are reused across attempts and erased on drop.
struct Matching {
    /// Bucket -> selected original input index, or `EMPTY` if unoccupied.
    selected_input_indices: Zeroizing<Vec<usize>>,
    /// Destination bucket -> bucket whose occupant can move into it.
    /// `EMPTY` means unvisited; a starting bucket points to itself and receives
    /// the new input when the path is applied.
    predecessor_buckets: Zeroizing<Vec<usize>>,
    /// Occupied buckets whose occupants' alternative candidates need visiting.
    pending_buckets: Zeroizing<Vec<usize>>,
}

impl Matching {
    /// Allocates an empty matching and reusable search buffers.
    /// At most `h` buckets are occupied, and each is queued at most once per
    /// search. The caller has checked lengths and uses the same weight and
    /// bucket range for every assignment with this workspace.
    fn new(hamming_weight: usize, bucket_count: usize) -> Self {
        Self {
            selected_input_indices: Zeroizing::new(vec![EMPTY; bucket_count]),
            predecessor_buckets: Zeroizing::new(vec![EMPTY; bucket_count]),
            pending_buckets: Zeroizing::new(Vec::with_capacity(hamming_weight)),
        }
    }

    /// Resets the matching and assigns every nonzero input to a distinct bucket.
    ///
    /// Candidate rows are indexed by original input coefficient; only rows named
    /// by `nonzero_indices` participate. Inputs satisfy [`BucketMap::try_generate`]'s
    /// bounds and match this workspace's dimensions. On failure, the partial
    /// matching cannot generate a key; the next call resets it before retrying.
    fn assign(
        &mut self,
        candidate_buckets: &[usize],
        copy_count: usize,
        nonzero_indices: &[usize],
    ) -> bool {
        self.selected_input_indices.fill(EMPTY);
        for &input_index in nonzero_indices {
            if !self.augment(input_index, candidate_buckets, copy_count) {
                return false;
            }
        }
        true
    }

    /// Adds one unassigned input, moving existing occupants only if necessary.
    ///
    /// First try an empty candidate. If all candidates are occupied, find a
    /// relocation path, then apply it backwards from its free end. Returns false
    /// only when no path exists; existing assignments remain unchanged.
    /// `input_index` is an unassigned original input index; candidate rows and
    /// existing assignments satisfy [`Self::assign`]'s contract.
    fn augment(
        &mut self,
        input_index: usize,
        candidate_buckets: &[usize],
        copy_count: usize,
    ) -> bool {
        let row_start = input_index * copy_count;
        let input_candidates = &candidate_buckets[row_start..row_start + copy_count];
        for &bucket in input_candidates {
            if self.selected_input_indices[bucket] == EMPTY {
                self.selected_input_indices[bucket] = input_index;
                return true;
            }
        }

        let Some(free_bucket) =
            self.find_relocation_path(input_candidates, candidate_buckets, copy_count)
        else {
            return false;
        };
        self.apply_relocation_path(input_index, free_bucket);
        true
    }

    /// Finds a path from an occupied candidate to a free bucket using BFS.
    ///
    /// For each occupied bucket, try moving its occupant to another candidate.
    /// Record `predecessor_buckets[destination] = source` when first reaching a
    /// bucket. The returned free bucket ends the path; assignments are untouched.
    /// Starting candidates must be distinct, occupied buckets from the current
    /// input's row. Other inputs inherit [`Self::augment`]'s contract.
    fn find_relocation_path(
        &mut self,
        input_candidates: &[usize],
        candidate_buckets: &[usize],
        copy_count: usize,
    ) -> Option<usize> {
        self.predecessor_buckets.fill(EMPTY);
        self.pending_buckets.clear();
        for &bucket in input_candidates {
            // A starting bucket has no predecessor: it will receive the new input.
            self.predecessor_buckets[bucket] = bucket;
            self.pending_buckets.push(bucket);
        }

        let mut queue_cursor = 0;
        while queue_cursor < self.pending_buckets.len() {
            let source_bucket = self.pending_buckets[queue_cursor];
            queue_cursor += 1;
            let occupant = self.selected_input_indices[source_bucket];
            let row_start = occupant * copy_count;
            for &destination in &candidate_buckets[row_start..row_start + copy_count] {
                if self.predecessor_buckets[destination] != EMPTY {
                    continue;
                }
                self.predecessor_buckets[destination] = source_bucket;
                if self.selected_input_indices[destination] == EMPTY {
                    return Some(destination);
                }
                self.pending_buckets.push(destination);
            }
        }
        None
    }

    /// Applies the path recorded by a successful [`Self::find_relocation_path`].
    ///
    /// For `A -> B -> C (free)`, move B's occupant to C, A's occupant to B, then
    /// put the new input in A. Each move vacates the source bucket; a predecessor
    /// pointing to itself marks the starting bucket. Assignments must be
    /// unchanged since the search.
    fn apply_relocation_path(&mut self, input_index: usize, mut free_bucket: usize) {
        loop {
            let source_bucket = self.predecessor_buckets[free_bucket];
            if source_bucket == free_bucket {
                self.selected_input_indices[free_bucket] = input_index;
                return;
            }
            self.selected_input_indices[free_bucket] = self.selected_input_indices[source_bucket];
            free_bucket = source_bucket;
        }
    }
}
