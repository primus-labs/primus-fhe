//! Coefficient controls for direct, contiguous block-binary blind rotation.

use std::ops::Range;

use primus_glwe::GgswParameters;
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_reduce::{Modulus, RingContext};

use crate::{BlockBootstrappingKeyError, GlweBlindRotationControls};

/// Coefficient GGSWs for a block-binary input secret, with no bucket map.
///
/// Logical input positions are contiguous, equally sized blocks. Each block
/// stores its `w` bit controls followed by an independently encrypted dummy
/// `d = 1 - sum(s_i)`. Thus an empty block selects the identity rotation.
/// Only the public geometry and ciphertexts are retained; neither actual block
/// occupancy nor the sampled total Hamming weight is recorded.
pub struct BlockGlweBootstrappingKey<T: FheUint, M: RingContext<T>> {
    controls: GlweBlindRotationControls<T, M>,
    block_size: usize,
}

impl<T: FheUint, M: RingContext<T>> BlockGlweBootstrappingKey<T, M> {
    /// Binds coefficient GGSWs to complete logical input blocks without copying
    /// or transforming their storage. Public ring-KS zero padding is excluded.
    ///
    /// # Correctness
    /// Each block must contain GGSWs of its binary coefficients followed by
    /// an independently encrypted `1 - sum(s_i)`, under one accumulator secret.
    /// Every block has at most one `1`. Coefficients are canonical under the
    /// parameter modulus, with the same gadget scales and level order.
    ///
    /// # Errors
    /// Rejects zero or incomplete block sizes, an unrepresentable rotation
    /// domain, overflowing storage, or a coefficient count different from
    /// `(n + n / w) * ggsw_len`.
    pub fn try_new<LM: Modulus<ValueT = T>>(
        data: Vec<T>,
        input_dimension: LweDimension,
        block_size: usize,
        parameters: &GgswParameters<T, M>,
        input_modulus: LM,
    ) -> Result<Self, BlockBootstrappingKeyError> {
        use BlockBootstrappingKeyError as Error;
        let dimension = input_dimension.get();
        if block_size == 0 || !dimension.is_multiple_of(block_size) {
            return Err(Error::InvalidBlockGeometry {
                dimension,
                block_size,
            });
        }
        let control_count = dimension
            .checked_add(dimension / block_size)
            .ok_or(Error::StorageSizeOverflow)?;
        let controls = GlweBlindRotationControls::try_new(
            data,
            input_dimension,
            control_count,
            parameters,
            input_modulus,
        )
        .map_err(|error| match error {
            crate::controls::BlindRotationControlsError::RotationDomainTooLarge => {
                Error::RotationDomainTooLarge
            }
            crate::controls::BlindRotationControlsError::StorageSizeOverflow => {
                Error::StorageSizeOverflow
            }
            crate::controls::BlindRotationControlsError::StorageLengthMismatch {
                expected,
                actual,
            } => Error::StorageLengthMismatch { expected, actual },
        })?;
        Ok(Self {
            controls,
            block_size,
        })
    }

    /// Borrows coefficient controls and their common numerical layout.
    #[must_use]
    #[inline]
    pub fn controls(&self) -> &GlweBlindRotationControls<T, M> {
        &self.controls
    }

    /// Returns the number of logical input coefficients per complete block.
    #[must_use]
    #[inline]
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Returns the number of public blocks, including empty secret blocks.
    #[must_use]
    #[inline]
    pub fn block_count(&self) -> usize {
        self.controls.input_dimension().get() / self.block_size
    }

    /// Borrows a block's logical input range and contiguous coefficient GGSWs.
    /// The final GGSW is the independent dummy and has no input position.
    ///
    /// # Panics
    /// Panics if `block_index >= self.block_count()`.
    #[must_use]
    pub fn block_data(&self, block_index: usize) -> (Range<usize>, &[T]) {
        assert!(
            block_index < self.block_count(),
            "block index out of bounds"
        );
        let start = block_index * self.block_size;
        let control_start = block_index * (self.block_size + 1);
        let ggsw_len = self.controls.size().ggsw_len();
        (
            start..start + self.block_size,
            &self.controls.as_slice()
                [control_start * ggsw_len..(control_start + self.block_size + 1) * ggsw_len],
        )
    }
}
