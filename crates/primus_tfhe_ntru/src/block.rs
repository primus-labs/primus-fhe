//! Contiguous coefficient controls for direct block-binary NTRU blind rotation.

use std::ops::Range;

use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_ntru::NlevParameters;
use primus_reduce::RingContext;

use crate::{BlockBootstrappingKeyError, NtruBlindRotationControls};

/// Coefficient controls for complete logical blocks, without a bucket map.
///
/// Each block stores its `w` binary coefficients and an independently encrypted
/// dummy `d = 1 - sum(s_i)`. The first block uses NLEV controls to lift a public
/// LUT; later blocks use NGSW controls. Both occupy the same `N*L` coefficient
/// layout. All-zero blocks and an all-zero external secret are valid.
/// Only public geometry and ciphertexts remain; no occupancy or total weight is stored.
pub struct BlockNtruBootstrappingKey<T: FheUint> {
    controls: NtruBlindRotationControls<T>,
    block_size: usize,
}

impl<T: FheUint> BlockNtruBootstrappingKey<T> {
    /// Binds complete coefficient controls to the logical input blocks, without
    /// copying, transforming or scanning ciphertext coefficients.
    ///
    /// # Correctness
    /// Each block has at most one secret `1`. The bit controls and final dummy
    /// must independently encrypt these values under the same accumulator secret,
    /// modulus and gadget scales. Every first-block control is NLEV; all later
    /// controls are NGSW. Coefficients must be canonical under that modulus.
    /// The backend BR owner must retain the same basis and modulus. Coefficient
    /// payloads recovered from Fourier representations retain their rounding error.
    ///
    /// # Errors
    /// Rejects zero or incomplete blocks, overflowing storage, or a coefficient
    /// count different from `(n + n / w) * nlev_len`.
    pub fn try_new<M: RingContext<T>>(
        data: Vec<T>,
        input_dimension: LweDimension,
        block_size: usize,
        parameters: &NlevParameters<T, M>,
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
        let controls =
            NtruBlindRotationControls::try_new(data, input_dimension, control_count, parameters)
                .map_err(|error| match error {
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

    /// Borrows the coefficient controls and their common `N*L` layout.
    #[must_use]
    pub fn controls(&self) -> &NtruBlindRotationControls<T> {
        &self.controls
    }

    /// Returns the number of logical coefficients per complete block.
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Returns the public block count, including empty secret blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.controls.input_dimension().get() / self.block_size
    }

    /// Borrows a block's logical input range and contiguous coefficient controls.
    /// The final control is its dummy and has no input position.
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
        let control_len = self.controls.control_len();
        (
            start..start + self.block_size,
            &self.controls.as_slice()
                [control_start * control_len..(control_start + self.block_size + 1) * control_len],
        )
    }
}
