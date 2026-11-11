//! Contiguous coefficient controls for direct block-binary NTRU blind rotation.

use std::ops::Range;

use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_ntru::{BlockOccupancy, NlevParameters};
use primus_reduce::RingContext;

use crate::{BlockBootstrappingKeyError, NtruBlindRotationControls};

/// Coefficient controls for complete logical blocks.
///
/// Each block stores its `w` binary controls. `AtMostOne` additionally stores an
/// independently encrypted dummy `d = 1 - sum(s_i)`; `ExactlyOne` has no dummy.
/// The first whole block uses NLEV controls to lift a public LUT; later blocks
/// use NGSW controls. Both occupy the same `N*L` coefficient layout. Only public
/// geometry, the declared occupancy mode and ciphertexts remain; sampled support
/// and total weight are not retained.
pub struct BlockNtruBootstrappingKey<T: FheUint> {
    controls: NtruBlindRotationControls<T>,
    block_size: usize,
    occupancy: BlockOccupancy,
}

impl<T: FheUint> BlockNtruBootstrappingKey<T> {
    /// Binds complete coefficient controls to the logical input blocks, without
    /// copying, transforming or scanning ciphertext coefficients.
    ///
    /// # Correctness
    /// Each block obeys `occupancy`. All bit controls and, for `AtMostOne`, the
    /// final dummy independently encrypt these values under the same accumulator
    /// secret, modulus and gadget scales. Every first-block control is NLEV; all later
    /// controls are NGSW. Coefficients must be canonical under that modulus.
    /// The backend BR owner must retain the same basis and modulus. Coefficient
    /// payloads recovered from Fourier representations retain their rounding error.
    ///
    /// # Errors
    /// Rejects zero or incomplete blocks, overflowing storage, or a coefficient
    /// count different from `(n + δ * n / w) * nlev_len`, where δ is one only
    /// for `AtMostOne`.
    pub fn try_new<M: RingContext<T>>(
        data: Vec<T>,
        input_dimension: LweDimension,
        block_size: usize,
        occupancy: BlockOccupancy,
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
            .checked_add(
                usize::from(occupancy == BlockOccupancy::AtMostOne) * (dimension / block_size),
            )
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
            occupancy,
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

    /// Returns the declared occupancy mode that determines the control layout.
    #[must_use]
    pub fn occupancy(&self) -> BlockOccupancy {
        self.occupancy
    }

    /// Returns the public block count, including empty secret blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.controls.input_dimension().get() / self.block_size
    }

    /// Borrows a block's logical input range and contiguous coefficient controls.
    /// Only `AtMostOne` has a final dummy control with no input position.
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
        let controls_per_block =
            self.block_size + usize::from(self.occupancy == BlockOccupancy::AtMostOne);
        let control_start = block_index * controls_per_block;
        let control_len = self.controls.control_len();
        (
            start..start + self.block_size,
            &self.controls.as_slice()
                [control_start * control_len..(control_start + controls_per_block) * control_len],
        )
    }
}
