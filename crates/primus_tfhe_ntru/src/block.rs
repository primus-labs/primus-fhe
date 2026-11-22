//! Contiguous coefficient controls for direct block-binary NTRU blind rotation.

use std::{alloc::Layout, marker::PhantomData, ops::Range};

use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_ntru::{BlockOccupancy, NlevParameters, SecretKeyDistr};
use primus_reduce::RingContext;

use crate::{BlockBootstrappingKeyError, PbsParameters};

/// Public geometry for a complete Block key, validated before key generation.
/// The coefficient type determines the maximum addressable allocation.
#[doc(hidden)]
pub struct BlockNtruKeyLayout<T: FheUint> {
    input_dimension: LweDimension,
    block_size: usize,
    occupancy: BlockOccupancy,
    control_len: usize,
    block_stride: usize,
    coefficients: PhantomData<T>,
}

impl<T: FheUint> BlockNtruKeyLayout<T> {
    /// Checks the complete control layout of the configured BlockBinary secret.
    ///
    /// # Errors
    /// Rejects other secret distributions, incomplete blocks or unaddressable storage.
    pub fn try_from_parameters<M: RingContext<T>, LM: RingContext<T>>(
        parameters: &PbsParameters<T, M, LM>,
    ) -> Result<Self, BlockBootstrappingKeyError> {
        let SecretKeyDistr::BlockBinary {
            block_size,
            occupancy,
        } = parameters.external_lwe().secret_key_distr()
        else {
            return Err(BlockBootstrappingKeyError::UnsupportedSecretDistribution);
        };
        Self::try_new(
            parameters.external_lwe_dimension(),
            block_size,
            occupancy,
            parameters.blind_rotation().nlev_len(),
        )
    }

    /// Validates logical blocks and the full coefficient allocation before any writes.
    fn try_new(
        input_dimension: LweDimension,
        block_size: usize,
        occupancy: BlockOccupancy,
        control_len: usize,
    ) -> Result<Self, BlockBootstrappingKeyError> {
        use BlockBootstrappingKeyError as Error;

        let dimension = input_dimension.get();
        if block_size == 0 || !dimension.is_multiple_of(block_size) {
            return Err(Error::InvalidBlockGeometry {
                dimension,
                block_size,
            });
        }
        // A valid block fits within the logical dimension, which leaves room for a dummy.
        let controls_per_block = block_size + usize::from(occupancy == BlockOccupancy::AtMostOne);
        let block_stride = controls_per_block
            .checked_mul(control_len)
            .ok_or(Error::StorageSizeOverflow)?;
        let data_len = (dimension / block_size)
            .checked_mul(block_stride)
            .ok_or(Error::StorageSizeOverflow)?;
        Layout::array::<T>(data_len).map_err(|_| Error::StorageSizeOverflow)?;
        Ok(Self {
            input_dimension,
            block_size,
            occupancy,
            control_len,
            block_stride,
            coefficients: PhantomData,
        })
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

    /// Allocates the validated payload and writes each complete block in key order.
    /// The callback receives a contiguous logical range and its coefficient
    /// storage, including the final dummy control for `AtMostOne`.
    ///
    /// # Correctness
    /// The callback must fill every control with the material specified by
    /// [`BlockNtruBootstrappingKey::try_new`]. The first range starts at zero.
    #[must_use]
    pub fn generate(
        self,
        mut write_block: impl FnMut(Range<usize>, &mut [T]),
    ) -> BlockNtruBootstrappingKey<T> {
        let mut data = vec![T::ZERO; self.data_len()];
        for (block, coefficients) in data.chunks_exact_mut(self.block_stride).enumerate() {
            let start = block * self.block_size;
            write_block(start..start + self.block_size, coefficients);
        }
        BlockNtruBootstrappingKey { data, layout: self }
    }

    /// Coefficient count established when the layout was prepared.
    fn data_len(&self) -> usize {
        (self.input_dimension.get() / self.block_size) * self.block_stride
    }
}

/// Coefficient controls for complete logical blocks.
///
/// Each block stores its `w` binary controls. `AtMostOne` additionally stores an
/// independently encrypted dummy `d = 1 - sum(s_i)`; `ExactlyOne` has no dummy.
/// The first whole block uses NLEV controls to lift a public LUT; later blocks
/// use NGSW controls. Both occupy the same `N*L` coefficient layout. Only public
/// geometry, the declared occupancy mode and ciphertexts remain; sampled support
/// and total weight are not retained.
pub struct BlockNtruBootstrappingKey<T: FheUint> {
    data: Vec<T>,
    layout: BlockNtruKeyLayout<T>,
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
        let layout = BlockNtruKeyLayout::try_new(
            input_dimension,
            block_size,
            occupancy,
            parameters.nlev_len(),
        )?;
        let expected = layout.data_len();
        if data.len() != expected {
            return Err(BlockBootstrappingKeyError::StorageLengthMismatch {
                expected,
                actual: data.len(),
            });
        }
        Ok(Self { data, layout })
    }

    /// Returns the logical external LWE dimension.
    #[must_use]
    #[inline]
    pub fn input_dimension(&self) -> LweDimension {
        self.layout.input_dimension
    }

    /// Returns the number of logical coefficients per complete block.
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.layout.block_size
    }

    /// Returns the declared occupancy mode that determines the control layout.
    #[must_use]
    pub fn occupancy(&self) -> BlockOccupancy {
        self.layout.occupancy
    }

    /// Returns N*L coefficient values per NLEV or NGSW control.
    #[must_use]
    #[inline]
    pub fn control_len(&self) -> usize {
        self.layout.control_len
    }

    /// Returns `[block][selector..., optional dummy][level][coefficient]` storage.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Borrows each block in key order as its input range, bit controls and dummy.
    /// The dummy slice is empty for `ExactlyOne`. The first block contains NLEV
    /// controls and all following blocks contain NGSW controls.
    #[inline]
    pub fn blocks(&self) -> impl ExactSizeIterator<Item = (Range<usize>, &[T], &[T])> + '_ {
        let block_size = self.layout.block_size;
        let selection_len = block_size * self.layout.control_len;
        self.data
            .chunks_exact(self.layout.block_stride)
            .enumerate()
            .map(move |(block, data)| {
                let start = block * block_size;
                let (selections, dummy) = data.split_at(selection_len);
                (start..start + block_size, selections, dummy)
            })
    }
}
