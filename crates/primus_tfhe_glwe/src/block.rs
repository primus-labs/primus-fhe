//! Coefficient controls for direct, contiguous block-binary blind rotation.

use std::{alloc::Layout, ops::Range};

use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{BlockOccupancy, GgswParameters, SecretKeyDistr};
use primus_integer::FheUint;
use primus_lattice::{GadgetSize, LweDimension};
use primus_reduce::{Modulus, RingContext};

use crate::BlockBootstrappingKeyError;

/// Validated layout for contiguous coefficient GGSWs, shared by GLWE backends.
///
/// Describes only logical LWE positions. Any public zero padding introduced by
/// ring key switching stays outside the block layout.
#[doc(hidden)]
pub struct BlockGlweKeyLayout<T: FheUint, M: RingContext<T>> {
    input_dimension: LweDimension,
    block_size: usize,
    occupancy: BlockOccupancy,
    selection_len: usize,
    block_stride: usize,
    size: GadgetSize,
    basis: ApproxSignedBasis<T>,
    ring_modulus: M,
    input_modulus: Option<T>,
}

impl<T: FheUint, M: RingContext<T>> BlockGlweKeyLayout<T, M> {
    /// Checks public geometry and coefficient allocation before key generation.
    /// `input_modulus` is the explicit LWE modulus q, or `None` for the native torus.
    ///
    /// # Errors
    /// Rejects a distribution other than block-binary, zero or incomplete
    /// blocks, an unrepresentable rotation domain, or overflowing storage.
    pub fn try_new(
        dimension: usize,
        distribution: SecretKeyDistr,
        parameters: &GgswParameters<T, M>,
        input_modulus: Option<T>,
    ) -> Result<Self, BlockBootstrappingKeyError> {
        use BlockBootstrappingKeyError as Error;
        let SecretKeyDistr::BlockBinary {
            block_size,
            occupancy,
        } = distribution
        else {
            return Err(Error::UnsupportedSecretDistribution);
        };
        let invalid_geometry = || Error::InvalidBlockGeometry {
            dimension,
            block_size,
        };
        let input_dimension = LweDimension::try_new(dimension).map_err(|_| invalid_geometry())?;
        if block_size == 0 || !dimension.is_multiple_of(block_size) {
            return Err(invalid_geometry());
        }
        if T::try_from(2 * parameters.poly_length().get()).is_err() {
            return Err(Error::RotationDomainTooLarge);
        }
        let size = parameters.size();
        let ggsw_len = size.ggsw_len();
        let selection_len = block_size
            .checked_mul(ggsw_len)
            .ok_or(Error::StorageSizeOverflow)?;
        let block_stride = selection_len
            .checked_add(usize::from(occupancy == BlockOccupancy::AtMostOne) * ggsw_len)
            .ok_or(Error::StorageSizeOverflow)?;
        let len = (dimension / block_size)
            .checked_mul(block_stride)
            .ok_or(Error::StorageSizeOverflow)?;
        Layout::array::<T>(len).map_err(|_| Error::StorageSizeOverflow)?;
        Ok(Self {
            input_dimension,
            block_size,
            occupancy,
            selection_len,
            block_stride,
            size,
            basis: parameters.basis().clone(),
            ring_modulus: parameters.cipher_modulus(),
            input_modulus,
        })
    }

    /// Returns the number of logical LWE positions per block.
    #[must_use]
    #[inline]
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Returns the declared occupancy law.
    #[must_use]
    #[inline]
    pub fn occupancy(&self) -> BlockOccupancy {
        self.occupancy
    }

    /// Returns the number of GGSWs per block, including an AtMostOne dummy.
    #[must_use]
    #[inline]
    pub fn controls_per_block(&self) -> usize {
        self.block_size + usize::from(self.occupancy == BlockOccupancy::AtMostOne)
    }

    /// Allocates the validated payload and writes each complete block in key order.
    /// The callback receives a contiguous logical range and its coefficient
    /// storage, including the final dummy control for `AtMostOne`.
    ///
    /// # Correctness
    /// The callback must fill every control with the material specified by
    /// [the key import contract](BlockGlweBootstrappingKey::try_new).
    #[must_use]
    pub fn generate(
        self,
        mut write_block: impl FnMut(Range<usize>, &mut [T]),
    ) -> BlockGlweBootstrappingKey<T, M> {
        let mut data = vec![T::ZERO; self.data_len()];
        for (block, coefficients) in data.chunks_exact_mut(self.block_stride).enumerate() {
            let start = block * self.block_size;
            write_block(start..start + self.block_size, coefficients);
        }
        BlockGlweBootstrappingKey { layout: self, data }
    }

    /// Coefficient count established when the layout was prepared.
    fn data_len(&self) -> usize {
        (self.input_dimension.get() / self.block_size) * self.block_stride
    }

    /// Binds imported material after checking that every complete block is present.
    fn bind(
        self,
        data: Vec<T>,
    ) -> Result<BlockGlweBootstrappingKey<T, M>, BlockBootstrappingKeyError> {
        let expected = self.data_len();
        if data.len() != expected {
            return Err(BlockBootstrappingKeyError::StorageLengthMismatch {
                expected,
                actual: data.len(),
            });
        }
        Ok(BlockGlweBootstrappingKey { layout: self, data })
    }
}

/// Coefficient GGSWs for a block-binary input secret.
///
/// Logical input positions are contiguous, equally sized blocks. Each block
/// stores its `w` bit controls. [`BlockOccupancy::AtMostOne`] adds an independently
/// encrypted dummy `d = 1 - sum(s_i)` so an empty block selects the identity;
/// [`BlockOccupancy::ExactlyOne`] has no dummy.
/// Only the public geometry and ciphertexts are retained; neither actual block
/// occupancy nor the sampled total Hamming weight is recorded.
pub struct BlockGlweBootstrappingKey<T: FheUint, M: RingContext<T>> {
    layout: BlockGlweKeyLayout<T, M>,
    data: Vec<T>,
}

impl<T: FheUint, M: RingContext<T>> BlockGlweBootstrappingKey<T, M> {
    /// Binds coefficient GGSWs to complete logical input blocks without copying
    /// or transforming their storage. Public ring-KS zero padding is excluded.
    ///
    /// # Correctness
    /// Each block must contain GGSWs of its binary coefficients under one
    /// accumulator secret and satisfy the declared occupancy. AtMostOne adds
    /// an independently encrypted `1 - sum(s_i)` last; ExactlyOne has no dummy.
    /// Coefficients are canonical under the parameter modulus, with the same
    /// gadget scales and level order.
    ///
    /// # Errors
    /// Rejects zero or incomplete block sizes, an unrepresentable rotation
    /// domain, overflowing storage, or a coefficient count different from
    /// `(n + δ * n / w) * ggsw_len`, where δ is one only for AtMostOne.
    pub fn try_new<LM: Modulus<ValueT = T>>(
        data: Vec<T>,
        input_dimension: LweDimension,
        block_size: usize,
        occupancy: BlockOccupancy,
        parameters: &GgswParameters<T, M>,
        input_modulus: LM,
    ) -> Result<Self, BlockBootstrappingKeyError> {
        BlockGlweKeyLayout::try_new(
            input_dimension.get(),
            SecretKeyDistr::BlockBinary {
                block_size,
                occupancy,
            },
            parameters,
            input_modulus.explicit_value(),
        )?
        .bind(data)
    }

    /// Returns the logical input dimension, excluding ring-KS zero padding.
    #[must_use]
    #[inline]
    pub fn input_dimension(&self) -> LweDimension {
        self.layout.input_dimension
    }

    /// Returns the explicit input modulus q, or `None` for the native torus.
    #[must_use]
    #[inline]
    pub fn input_modulus_value(&self) -> Option<T> {
        self.layout.input_modulus
    }

    /// Returns the reducer for accumulator coefficients and gadget rows at Q.
    #[must_use]
    #[inline]
    pub fn ring_modulus(&self) -> M {
        self.layout.ring_modulus
    }

    /// Returns the GGSW layout shared by all selections and dummies.
    #[must_use]
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.layout.size
    }

    /// Returns the decomposition basis, including its level order.
    #[must_use]
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.layout.basis
    }

    /// Returns the number of logical input coefficients per complete block.
    #[must_use]
    #[inline]
    pub fn block_size(&self) -> usize {
        self.layout.block_size
    }

    /// Returns the declared secret law, which determines whether a dummy is stored.
    #[must_use]
    #[inline]
    pub fn occupancy(&self) -> BlockOccupancy {
        self.layout.occupancy
    }

    /// Borrows all coefficient GGSWs in block order. Each control uses
    /// `[row][level][component][coefficient]` order.
    #[must_use]
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Iterates complete blocks in input order.
    ///
    /// Each item contains the logical input range, its contiguous coefficient
    /// GGSWs, and the independently encrypted dummy for AtMostOne. The dummy
    /// slice is empty for ExactlyOne.
    #[inline]
    pub fn blocks(&self) -> impl ExactSizeIterator<Item = (Range<usize>, &[T], &[T])> {
        let width = self.layout.block_size;
        let selection_len = self.layout.selection_len;
        self.data
            .chunks_exact(self.layout.block_stride)
            .enumerate()
            .map(move |(block, controls)| {
                let (selections, dummy) = controls.split_at(selection_len);
                (block * width..(block + 1) * width, selections, dummy)
            })
    }
}
