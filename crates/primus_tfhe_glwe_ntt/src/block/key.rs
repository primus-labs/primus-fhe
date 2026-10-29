//! Direct block controls encrypted with the existing coefficient GGSW kernel.

use std::alloc::Layout;

use primus_glwe::{
    GgswParameters, NttGlweGadgetEncryptWorkspace, NttGlweSecretKey, SecretKeyDistr,
};
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lwe::LweSecretKey;
use primus_modulus::{BarrettModulus, NativeModulus, UintModulus};
use primus_ntt::MonomialNttTable;
use primus_tfhe_glwe::{BlockBootstrappingKeyError, BlockGlweBootstrappingKey};
use zeroize::Zeroizing;

use crate::KeyGenerationError;

/// Setup-only complete logical block geometry and checked ciphertext allocation.
/// Neither sampled occupancy nor a persistent input-index table is retained.
pub(crate) struct BlockKeyLayout {
    block_size: usize,
    data_len: usize,
}

impl BlockKeyLayout {
    /// Checks the public geometry before secret sampling or key allocation.
    pub(crate) fn try_new<T: FheUint>(
        dimension: usize,
        distribution: SecretKeyDistr,
        parameters: &GgswParameters<T, BarrettModulus<T>>,
    ) -> Result<Self, KeyGenerationError> {
        use BlockBootstrappingKeyError as Error;
        let SecretKeyDistr::BlockBinary { block_size } = distribution else {
            return Err(Error::UnsupportedSecretDistribution.into());
        };
        if dimension == 0 || block_size == 0 || !dimension.is_multiple_of(block_size) {
            return Err(Error::InvalidBlockGeometry {
                dimension,
                block_size,
            }
            .into());
        }
        if T::try_from(2 * parameters.poly_length().get()).is_err() {
            return Err(Error::RotationDomainTooLarge.into());
        }
        let control_count = dimension
            .checked_add(dimension / block_size)
            .ok_or(Error::StorageSizeOverflow)?;
        let data_len = control_count
            .checked_mul(parameters.ggsw_len())
            .ok_or(Error::StorageSizeOverflow)?;
        Layout::array::<T>(data_len).map_err(|_| Error::StorageSizeOverflow)?;
        Ok(Self {
            block_size,
            data_len,
        })
    }
}

/// Validates imported coefficients once at the independent BR-key boundary.
/// Invalid support is rejected before ciphertext allocation or RNG consumption.
pub(crate) fn generate_with_layout<T: FheUint, Table, R>(
    input: &LweSecretKey<T>,
    layout: BlockKeyLayout,
    output_key: &NttGlweSecretKey<T>,
    parameters: &GgswParameters<T, BarrettModulus<T>>,
    ntt: &Table,
    rng: &mut R,
    workspace: &mut NttGlweGadgetEncryptWorkspace<T>,
) -> Result<BlockGlweBootstrappingKey<T, BarrettModulus<T>>, KeyGenerationError>
where
    Table: MonomialNttTable<ValueT = T>,
    R: rand::Rng + rand::CryptoRng,
{
    // Inspect every logical coefficient, without revealing the first invalid
    // position through an early return. Public geometry was checked by layout.
    let mut invalid = false;
    for block in input.as_ref().chunks_exact(layout.block_size) {
        let mut occupied = false;
        for &coefficient in block {
            let selected = coefficient == T::ONE;
            invalid |= (coefficient > T::ONE) | (occupied & selected);
            occupied |= selected;
        }
    }
    if invalid {
        return Err(BlockBootstrappingKeyError::InvalidSecretCoefficients.into());
    }
    generate_validated_with_layout(input, layout, output_key, parameters, ntt, rng, workspace)
}

/// Shares the exact encryption kernel with independently imported BR secrets.
/// The owning ClientKey boundary has already checked 0/1 and at-most-one per
/// logical block; the input/layout distributions and dimensions must agree.
/// Only the n logical coefficients are encrypted, excluding ring-KS zero tails.
pub(crate) fn generate_validated_with_layout<T: FheUint, Table, R>(
    input: &LweSecretKey<T>,
    layout: BlockKeyLayout,
    output_key: &NttGlweSecretKey<T>,
    parameters: &GgswParameters<T, BarrettModulus<T>>,
    ntt: &Table,
    rng: &mut R,
    workspace: &mut NttGlweGadgetEncryptWorkspace<T>,
) -> Result<BlockGlweBootstrappingKey<T, BarrettModulus<T>>, KeyGenerationError>
where
    Table: MonomialNttTable<ValueT = T>,
    R: rand::Rng + rand::CryptoRng,
{
    let BlockKeyLayout {
        block_size,
        data_len,
    } = layout;
    let mut data = vec![T::ZERO; data_len];
    let controls_per_block = block_size + 1;
    let block_len = controls_per_block * parameters.ggsw_len();
    let mut constants = Zeroizing::new(vec![T::ZERO; controls_per_block]);
    for (block, output) in input
        .as_ref()
        .chunks_exact(block_size)
        .zip(data.chunks_exact_mut(block_len))
    {
        let mut occupied = false;
        for (constant, &coefficient) in constants[..block_size].iter_mut().zip(block) {
            *constant = coefficient;
            occupied |= coefficient == T::ONE;
        }
        constants[block_size] = if occupied { T::ZERO } else { T::ONE };
        // Encrypt the dummy as an ordinary independent GGSW. Deriving it from
        // the bit ciphertexts would correlate its row errors with their sum.
        output_key.encrypt_ggsw_constant_batch_coeff_to(
            &constants, output, parameters, ntt, rng, workspace,
        );
    }

    let dimension = LweDimension::new(input.dimension());
    if input.cipher_modulus_minus_one() == T::MAX {
        Ok(BlockGlweBootstrappingKey::try_new(
            data,
            dimension,
            block_size,
            parameters,
            NativeModulus::<T>::new(),
        )?)
    } else {
        Ok(BlockGlweBootstrappingKey::try_new(
            data,
            dimension,
            block_size,
            parameters,
            UintModulus::new(input.cipher_modulus_minus_one() + T::ONE),
        )?)
    }
}
