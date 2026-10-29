//! Exact coefficient GGSW encryption for contiguous block controls.

use std::alloc::Layout;

use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_glwe::{BlockOccupancy, FourierGlweEncryptor, GgswParameters, SecretKeyDistr};
use primus_lattice::LweDimension;
use primus_modulus::NativeModulus;
use primus_reduce::RingContext;
use primus_tfhe_glwe::BlockBootstrappingKeyError;
use zeroize::Zeroizing;

use crate::{ClientKey, KeyGenerationError, KeyGenerator, block::BlockGlweBootstrappingKey};

/// Setup-only public block geometry and checked ciphertext allocation size.
/// Actual occupancy and input-index tables are not retained.
pub(crate) struct BlockKeyLayout {
    block_size: usize,
    data_len: usize,
}

impl BlockKeyLayout {
    /// Checks complete logical blocks before sampling secrets or allocating rows.
    pub(crate) fn try_new<T: TorusFftValue>(
        dimension: usize,
        distribution: SecretKeyDistr,
        parameters: &GgswParameters<T, NativeModulus<T>>,
    ) -> Result<Self, KeyGenerationError> {
        use BlockBootstrappingKeyError as Error;
        let SecretKeyDistr::BlockBinary {
            block_size,
            occupancy: BlockOccupancy::AtMostOne,
        } = distribution
        else {
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
        Layout::array::<Complex64>(parameters.size().fourier_ggsw_len())
            .map_err(|_| Error::StorageSizeOverflow)?;
        Ok(Self {
            block_size,
            data_len,
        })
    }
}

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: TorusFftValue,
    LM: RingContext<T>,
    Table: FftTable,
{
    /// Encrypts complete logical blocks after client compatibility was established
    /// by sampling or validation. Public ring-KS zero tails are not controls.
    pub(crate) fn generate_block_bootstrapping_key_with_accumulator<R>(
        &mut self,
        client: &ClientKey<T>,
        layout: BlockKeyLayout,
        encryptor: &mut FourierGlweEncryptor<'_, T>,
        rng: &mut R,
    ) -> Result<BlockGlweBootstrappingKey<T, NativeModulus<T>>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let BlockKeyLayout {
            block_size,
            data_len,
        } = layout;
        let parameters = self.context.parameters();
        let gadget = parameters.blind_rotation_params();
        let controls_per_block = block_size + 1;
        let block_len = controls_per_block * gadget.ggsw_len();
        let mut data = vec![T::ZERO; data_len];
        let mut constants = Zeroizing::new(vec![T::ZERO; controls_per_block]);
        for (block, output) in client
            .small_lwe_secret_key()
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
            // The dummy is a fresh encryption, not a ciphertext subtraction of
            // the bit controls: its row errors must be independent of their sum.
            // Reuse the exact auxiliary-NTT/CRT products, then retain torus rows.
            encryptor.encrypt_ggsw_constant_batch_coeff_to(&constants, output, gadget, rng);
        }
        Ok(BlockGlweBootstrappingKey::try_new(
            data,
            LweDimension::new(client.small_lwe_secret_key().dimension()),
            block_size,
            gadget,
            parameters.small_lwe().cipher_modulus(),
        )?)
    }
}
