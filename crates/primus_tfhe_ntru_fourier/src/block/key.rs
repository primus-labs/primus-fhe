//! Exact native controls written before any online Fourier conversion.

use std::alloc::Layout;

use primus_fft::{FftTable, TorusFftValue};
use primus_lattice::nlev::Nlev;
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, SecretKeyDistr, split::NativeNtruGadgetGenerator};
use primus_tfhe_ntru::BlockBootstrappingKeyError;

use super::BlockNtruBootstrappingKey;
use crate::{ClientKey, KeyGenerationError, KeyGenerator};

/// Complete public block geometry and coefficient allocation, checked before RNG.
/// No support assignment, sampled occupancy or index table is retained.
pub(crate) struct BlockKeyLayout {
    block_size: usize,
    data_len: usize,
}

impl BlockKeyLayout {
    /// Checks the exact-native capability and complete logical block payload.
    pub(crate) fn try_new<T: TorusFftValue>(
        dimension: usize,
        distribution: SecretKeyDistr,
        parameters: &NlevParameters<T, NativeModulus<T>>,
    ) -> Result<Self, KeyGenerationError> {
        use BlockBootstrappingKeyError as Error;
        if T::BITS != 64 {
            return Err(Error::UnsupportedFourierWordSize { bits: T::BITS }.into());
        }
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
        let data_len = dimension
            .checked_add(dimension / block_size)
            .and_then(|count| count.checked_mul(parameters.nlev_len()))
            .ok_or(Error::StorageSizeOverflow)?;
        Layout::array::<T>(data_len).map_err(|_| Error::StorageSizeOverflow)?;
        Ok(Self {
            block_size,
            data_len,
        })
    }
}

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Writes independently encrypted bits and dummies from the accepted secret's
    /// exact inverse. Sampling or ClientKey validation established occupancy.
    /// No approximate Fourier ciphertext is converted back to coefficients.
    pub(crate) fn generate_block_blind_rotation_key_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client: &ClientKey<T>,
        generator: &NativeNtruGadgetGenerator<T>,
        layout: BlockKeyLayout,
        rng: &mut R,
    ) -> Result<crate::key::BlindRotationKey<T>, KeyGenerationError> {
        let BlockKeyLayout {
            block_size,
            data_len,
        } = layout;
        let parameters = self.context.parameters();
        let gadget = parameters.blind_rotation();
        let control_len = gadget.nlev_len();
        let mut data = vec![T::ZERO; data_len];
        for (block_index, (block, output)) in client
            .external_lwe_secret_key()
            .as_ref()
            .chunks_exact(block_size)
            .zip(data.chunks_exact_mut((block_size + 1) * control_len))
            .enumerate()
        {
            let occupied = block
                .iter()
                .fold(false, |occupied, &bit| occupied | (bit == T::ONE));
            for (bit, coefficients) in block
                .iter()
                .map(|&bit| bit == T::ONE)
                .chain(std::iter::once(!occupied))
                .zip(output.chunks_exact_mut(control_len))
            {
                // The first whole block is NLEV, even for an empty block or
                // zero rotation: its independently encrypted dummy still lifts
                // the public LUT. Every following block instead uses NGSW.
                generator.encrypt_bit_coeff_to(
                    bit,
                    block_index == 0,
                    Nlev::new(coefficients),
                    gadget,
                    rng,
                );
            }
        }
        let controls = BlockNtruBootstrappingKey::try_new(
            data,
            parameters.external_lwe_dimension(),
            block_size,
            gadget,
        )?;
        Ok(crate::key::BlindRotationKey::from_block(
            parameters,
            controls,
            self.context.br_precision(),
        ))
    }
}
