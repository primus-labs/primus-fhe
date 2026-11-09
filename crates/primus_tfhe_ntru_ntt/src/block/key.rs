//! Exact coefficient controls encrypted using the accepted accumulator transform.

use std::alloc::Layout;

use num_traits::{ConstOne, ConstZero};
use primus_integer::FheUint;
use primus_lattice::nlev::NttNlev;
use primus_ntru::{BlockOccupancy, NttNtruSecretKey, SecretKeyDistr};
use primus_ntt::MonomialNttTable;
use primus_tfhe_ntru::BlockBootstrappingKeyError;
use zeroize::Zeroizing;

use super::BlockNtruBootstrappingKey;
use crate::{ClientKey, KeyGenerationError, KeyGenerator};

/// Complete public block geometry and ciphertext allocation, checked before RNG.
/// No support assignment, sampled occupancy or index table is retained.
pub(crate) struct BlockKeyLayout {
    block_size: usize,
    occupancy: BlockOccupancy,
    data_len: usize,
}

impl BlockKeyLayout {
    /// Checks the logical geometry and full control payload before sampling.
    pub(crate) fn try_new<T: FheUint, M: primus_reduce::RingContext<T>>(
        dimension: usize,
        distribution: SecretKeyDistr,
        parameters: &primus_ntru::NlevParameters<T, M>,
    ) -> Result<Self, KeyGenerationError> {
        use BlockBootstrappingKeyError as Error;
        let SecretKeyDistr::BlockBinary {
            block_size,
            occupancy,
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
        let data_len = dimension
            .checked_add(
                usize::from(occupancy == BlockOccupancy::AtMostOne) * (dimension / block_size),
            )
            .and_then(|count| count.checked_mul(parameters.nlev_len()))
            .ok_or(Error::StorageSizeOverflow)?;
        Layout::array::<T>(data_len).map_err(|_| Error::StorageSizeOverflow)?;
        Ok(Self {
            block_size,
            occupancy,
            data_len,
        })
    }
}

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Encrypts every bit and any required dummy using the accepted f transform
    /// and inverse. Sampling or the ClientKey boundary established 0/1 and the
    /// declared occupancy; no secret-dependent control is omitted or rescanned.
    pub(crate) fn generate_block_blind_rotation_key_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client: &ClientKey<T>,
        accumulator_ntt: &NttNtruSecretKey<T>,
        layout: BlockKeyLayout,
        rng: &mut R,
    ) -> Result<crate::key::BlindRotationKey<T>, KeyGenerationError> {
        let BlockKeyLayout {
            block_size,
            occupancy,
            data_len,
        } = layout;
        let parameters = self.context.parameters();
        let gadget = parameters.blind_rotation();
        let control_len = gadget.nlev_len();
        let ntt = self.context.table();
        let has_dummy = occupancy == BlockOccupancy::AtMostOne;
        let controls_per_block = block_size + usize::from(has_dummy);
        let mut data = vec![T::ZERO; data_len];
        let mut constants = Zeroizing::new(vec![T::SignedInteger::ZERO; controls_per_block]);
        for (block_index, (block, output)) in client
            .external_lwe_secret_key()
            .as_ref()
            .chunks_exact(block_size)
            .zip(data.chunks_exact_mut(controls_per_block * control_len))
            .enumerate()
        {
            let mut occupied = false;
            for (&bit, constant) in block.iter().zip(&mut constants[..block_size]) {
                let selected = bit == T::ONE;
                *constant = if selected {
                    T::SignedInteger::ONE
                } else {
                    T::SignedInteger::ZERO
                };
                occupied |= selected;
            }
            if has_dummy {
                constants[block_size] = if occupied {
                    T::SignedInteger::ZERO
                } else {
                    T::SignedInteger::ONE
                };
            }
            // The first *whole block* uses NLEV, with a dummy only for AtMostOne.
            // Its public-LUT lift is compulsory even when every exponent is zero.
            // Every later block has NGSW controls, with the same product layout.
            if block_index == 0 {
                for (&bit, row) in constants.iter().zip(output.chunks_exact_mut(control_len)) {
                    accumulator_ntt.encrypt_nlev_constant_to(
                        if bit == T::SignedInteger::ONE {
                            T::ONE
                        } else {
                            T::ZERO
                        },
                        &mut NttNlev::new(row),
                        gadget,
                        ntt,
                        rng,
                        &mut self.gadget,
                    );
                }
            } else {
                accumulator_ntt
                    .encrypt_ngsw_signed_constant_batch_to(&constants, output, gadget, ntt, rng);
            }
            // Group aggregation consumes canonical coefficient controls. Keep
            // only this representation instead of a second transformed BSK.
            for polynomial in output.chunks_exact_mut(parameters.poly_length().get()) {
                ntt.inverse_transform_slice(polynomial);
            }
        }
        let controls = BlockNtruBootstrappingKey::try_new(
            data,
            parameters.external_lwe_dimension(),
            block_size,
            occupancy,
            gadget,
        )?;
        Ok(crate::key::BlindRotationKey::from_block(
            parameters, controls,
        ))
    }
}
