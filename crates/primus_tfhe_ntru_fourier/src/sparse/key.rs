//! Coefficient-domain bucket selections for experimental sparse NTRU PBS.

use primus_fft::{FftTable, TorusFftValue};
use primus_lattice::nlev::Nlev;
use primus_ntru::{FourierNtruSecretKey, SecretKeyDistr};
use primus_tfhe::sparse::BucketMap;
use std::alloc::Layout;
use zeroize::Zeroizing;

use crate::{
    ClientKey, KeyGenerationError, KeyGenerator, SparseBootstrappingKeyError,
    sparse::SparseNtruBootstrappingKey,
};

/// Validated bucket geometry and ciphertext allocation size, before secret sampling.
/// Kept only during setup; the map and key retain their own final metadata.
pub(crate) struct SparseKeyLayout {
    copy_count: usize,
    bucket_count: usize,
    hamming_weight: usize,
    data_len: usize,
}

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Validates public sparse choices before allocating keys or consuming randomness.
    pub(crate) fn prepare_sparse_layout(
        &self,
        copy_count: usize,
        bucket_count: usize,
    ) -> Result<SparseKeyLayout, KeyGenerationError> {
        use SparseBootstrappingKeyError as Error;
        let parameters = self.context.parameters();
        let input = parameters.external_lwe();
        let SecretKeyDistr::FixedHammingWeightBinary { hamming_weight } = input.secret_key_distr()
        else {
            return Err(Error::UnsupportedSecretDistribution.into());
        };
        let dimension = input.dimension().get();
        if hamming_weight == 0 || hamming_weight >= dimension {
            return Err(Error::InvalidHammingWeight.into());
        }
        let entries = dimension
            .checked_mul(copy_count)
            .ok_or(Error::StorageSizeOverflow)?;
        let offsets = bucket_count
            .checked_add(1)
            .ok_or(Error::StorageSizeOverflow)?;
        let data_len = entries
            .checked_add(bucket_count)
            .and_then(|count| count.checked_mul(parameters.blind_rotation().nlev_len()))
            .ok_or(Error::StorageSizeOverflow)?;
        Layout::array::<usize>(entries).map_err(|_| Error::StorageSizeOverflow)?;
        Layout::array::<usize>(offsets).map_err(|_| Error::StorageSizeOverflow)?;
        Layout::array::<T>(data_len).map_err(|_| Error::StorageSizeOverflow)?;
        if copy_count == 0 || bucket_count < copy_count.max(hamming_weight) {
            return Err(
                Error::from(primus_tfhe::sparse::BucketMapError::InvalidBucketParameters).into(),
            );
        }
        Ok(SparseKeyLayout {
            copy_count,
            bucket_count,
            hamming_weight,
            data_len,
        })
    }

    /// Matches the fixed support and encrypts controls with the already accepted inverse.
    /// The caller established client compatibility and sparse allocation bounds.
    pub(crate) fn generate_sparse_blind_rotation_key_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        accumulator_fourier: &FourierNtruSecretKey,
        layout: SparseKeyLayout,
        rng: &mut R,
    ) -> Result<crate::key::BlindRotationKey<T>, KeyGenerationError> {
        use SparseBootstrappingKeyError as Error;
        let parameters = self.context.parameters();
        let SparseKeyLayout {
            copy_count,
            bucket_count,
            hamming_weight,
            data_len,
        } = layout;
        let dimension = parameters.external_lwe_dimension().get();
        let control_len = parameters.blind_rotation().nlev_len();
        let nonzero_indices = Zeroizing::new(
            client_key
                .external_lwe_secret_key()
                .as_ref()
                .iter()
                .enumerate()
                .filter_map(|(i, &bit)| (bit == T::ONE).then_some(i))
                .collect::<Vec<_>>(),
        );
        if nonzero_indices.len() != hamming_weight {
            return Err(Error::InvalidSecretWeight.into());
        }
        let (map, selected) =
            BucketMap::try_generate(dimension, copy_count, bucket_count, &nonzero_indices, rng)
                .map_err(Error::from)?;
        drop(nonzero_indices);
        let mut data = vec![T::ZERO; data_len];
        // Write native controls in their retained representation. Evaluation
        // transforms the selected aggregates, so setup needs no round trip.
        for (bucket, &chosen) in selected.iter().enumerate() {
            let start = map.bucket_offsets()[bucket];
            let end = map.bucket_offsets()[bucket + 1];
            let output =
                &mut data[(start + bucket) * control_len..(end + bucket + 1) * control_len];
            for (&index, coefficients) in map.input_indices()[start..end]
                .iter()
                .chain(std::iter::once(&BucketMap::UNASSIGNED))
                .zip(output.chunks_exact_mut(control_len))
            {
                accumulator_fourier.encrypt_gadget_bit_coeff_to(
                    index == chosen,
                    bucket == 0,
                    Nlev::new(coefficients),
                    parameters.blind_rotation(),
                    rng,
                    &mut self.gadget,
                );
            }
        }
        drop(selected);
        let controls = SparseNtruBootstrappingKey::try_new(
            data,
            map,
            hamming_weight,
            parameters.blind_rotation(),
        )?;
        let blind_rotation = crate::key::BlindRotationKey::from_sparse(parameters, controls);
        Ok(blind_rotation)
    }
}
