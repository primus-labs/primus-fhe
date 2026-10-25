use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_glwe::{FourierGlweSecretKey, SecretKeyDistr};
use primus_lattice::ggsw::FourierGgsw;
use primus_modulus::NativeModulus;
use primus_reduce::RingContext;
use primus_tfhe::sparse::BucketMap;
use std::alloc::Layout;
use zeroize::Zeroizing;

use crate::{
    ClientKey, KeyGenerationError, KeyGenerator, SparseBootstrappingKeyError,
    sparse::SparseGlweBootstrappingKey,
};

// Checked public map and private assignment, retained only until selector encryption.
pub(crate) struct PreparedSparseMap {
    map: BucketMap,
    selected_input_indices: Zeroizing<Vec<usize>>,
    hamming_weight: usize,
    data_len: usize,
}

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
    LM: RingContext<T>,
    Table: FftTable,
{
    /// Validates public sparse choices before allocating keys or consuming randomness.
    pub(crate) fn prepare_sparse_layout(
        &self,
        copy_count: usize,
        bucket_count: usize,
    ) -> Result<SparseKeyLayout, KeyGenerationError> {
        use SparseBootstrappingKeyError as Error;
        let parameters = self.context.parameters();
        let input = parameters.small_lwe();
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
            .and_then(|count| {
                count.checked_mul(parameters.blind_rotation_params().size().ggsw_len())
            })
            .ok_or(Error::StorageSizeOverflow)?;
        Layout::array::<usize>(entries).map_err(|_| Error::StorageSizeOverflow)?;
        Layout::array::<usize>(offsets).map_err(|_| Error::StorageSizeOverflow)?;
        Layout::array::<T>(data_len).map_err(|_| Error::StorageSizeOverflow)?;
        Layout::array::<Complex64>(parameters.blind_rotation_params().size().fourier_ggsw_len())
            .map_err(|_| Error::StorageSizeOverflow)?;
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

    /// Builds a public map after key compatibility and layout validation.
    pub(crate) fn prepare_sparse_map<R: rand::Rng + rand::CryptoRng>(
        &self,
        client_key: &ClientKey<T>,
        layout: SparseKeyLayout,
        rng: &mut R,
    ) -> Result<PreparedSparseMap, KeyGenerationError> {
        use SparseBootstrappingKeyError as Error;
        let SparseKeyLayout {
            copy_count,
            bucket_count,
            hamming_weight,
            data_len,
        } = layout;
        let input = client_key.small_lwe_secret_key();
        let input_dimension = input.dimension();
        let mut nonzero_indices = Zeroizing::new(Vec::with_capacity(hamming_weight));
        for (index, &coefficient) in input.as_ref().iter().enumerate() {
            if coefficient == T::ONE {
                if nonzero_indices.len() == hamming_weight {
                    return Err(Error::InvalidSecretCoefficients.into());
                }
                nonzero_indices.push(index);
            } else if coefficient != T::ZERO {
                return Err(Error::InvalidSecretCoefficients.into());
            }
        }
        if nonzero_indices.len() != hamming_weight {
            return Err(Error::InvalidSecretCoefficients.into());
        }
        let (map, selected_input_indices) = BucketMap::try_generate(
            input_dimension,
            copy_count,
            bucket_count,
            &nonzero_indices,
            rng,
        )
        .map_err(Error::from)?;
        drop(nonzero_indices);
        Ok(PreparedSparseMap {
            map,
            selected_input_indices,
            hamming_weight,
            data_len,
        })
    }

    /// Consumes the checked map and reuses the secret transform shared with optional CBS generation.
    pub(crate) fn generate_sparse_bootstrapping_key_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        prepared: PreparedSparseMap,
        output_key: &FourierGlweSecretKey,
        rng: &mut R,
    ) -> SparseGlweBootstrappingKey<T, NativeModulus<T>> {
        let PreparedSparseMap {
            map,
            selected_input_indices,
            hamming_weight,
            data_len,
        } = prepared;
        let parameters = self.context.parameters();
        let size = parameters.blind_rotation_params().size();

        // Flatten the private selectors in final bucket order, including each
        // dummy. One batch reuses level transforms across consecutive zeros;
        // fresh randomness and the original ciphertext order are preserved.
        let mut selectors = Zeroizing::new(Vec::with_capacity(
            map.input_indices().len() + selected_input_indices.len(),
        ));
        for (bucket, &selected_index) in selected_input_indices.iter().enumerate() {
            let start = map.bucket_offsets()[bucket];
            let end = map.bucket_offsets()[bucket + 1];
            selectors.extend(
                map.input_indices()[start..end]
                    .iter()
                    .chain(std::iter::once(&BucketMap::UNASSIGNED))
                    .map(|&index| {
                        if index == selected_index {
                            T::ONE
                        } else {
                            T::ZERO
                        }
                    }),
            );
        }
        drop(selected_input_indices);
        let gadget = parameters.blind_rotation_params();
        self.gadget.resize(size);
        let mut data = vec![T::ZERO; data_len];
        let mut transformed = FourierGgsw::<Vec<Complex64>>::zero(size.fourier_ggsw_len());
        output_key.encrypt_ggsw_constant_batch_coeff_to(
            &selectors,
            &mut data,
            gadget,
            &mut self.fft,
            rng,
            &mut self.gadget,
            transformed.as_mut(),
        );
        drop(selectors);

        SparseGlweBootstrappingKey::try_new(
            data,
            map,
            hamming_weight,
            gadget,
            parameters.small_lwe().cipher_modulus(),
        )
        .expect("prepared sparse map and coefficient storage must match")
    }
}
