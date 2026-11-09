use primus_glwe::{
    GgswParameters, NttGlweGadgetEncryptWorkspace, NttGlweSecretKey, SecretKeyDistr,
};
use primus_integer::FheUint;
use primus_lwe::LweSecretKey;
use primus_modulus::{BarrettModulus, NativeModulus, UintModulus};
use primus_ntt::MonomialNttTable;
use primus_tfhe::sparse::BucketMap;
use std::alloc::Layout;
use zeroize::Zeroizing;

use crate::{KeyGenerationError, SparseBootstrappingKeyError, sparse::SparseGlweBootstrappingKey};

/// Validated bucket geometry and ciphertext allocation size, before secret sampling.
/// Kept only during setup; the map and key retain their own final metadata.
pub(crate) struct SparseKeyLayout {
    copy_count: usize,
    bucket_count: usize,
    hamming_weight: usize,
    data_len: usize,
}

impl SparseKeyLayout {
    /// Validates public sparse choices before allocating keys or consuming randomness.
    pub(crate) fn try_new<T: FheUint>(
        dimension: usize,
        distribution: SecretKeyDistr,
        gadget: &GgswParameters<T, BarrettModulus<T>>,
        copy_count: usize,
        bucket_count: usize,
    ) -> Result<SparseKeyLayout, KeyGenerationError> {
        use SparseBootstrappingKeyError as Error;
        let SecretKeyDistr::FixedHammingWeightBinary { hamming_weight } = distribution else {
            return Err(Error::UnsupportedSecretDistribution.into());
        };
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
            .and_then(|count| count.checked_mul(gadget.ggsw_len()))
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
}

/// Reuses the accepted accumulator transform for BR and optional CBS.
/// Only sparse support/matching checks remain after setup validation.
pub(crate) fn generate_with_layout<T: FheUint, Table, R>(
    input: &LweSecretKey<T>,
    layout: SparseKeyLayout,
    output_key: &NttGlweSecretKey<T>,
    gadget: &GgswParameters<T, BarrettModulus<T>>,
    ntt: &Table,
    rng: &mut R,
    workspace: &mut NttGlweGadgetEncryptWorkspace<T>,
) -> Result<SparseGlweBootstrappingKey<T, BarrettModulus<T>>, KeyGenerationError>
where
    Table: MonomialNttTable<ValueT = T>,
    R: rand::Rng + rand::CryptoRng,
{
    use SparseBootstrappingKeyError as Error;
    let SparseKeyLayout {
        copy_count,
        bucket_count,
        hamming_weight,
        data_len,
    } = layout;
    let input_dimension = input.dimension();
    let size = gadget.size();
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

    let mut data = vec![T::ZERO; data_len];
    let max_bucket_len = map
        .bucket_offsets()
        .windows(2)
        .map(|pair| pair[1] - pair[0] + 1)
        .max()
        .unwrap();
    let mut constants = Zeroizing::new(Vec::with_capacity(max_bucket_len));
    for (bucket, &selected_index) in selected_input_indices.iter().enumerate() {
        let start = map.bucket_offsets()[bucket];
        let end = map.bucket_offsets()[bucket + 1];
        constants.clear();
        constants.extend(map.input_indices()[start..end].iter().map(|&index| {
            if index == selected_index {
                T::ONE
            } else {
                T::ZERO
            }
        }));
        constants.push(if selected_index == BucketMap::UNASSIGNED {
            T::ONE
        } else {
            T::ZERO
        });
        let output =
            &mut data[(start + bucket) * size.ggsw_len()..(end + bucket + 1) * size.ggsw_len()];
        output_key
            .encrypt_ggsw_constant_batch_coeff_to(&constants, output, gadget, ntt, rng, workspace);
    }

    // Only q metadata is retained; BR arithmetic uses the target ring modulus.
    if input.cipher_modulus_minus_one() == T::MAX {
        Ok(SparseGlweBootstrappingKey::try_new(
            data,
            map,
            hamming_weight,
            gadget,
            NativeModulus::<T>::new(),
        )?)
    } else {
        Ok(SparseGlweBootstrappingKey::try_new(
            data,
            map,
            hamming_weight,
            gadget,
            UintModulus::new(input.cipher_modulus_minus_one() + T::ONE),
        )?)
    }
}
