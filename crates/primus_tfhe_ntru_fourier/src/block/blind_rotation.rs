//! Direct block aggregation with compulsory first-block public-LUT lifting.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_lattice::ntru::Ntru;
use primus_ntru::FourierNtruSplitWorkspace;

use super::BlockNtruBootstrappingKey;
use crate::grouped_rotation::{
    AggregationWorkspace, SplitAggregationWorkspace, rotate_groups, rotate_groups_split,
};

/// Consumes every block, including empty blocks and zero exponents. `scratch`
/// initially contains the public rotated LUT. The first block's NLEV aggregate
/// lifts that polynomial under f; subsequent NGSW aggregates rotate the encrypted
/// accumulator with the same ordinary Fourier arithmetic. Omitting an empty first
/// block would leave the public LUT unlifted. Output stays in `current`. Key,
/// basis, FFT and exponent/workspace layouts were bound upstream. Ordinary FFT
/// rounding remains part of the phase error; this is not a split-product path.
pub(crate) fn rotate_blocks<T: TorusFftValue, Table: FftTable>(
    key: &BlockNtruBootstrappingKey<T>,
    workspace: &mut AggregationWorkspace<T>,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
) {
    rotate_groups(blocks(key), workspace, current, scratch, basis, fft);
}

/// Preserves exact native aggregation, then canonically re-splits each complete
/// aggregate before its product. This includes the compulsory first-block lift;
/// no exponent, encrypted selector or dummy is omitted. Split precision belongs
/// to the aggregate workspace and remains independent of trace/SS precision.
pub(crate) fn rotate_blocks_split<T: TorusFftValue, Table: FftTable>(
    key: &BlockNtruBootstrappingKey<T>,
    workspace: &mut SplitAggregationWorkspace<T>,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    fft: &mut FftEngine<'_, Table>,
    split: &mut FourierNtruSplitWorkspace<T>,
) {
    rotate_groups_split(blocks(key), workspace, current, scratch, fft, split);
}

/// Direct controls and masks share contiguous, equally sized block order. The
/// complete key geometry was validated at construction, so no index table is
/// needed and chunking never discards a partial block.
pub(crate) fn blocks<T: TorusFftValue>(
    key: &BlockNtruBootstrappingKey<T>,
) -> impl Iterator<Item = (core::ops::Range<usize>, &[T])> {
    let block_size = key.block_size();
    let controls = key.controls();
    let controls_per_block =
        block_size + usize::from(key.occupancy() == primus_ntru::BlockOccupancy::AtMostOne);
    controls
        .as_slice()
        .chunks_exact(controls_per_block * controls.control_len())
        .enumerate()
        .map(move |(block, data)| {
            let start = block * block_size;
            (start..start + block_size, data)
        })
}

#[cfg(all(test, any(feature = "rustfft", feature = "tfhe-fft")))]
mod tests {
    use std::sync::Arc;

    use primus_decompose::DecompositionBaseLog;
    use primus_modulus::NativeModulus;
    use primus_ntru::{LweDimension, NlevParameters, NtruEncryptionParameters, SecretKeyDistr};
    use primus_reduce::TryReduceInv;
    use primus_shape::PolyLength;

    use super::*;

    /// The oracle exercises either production aggregate representation while
    /// keeping the integer fixture and expected phase independent of it.
    enum OracleWorkspace<T: TorusFftValue> {
        Ordinary(AggregationWorkspace<T>),
        Split(SplitAggregationWorkspace<T>),
    }

    impl<T: TorusFftValue> OracleWorkspace<T> {
        fn exponents(&mut self) -> &mut [usize] {
            match self {
                Self::Ordinary(workspace) => &mut workspace.exponents,
                Self::Split(workspace) => &mut workspace.exponents,
            }
        }

        /// Exercises each production single-input representation for the same
        /// integer fixture; pair results below must retain its exact arithmetic.
        fn rotate<Table: FftTable>(
            &mut self,
            key: &BlockNtruBootstrappingKey<T>,
            current: &mut Ntru<Vec<T>>,
            scratch: &mut Ntru<Vec<T>>,
            basis: &ApproxSignedBasis<T>,
            fft: &mut FftEngine<'_, Table>,
            split: Option<&mut FourierNtruSplitWorkspace<T>>,
        ) {
            match self {
                Self::Ordinary(workspace) => {
                    rotate_blocks(key, workspace, current, scratch, basis, fft);
                }
                Self::Split(workspace) => {
                    rotate_blocks_split(key, workspace, current, scratch, fft, split.unwrap());
                }
            }
        }
    }

    /// Noiseless constant odd f distinguishes first-block NLEV[g/f] from later
    /// NGSW[g]. The integer oracle independently rotates the LUT and compares
    /// f*c with its expected native-torus phase. Full base-16 decomposition
    /// removes gadget truncation. The absolute phase tolerances (32 for u32,
    /// 2^20 for u64) cover only these N=32, at-most-three-block FFT fixtures;
    /// they are neither a general Fourier error bound nor a DFR claim. Split
    /// fixtures use the same bound and reuse dirty buffers between rotations.
    fn block_rotation_oracle<T: TorusFftValue, Table: FftTable>(
        split_bits: Option<u32>,
        occupancy: primus_ntru::BlockOccupancy,
    ) {
        let n = 32;
        let modulus = NativeModulus::<T>::new();
        let table = Table::new(PolyLength::new(n));
        let mut fft = FftEngine::new(&table);
        let basis = ApproxSignedBasis::new(None, DecompositionBaseLog::new(4), None);
        let parameters = NlevParameters::try_from_parts(
            Arc::new(NtruEncryptionParameters::new(
                PolyLength::new(n),
                modulus,
                SecretKeyDistr::SparseTernary,
                0.7,
            )),
            basis,
        )
        .unwrap();
        let scale = T::ONE << (T::BITS - 10);
        let lut: Vec<_> = (0..n)
            .map(|i| T::as_from(i + 1).wrapping_mul(scale))
            .collect();
        let rotate = |exponent: usize| {
            let mut output = vec![T::ZERO; n];
            for (i, &value) in lut.iter().enumerate() {
                let degree = (i + exponent) & (2 * n - 1);
                output[degree & (n - 1)] = if degree < n {
                    value
                } else {
                    T::ZERO.wrapping_sub(value)
                };
            }
            output
        };
        let error_bound = if T::BITS == 32 { 32 } else { 1 << 20 };
        for secret in [T::ZERO.wrapping_sub(T::ONE), T::as_from(3)] {
            let inverse = modulus.try_reduce_inv(secret).unwrap();
            for (dimension, block_size) in [(3, 3), (6, 3), (10, 5), (21, 7)] {
                let block_count = dimension / block_size;
                let has_dummy = occupancy == primus_ntru::BlockOccupancy::AtMostOne;
                let controls_per_block = block_size + usize::from(has_dummy);
                for selection_pattern in 0..if has_dummy { 4 } else { 2 } {
                    let selected: Vec<_> = (0..block_count)
                        .map(|block| {
                            if !has_dummy {
                                Some(if selection_pattern == 0 {
                                    0
                                } else {
                                    block_size - 1
                                })
                            } else {
                                match selection_pattern {
                                    0 => None,
                                    1 if block != 0 => Some(block_size - 1),
                                    2 if block == 0 => Some(0),
                                    3 => Some(block_size - 1),
                                    _ => None,
                                }
                            }
                        })
                        .collect();
                    let control_len = parameters.nlev_len();
                    let mut data = vec![T::ZERO; block_count * controls_per_block * control_len];
                    for (block, controls) in data
                        .chunks_exact_mut(controls_per_block * control_len)
                        .enumerate()
                    {
                        for (position, control) in
                            controls.chunks_exact_mut(control_len).enumerate()
                        {
                            let one = if position == block_size {
                                selected[block].is_none()
                            } else {
                                selected[block] == Some(position)
                            };
                            if one {
                                for (row, scalar) in control
                                    .chunks_exact_mut(n)
                                    .zip(parameters.basis().scalar_iter())
                                {
                                    row[0] = if block == 0 {
                                        scalar.wrapping_mul(inverse)
                                    } else {
                                        scalar
                                    };
                                }
                            }
                        }
                    }
                    let key = BlockNtruBootstrappingKey::try_new(
                        data,
                        LweDimension::new(dimension),
                        block_size,
                        occupancy,
                        &parameters,
                    )
                    .unwrap();
                    let mut workspace = if let Some(low_bits) = split_bits {
                        OracleWorkspace::Split(AggregationWorkspace::new_split(
                            &parameters,
                            key.controls(),
                            low_bits,
                        ))
                    } else {
                        OracleWorkspace::Ordinary(AggregationWorkspace::new(
                            &parameters,
                            key.controls(),
                        ))
                    };
                    let mut split = split_bits
                        .map(|_| FourierNtruSplitWorkspace::new(parameters.poly_length()));
                    let mut second = crate::bootstrap::BlindRotationPairWorkspace::new(
                        &parameters,
                        LweDimension::new(dimension),
                    );
                    for nonzero_exponents in [false, true] {
                        let exponents = workspace.exponents();
                        for (i, exponent) in exponents.iter_mut().enumerate() {
                            *exponent = if nonzero_exponents {
                                [0, n, 2 * n - 1][i % 3]
                            } else {
                                0
                            };
                        }
                        let mask_rotation: usize = selected
                            .iter()
                            .enumerate()
                            .filter_map(|(block, &position)| {
                                position.map(|position| exponents[block * block_size + position])
                            })
                            .sum();
                        for b in [0, n, 2 * n - 1] {
                            let mut scratch = Ntru::new(rotate(b.wrapping_neg() & (2 * n - 1)));
                            let mut current = Ntru::new(vec![T::MAX; n]);
                            workspace.rotate(
                                &key,
                                &mut current,
                                &mut scratch,
                                parameters.basis(),
                                &mut fft,
                                split.as_mut(),
                            );
                            let expected = rotate(mask_rotation.wrapping_sub(b) & (2 * n - 1));
                            for (&actual, expected) in current.as_ref().iter().zip(expected) {
                                let phase = actual.wrapping_mul(secret);
                                let distance = phase
                                    .wrapping_sub(expected)
                                    .min(expected.wrapping_sub(phase));
                                let distance: u128 = distance.as_into();
                                assert!(
                                    distance <= error_bound,
                                    "FFT phase error {distance} exceeds fixture bound {error_bound}"
                                );
                            }
                            let first_output = current.as_ref().to_vec();
                            let first_exponents = workspace.exponents().to_vec();
                            // A distinct second rotation catches lane mixups;
                            // dirty pair/product buffers persist across cases.
                            for (i, exponent) in second.exponents.iter_mut().enumerate() {
                                *exponent = [2 * n - 1, n, 0][i % 3];
                            }
                            let second_body = (b + n / 2) & (2 * n - 1);
                            workspace.exponents().copy_from_slice(&second.exponents);
                            scratch
                                .as_mut()
                                .copy_from_slice(&rotate(second_body.wrapping_neg() & (2 * n - 1)));
                            workspace.rotate(
                                &key,
                                &mut current,
                                &mut scratch,
                                parameters.basis(),
                                &mut fft,
                                split.as_mut(),
                            );
                            let second_output = current.as_ref().to_vec();
                            workspace.exponents().copy_from_slice(&first_exponents);
                            current
                                .as_mut()
                                .copy_from_slice(&rotate(b.wrapping_neg() & (2 * n - 1)));
                            second
                                .current
                                .as_mut()
                                .copy_from_slice(&rotate(second_body.wrapping_neg() & (2 * n - 1)));
                            let buffers = [&mut current, &mut scratch];
                            match &mut workspace {
                                OracleWorkspace::Ordinary(workspace) => {
                                    crate::grouped_rotation::rotate_groups_pair(
                                        blocks(&key),
                                        workspace,
                                        &mut second,
                                        buffers,
                                        parameters.basis(),
                                        &mut fft,
                                    );
                                }
                                OracleWorkspace::Split(workspace) => {
                                    crate::grouped_rotation::rotate_groups_split_pair(
                                        blocks(&key),
                                        workspace,
                                        &mut second,
                                        buffers,
                                        &mut fft,
                                        split.as_mut().unwrap(),
                                    );
                                }
                            }
                            assert_eq!(current.as_ref(), first_output);
                            assert_eq!(second.current.as_ref(), second_output);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn block_lifting_matches_integer_oracle() {
        #[cfg(feature = "rustfft")]
        {
            block_rotation_oracle::<u32, primus_fft::RustFftTable>(
                None,
                primus_ntru::BlockOccupancy::AtMostOne,
            );
            for occupancy in [
                primus_ntru::BlockOccupancy::AtMostOne,
                primus_ntru::BlockOccupancy::ExactlyOne,
            ] {
                block_rotation_oracle::<u64, primus_fft::RustFftTable>(None, occupancy);
            }
        }
        #[cfg(feature = "tfhe-fft")]
        {
            block_rotation_oracle::<u32, primus_fft::TfheFftTable>(
                None,
                primus_ntru::BlockOccupancy::AtMostOne,
            );
            for occupancy in [
                primus_ntru::BlockOccupancy::AtMostOne,
                primus_ntru::BlockOccupancy::ExactlyOne,
            ] {
                block_rotation_oracle::<u64, primus_fft::TfheFftTable>(None, occupancy);
            }
        }
    }

    #[test]
    fn split_block_lifting_matches_integer_oracle() {
        for low_bits in [35, 40] {
            #[cfg(feature = "rustfft")]
            for occupancy in [
                primus_ntru::BlockOccupancy::AtMostOne,
                primus_ntru::BlockOccupancy::ExactlyOne,
            ] {
                block_rotation_oracle::<u64, primus_fft::RustFftTable>(Some(low_bits), occupancy);
            }
            #[cfg(feature = "tfhe-fft")]
            for occupancy in [
                primus_ntru::BlockOccupancy::AtMostOne,
                primus_ntru::BlockOccupancy::ExactlyOne,
            ] {
                block_rotation_oracle::<u64, primus_fft::TfheFftTable>(Some(low_bits), occupancy);
            }
        }
    }
}
