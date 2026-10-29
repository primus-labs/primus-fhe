//! Direct block aggregation with compulsory first-block public-LUT lifting.

use std::ops::Range;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::ntru::Ntru;
use primus_modulus::BarrettModulus;
use primus_ntt::MonomialNttTable;

use super::BlockNtruBootstrappingKey;
use crate::{
    bootstrap::BlindRotationPairWorkspace,
    sparse::{AggregationWorkspace, rotate_groups, rotate_groups_pair},
};

/// Consumes every block, including empty blocks and zero exponents. `scratch`
/// initially contains the public rotated LUT. The first block's NLEV aggregate
/// lifts that polynomial under f; subsequent NGSW aggregates rotate the encrypted
/// accumulator with the same arithmetic. Omitting an empty first block would
/// leave the public LUT unlifted. Final coefficient output stays in `current`.
/// Key, basis, modulus, table and exponent/workspace layouts were bound upstream.
pub(crate) fn rotate_blocks<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    key: &BlockNtruBootstrappingKey<T>,
    workspace: &mut AggregationWorkspace<T>,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    basis: &ApproxSignedBasis<T>,
    modulus: BarrettModulus<T>,
    ntt: &Table,
) {
    rotate_groups(
        block_groups(key),
        workspace,
        current,
        scratch,
        basis,
        modulus,
        ntt,
    );
}

/// Visits each contiguous block for both inputs without bucket maps or replicated
/// controls. Both current buffers hold the public LUT rotation on entry, so the
/// entire first block must be consumed for both NLEV lifts, including empty blocks.
/// The owning evaluator established key, exponent and workspace compatibility.
pub(crate) fn rotate_blocks_pair<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    key: &BlockNtruBootstrappingKey<T>,
    workspace: &mut AggregationWorkspace<T>,
    second: &mut BlindRotationPairWorkspace<T>,
    buffers: [&mut Ntru<Vec<T>>; 2],
    basis: &ApproxSignedBasis<T>,
    modulus: BarrettModulus<T>,
    ntt: &Table,
) {
    rotate_groups_pair(
        block_groups(key),
        workspace,
        second,
        buffers,
        basis,
        modulus,
        ntt,
    );
}

/// Exposes each complete bit group, any mode-required dummy and its contiguous
/// input coordinates; the direct-block layout needs no persistent index map.
fn block_groups<T: FheUint>(
    key: &BlockNtruBootstrappingKey<T>,
) -> impl Iterator<Item = (Range<usize>, &[T])> {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use primus_decompose::DecompositionBaseLog;
    use primus_ntru::{NlevParameters, NtruEncryptionParameters, SecretKeyDistr};
    use primus_ntt::{U32NttTable, U64NttTable};
    use primus_reduce::{ReduceInv, ReduceMul};
    use primus_shape::PolyLength;

    use super::*;

    /// A noise-free constant secret f=3 separates first-block NLEV weights g/3
    /// from later NGSW weights g. The independent integer oracle checks the phase
    /// rather than sharing production monomial multiplication or decomposition.
    fn block_rotation_oracle<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
        q: u64,
        occupancy: primus_ntru::BlockOccupancy,
    ) {
        let n = 32;
        let modulus = BarrettModulus::new(T::as_from(q));
        let table = Table::new(PolyLength::new(n), modulus).unwrap();
        let basis = ApproxSignedBasis::new(Some(T::as_from(q)), DecompositionBaseLog::new(2), None);
        let parameters = NlevParameters::try_from_parts(
            Arc::new(NtruEncryptionParameters::new(
                PolyLength::new(n),
                modulus,
                SecretKeyDistr::Binary {
                    one_probability: 0.5,
                },
                0.7,
            )),
            basis,
        )
        .unwrap();
        let inverse = modulus.reduce_inv(T::as_from(3));
        let lut: Vec<i128> = (0..n).map(|i| i as i128 + 1).collect();
        let rotate = |exponent: usize| {
            let mut output = vec![0i128; n];
            for (i, &value) in lut.iter().enumerate() {
                let degree = (i + exponent) & (2 * n - 1);
                output[degree & (n - 1)] = if degree < n { value } else { -value };
            }
            output
        };

        for (dimension, block_size) in [(3, 3), (6, 3), (10, 5)] {
            let blocks = dimension / block_size;
            let has_dummy = occupancy == primus_ntru::BlockOccupancy::AtMostOne;
            let controls_per_block = block_size + usize::from(has_dummy);
            for selection_pattern in 0..if has_dummy { 4 } else { 2 } {
                let selected: Vec<_> = (0..blocks)
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
                let mut data = vec![T::ZERO; blocks * controls_per_block * control_len];
                for (block, controls) in data
                    .chunks_exact_mut(controls_per_block * control_len)
                    .enumerate()
                {
                    for (position, control) in controls.chunks_exact_mut(control_len).enumerate() {
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
                                    modulus.reduce_mul(scalar, inverse)
                                } else {
                                    scalar
                                };
                            }
                        }
                    }
                }
                let key = BlockNtruBootstrappingKey::try_new(
                    data,
                    primus_lwe::LweDimension::new(dimension),
                    block_size,
                    occupancy,
                    &parameters,
                )
                .unwrap();
                let mut workspace = AggregationWorkspace::new(&parameters, key.controls());
                for nonzero_exponents in [false, true] {
                    for (i, exponent) in workspace.exponents.iter_mut().enumerate() {
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
                            position
                                .map(|position| workspace.exponents[block * block_size + position])
                        })
                        .sum();
                    for b in [0, n, 2 * n - 1] {
                        let public = rotate(b.wrapping_neg() & (2 * n - 1));
                        let mut scratch = Ntru::new(
                            public
                                .iter()
                                .map(|&value| T::as_from(value.rem_euclid(q as i128)))
                                .collect::<Vec<_>>(),
                        );
                        let mut current = Ntru::zero(n);
                        rotate_blocks(
                            &key,
                            &mut workspace,
                            &mut current,
                            &mut scratch,
                            parameters.basis(),
                            modulus,
                            &table,
                        );
                        let expected = rotate(mask_rotation.wrapping_sub(b) & (2 * n - 1));
                        for (&actual, expected) in current.as_ref().iter().zip(expected) {
                            let actual: u128 = actual.as_into();
                            assert!(actual < q as u128);
                            assert_eq!(
                                actual * 3 % q as u128,
                                expected.rem_euclid(q as i128) as u128
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn block_lifting_matches_integer_oracle() {
        for occupancy in [
            primus_ntru::BlockOccupancy::AtMostOne,
            primus_ntru::BlockOccupancy::ExactlyOne,
        ] {
            block_rotation_oracle::<u32, U32NttTable>(998_244_353, occupancy);
            block_rotation_oracle::<u64, U64NttTable>(1_125_899_906_826_241, occupancy);
        }
    }
}
