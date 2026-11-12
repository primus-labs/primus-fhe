//! Direct block aggregation, public-LUT lift and NTT products.

use std::ops::Range;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{
    nlev::{Nlev, NlevIter},
    ntru::Ntru,
};
use primus_modulus::BarrettModulus;
use primus_ntru::{NlevParameters, NttNtruExternalProductWorkspace};
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use primus_reduce::ReduceOnceSlice;

use super::BlockNtruBootstrappingKey;
use crate::bootstrap::BlindRotationPairWorkspace;

/// Reusable aggregate and product scratch, independent of block geometry.
pub(crate) struct AggregationWorkspace<T: FheUint> {
    pub(crate) exponents: Vec<usize>,
    aggregate: Vec<T>,
    pub(crate) external_product: NttNtruExternalProductWorkspace<T>,
}

impl<T: FheUint> AggregationWorkspace<T> {
    pub(crate) fn new(
        parameters: &NlevParameters<T, BarrettModulus<T>>,
        key: &BlockNtruBootstrappingKey<T>,
    ) -> Self {
        Self {
            exponents: vec![0; key.input_dimension().get()],
            aggregate: vec![T::ZERO; key.control_len()],
            external_product: NttNtruExternalProductWorkspace::new(parameters.poly_length()),
        }
    }
}

/// The first block's NLEV aggregate lifts public P; later blocks actually hold
/// `NGSW[H] = NLEV[f*H]` and act on ciphertexts. Their product arithmetic agrees,
/// so the same loop consumes every block, including encrypted zeros and any
/// dummy. On entry, `scratch` holds the public rotated LUT. The final
/// coefficient-domain result stays in `current`.
pub(crate) fn rotate_blocks<T, Table>(
    key: &BlockNtruBootstrappingKey<T>,
    workspace: &mut AggregationWorkspace<T>,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    basis: &ApproxSignedBasis<T>,
    modulus: BarrettModulus<T>,
    ntt: &Table,
) where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    let n = ntt.poly_length().get();
    core::mem::swap(current, scratch);
    for (indices, selections, dummy) in key.blocks() {
        aggregate_controls(
            indices,
            selections,
            dummy,
            [(
                &workspace.exponents,
                Nlev::new(workspace.aggregate.as_mut_slice()),
            )],
            n,
            modulus,
        );
        let aggregate = Nlev::new(workspace.aggregate.as_mut_slice()).into_ntt_form(ntt);
        aggregate.external_product_to(
            &Polynomial(current.as_ref()),
            scratch,
            basis,
            modulus,
            ntt,
            &mut workspace.external_product,
        );
        core::mem::swap(current, scratch);
    }
}

/// Aggregates each block's controls for both inputs before advancing, preserving
/// each input's control order. Both current buffers initially hold independent
/// public LUT rotations: the complete first block, including any dummy, lifts
/// each through NLEV; later NGSW blocks use the same external-product arithmetic.
/// Transform/product scratch is shared serially, with final results in the two
/// current buffers. The caller established all key, exponent and buffer geometry.
pub(crate) fn rotate_blocks_pair<T, Table>(
    key: &BlockNtruBootstrappingKey<T>,
    workspace: &mut AggregationWorkspace<T>,
    second: &mut BlindRotationPairWorkspace<T>,
    buffers: [&mut Ntru<Vec<T>>; 2],
    basis: &ApproxSignedBasis<T>,
    modulus: BarrettModulus<T>,
    ntt: &Table,
) where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    let [current, scratch] = buffers;
    let n = ntt.poly_length().get();
    for (indices, selections, dummy) in key.blocks() {
        aggregate_controls(
            indices,
            selections,
            dummy,
            [
                (
                    &workspace.exponents,
                    Nlev::new(workspace.aggregate.as_mut_slice()),
                ),
                (
                    &second.exponents,
                    Nlev::new(second.aggregate.as_mut_slice()),
                ),
            ],
            n,
            modulus,
        );
        for (aggregate, current) in [
            (&mut workspace.aggregate, &mut *current),
            (&mut second.aggregate, &mut second.current),
        ] {
            let aggregate = Nlev::new(aggregate.as_mut_slice()).into_ntt_form(ntt);
            aggregate.external_product_to(
                &Polynomial(current.as_ref()),
                scratch,
                basis,
                modulus,
                ntt,
                &mut workspace.external_product,
            );
            core::mem::swap(current, scratch);
        }
    }
}

/// Starts from the encrypted dummy when present, otherwise clears the aggregate,
/// then adds every selector in key order. The iterator selects coordinates
/// from each input's exponent slice. Pairing shares an accumulator traversal
/// and includes zero exponents and encrypted zeros. An odd final selector uses
/// the single-product kernel. For u64, pairs retain [0,2q) residues until one
/// final normalization before NTT. Other widths retain canonical updates.
/// The key and workspace establish complete, equally sized controls and
/// canonical source residues.
/// Instantiated only for one input or the fixed two-input window.
#[inline]
fn aggregate_controls<T: FheUint, const INPUTS: usize>(
    indices: Range<usize>,
    selections: &[T],
    dummy: &[T],
    mut inputs: [(&[usize], Nlev<&mut [T]>); INPUTS],
    poly_length: usize,
    modulus: BarrettModulus<T>,
) {
    let control_len = inputs[0].1.as_ref().len();
    for (_, aggregate) in &mut inputs {
        if dummy.is_empty() {
            aggregate.as_mut().fill(T::ZERO);
        } else {
            aggregate.as_mut().copy_from_slice(dummy);
        }
    }
    let mut controls = indices.zip(NlevIter::new(selections, control_len));
    while let Some((first_index, first)) = controls.next() {
        if let Some((second_index, second)) = controls.next() {
            for (exponents, aggregate) in &mut inputs {
                let exponent = exponents[first_index];
                if T::BITS == 64 {
                    primus_poly::lazy_add_mul_monomial_pair_assign(
                        aggregate.as_mut(),
                        first.as_ref(),
                        exponent,
                        second.as_ref(),
                        exponents[second_index],
                        poly_length,
                        modulus,
                    );
                } else {
                    aggregate.add_mul_monomial_pair_assign(
                        &first,
                        exponent,
                        &second,
                        exponents[second_index],
                        poly_length,
                        modulus,
                    );
                }
            }
        } else {
            for (exponents, aggregate) in &mut inputs {
                let exponent = exponents[first_index];
                if T::BITS == 64 {
                    primus_poly::lazy_add_mul_monomial_assign(
                        aggregate.as_mut(),
                        first.as_ref(),
                        exponent,
                        poly_length,
                        modulus,
                    );
                } else {
                    aggregate.add_mul_monomial_assign(&first, exponent, poly_length, modulus);
                }
            }
        }
    }
    if T::BITS == 64 {
        for (_, aggregate) in &mut inputs {
            modulus.reduce_once_slice_assign(aggregate.as_mut());
        }
    }
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
                let mut workspace = AggregationWorkspace::new(&parameters, &key);
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
