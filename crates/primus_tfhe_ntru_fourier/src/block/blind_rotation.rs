//! Direct block aggregation with compulsory first-block public-LUT lifting.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_lattice::ntru::Ntru;

use super::BlockNtruBootstrappingKey;
use crate::sparse::{AggregationWorkspace, rotate_groups};

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
    let block_size = key.block_size();
    let controls = key.controls();
    let groups = controls
        .as_slice()
        .chunks_exact((block_size + 1) * controls.control_len())
        .enumerate()
        .map(|(block, data)| {
            let start = block * block_size;
            (start..start + block_size, data)
        });
    rotate_groups(groups, workspace, current, scratch, basis, fft);
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

    /// Noiseless constant odd f distinguishes first-block NLEV[g/f] from later
    /// NGSW[g]. The integer oracle independently rotates the LUT and compares
    /// f*c with its expected native-torus phase. Full base-16 decomposition
    /// removes gadget truncation. The absolute phase tolerances (32 for u32,
    /// 2^20 for u64) cover only these N=32, at-most-three-block FFT fixtures;
    /// they are neither a general Fourier error bound nor a DFR claim.
    fn block_rotation_oracle<T: TorusFftValue, Table: FftTable>() {
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
                let blocks = dimension / block_size;
                for selection_pattern in 0..4 {
                    let selected: Vec<_> = (0..blocks)
                        .map(|block| match selection_pattern {
                            0 => None,
                            1 if block != 0 => Some(block_size - 1),
                            2 if block == 0 => Some(0),
                            3 => Some(block_size - 1),
                            _ => None,
                        })
                        .collect();
                    let control_len = parameters.nlev_len();
                    let mut data = vec![T::ZERO; (dimension + blocks) * control_len];
                    for (block, controls) in data
                        .chunks_exact_mut((block_size + 1) * control_len)
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
                                position.map(|position| {
                                    workspace.exponents[block * block_size + position]
                                })
                            })
                            .sum();
                        for b in [0, n, 2 * n - 1] {
                            let mut scratch = Ntru::new(rotate(b.wrapping_neg() & (2 * n - 1)));
                            let mut current = Ntru::zero(n);
                            rotate_blocks(
                                &key,
                                &mut workspace,
                                &mut current,
                                &mut scratch,
                                parameters.basis(),
                                &mut fft,
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
                                    "ordinary FFT phase error {distance} exceeds fixture bound {error_bound}"
                                );
                            }
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
            block_rotation_oracle::<u32, primus_fft::RustFftTable>();
            block_rotation_oracle::<u64, primus_fft::RustFftTable>();
        }
        #[cfg(feature = "tfhe-fft")]
        {
            block_rotation_oracle::<u32, primus_fft::TfheFftTable>();
            block_rotation_oracle::<u64, primus_fft::TfheFftTable>();
        }
    }
}
