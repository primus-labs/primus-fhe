//! Direct block aggregation, public-LUT lift and Fourier products.

use std::ops::Range;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::{
    nlev::{FourierNlev, Nlev, NlevIter},
    ntru::Ntru,
};
use primus_modulus::NativeModulus;
use primus_ntru::{
    FourierNtruExternalProductWorkspace, FourierNtruSplitGadget, FourierNtruSplitWorkspace,
    NlevParameters,
};
use primus_poly::Polynomial;

use super::BlockNtruBootstrappingKey;
use crate::bootstrap::BlindRotationPairWorkspace;

mod aggregation;

/// Reusable aggregate and product scratch, independent of block geometry.
pub(crate) struct AggregationWorkspace<T: TorusFftValue, Transformed = Vec<Complex64>> {
    pub(crate) exponents: Vec<usize>,
    aggregate: Vec<T>,
    transformed: Transformed,
    pub(crate) external_product: FourierNtruExternalProductWorkspace<T>,
}

impl<T: TorusFftValue> AggregationWorkspace<T> {
    pub(crate) fn new(
        parameters: &NlevParameters<T, NativeModulus<T>>,
        key: &BlockNtruBootstrappingKey<T>,
    ) -> Self {
        Self::with_transformed(
            parameters,
            key,
            vec![Complex64::ZERO; parameters.fourier_nlev_len()],
        )
    }
}

impl<T: TorusFftValue> AggregationWorkspace<T, FourierNtruSplitGadget<T>> {
    /// Allocates only the selected two-limb aggregate representation. Exact
    /// native coefficients and product scratch are shared with the ordinary
    /// layout; no permanent per-control Fourier material is retained.
    pub(crate) fn new_split(
        parameters: &NlevParameters<T, NativeModulus<T>>,
        key: &BlockNtruBootstrappingKey<T>,
        low_bits: u32,
    ) -> Self {
        Self::with_transformed(
            parameters,
            key,
            FourierNtruSplitGadget::zero(parameters.poly_length(), parameters.basis(), low_bits),
        )
    }
}

impl<T: TorusFftValue, Transformed> AggregationWorkspace<T, Transformed> {
    /// Common geometry owns one coefficient aggregate and one product workspace;
    /// the caller supplies exactly the Fourier representation used online.
    fn with_transformed(
        parameters: &NlevParameters<T, NativeModulus<T>>,
        key: &BlockNtruBootstrappingKey<T>,
        transformed: Transformed,
    ) -> Self {
        Self {
            exponents: vec![0; key.input_dimension().get()],
            aggregate: vec![T::ZERO; key.control_len()],
            transformed,
            external_product: FourierNtruExternalProductWorkspace::new(parameters.poly_length()),
        }
    }
}

/// Split payload for block rotation using a two-limb Fourier product.
pub(crate) type SplitAggregationWorkspace<T> = AggregationWorkspace<T, FourierNtruSplitGadget<T>>;

/// `scratch` holds the rotated public LUT on entry. The first block's NLEV
/// aggregate lifts it, then later `NGSW[H] = NLEV[f*H]` aggregates act on
/// ciphertexts with the same product arithmetic. Every encrypted selector
/// and dummy contributes, including zeros. The result stays in `current`.
pub(crate) fn rotate_blocks<T, Table>(
    key: &BlockNtruBootstrappingKey<T>,
    workspace: &mut AggregationWorkspace<T>,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
) where
    T: TorusFftValue,
    Table: FftTable,
{
    let n = fft.poly_length().get();
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
        );
        let mut transformed = FourierNlev::new(workspace.transformed.as_mut_slice());
        Nlev::new(workspace.aggregate.as_slice()).write_fourier_form(&mut transformed, fft);
        transformed.external_product_to(
            &Polynomial(current.as_ref()),
            scratch,
            basis,
            fft,
            &mut workspace.external_product,
        );
        core::mem::swap(current, scratch);
    }
}

/// Exact native aggregation precedes canonical limb splitting. In particular,
/// negacyclic signs and wrapping carries are applied before extracting low/high
/// bits; rotating or adding already split spectra would miss limb carries.
/// The first NLEV aggregate always lifts the public LUT, even for an empty block
/// or zero exponents. Later NGSW aggregates use the same two-limb product. Product
/// digits are dead while refreshing the gadget and are overwritten by the next
/// decomposition; no additional coefficient scratch is required.
pub(crate) fn rotate_blocks_split<T, Table>(
    key: &BlockNtruBootstrappingKey<T>,
    workspace: &mut SplitAggregationWorkspace<T>,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    fft: &mut FftEngine<'_, Table>,
    split: &mut FourierNtruSplitWorkspace<T>,
) where
    T: TorusFftValue,
    Table: FftTable,
{
    let n = fft.poly_length().get();
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
        );
        workspace.transformed.set_from_coefficients(
            &workspace.aggregate,
            fft,
            &mut workspace.external_product,
        );
        workspace.transformed.external_product_to(
            current.as_ref(),
            scratch.as_mut(),
            fft,
            &mut workspace.external_product,
            split,
        );
        core::mem::swap(current, scratch);
    }
}

/// Aggregates a block for both inputs before advancing, preserving
/// source order and each input's compulsory first-block public-LUT lift. Both
/// current buffers contain their rotated public LUT on entry. Ordinary transforms
/// and products run serially through one shared workspace; final results remain
/// in the two current buffers, regardless of the number of blocks.
pub(crate) fn rotate_blocks_pair<T, Table>(
    key: &BlockNtruBootstrappingKey<T>,
    workspace: &mut AggregationWorkspace<T>,
    second: &mut BlindRotationPairWorkspace<T>,
    buffers: [&mut Ntru<Vec<T>>; 2],
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
) where
    T: TorusFftValue,
    Table: FftTable,
{
    let [current, scratch] = buffers;
    let n = fft.poly_length().get();
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
        );
        // First-block NLEV and later NGSW use the same product arithmetic.
        for (aggregate, current) in [
            (&mut workspace.aggregate, &mut *current),
            (&mut second.aggregate, &mut second.current),
        ] {
            let mut transformed = FourierNlev::new(workspace.transformed.as_mut_slice());
            Nlev::new(aggregate.as_slice()).write_fourier_form(&mut transformed, fft);
            transformed.external_product_to(
                &Polynomial(current.as_ref()),
                scratch,
                basis,
                fft,
                &mut workspace.external_product,
            );
            core::mem::swap(current, scratch);
        }
    }
}

/// Both native aggregates are complete before either is split. Each lane then
/// overwrites the same low/high spectra and independently recovers its product
/// before the other lane reuses those buffers. Native wrapping carries and
/// negacyclic signs therefore precede canonical limb extraction, exactly as in
/// single-input split BR. No second spectra or split/product workspace is kept.
pub(crate) fn rotate_blocks_split_pair<T, Table>(
    key: &BlockNtruBootstrappingKey<T>,
    workspace: &mut SplitAggregationWorkspace<T>,
    second: &mut BlindRotationPairWorkspace<T>,
    buffers: [&mut Ntru<Vec<T>>; 2],
    fft: &mut FftEngine<'_, Table>,
    split: &mut FourierNtruSplitWorkspace<T>,
) where
    T: TorusFftValue,
    Table: FftTable,
{
    let [current, scratch] = buffers;
    let n = fft.poly_length().get();
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
        );
        for (aggregate, current) in [
            (&workspace.aggregate, &mut *current),
            (&second.aggregate, &mut second.current),
        ] {
            workspace.transformed.set_from_coefficients(
                aggregate,
                fft,
                &mut workspace.external_product,
            );
            workspace.transformed.external_product_to(
                current.as_ref(),
                scratch.as_mut(),
                fft,
                &mut workspace.external_product,
                split,
            );
            core::mem::swap(current, scratch);
        }
    }
}

/// Starts from the encrypted dummy when present, otherwise clears the aggregate,
/// then adds every selector in key order. The iterator selects coordinates from
/// each input's complete exponent slice. For u64, four controls share a
/// coefficient traversal; u32 retains the pair path.
/// Remaining controls use pairs and a possible single tail. No zero exponent
/// or encrypted zero is skipped. The key/workspace establish complete, equally
/// sized controls, and native wrapping preserves the coefficient representation.
/// Instantiated only for one input or the fixed two-input window.
#[inline]
fn aggregate_controls<T: TorusFftValue, const INPUTS: usize>(
    mut indices: Range<usize>,
    selections: &[T],
    dummy: &[T],
    mut inputs: [(&[usize], Nlev<&mut [T]>); INPUTS],
    poly_length: usize,
) {
    let modulus = NativeModulus::new();
    let control_len = inputs[0].1.as_ref().len();
    for (_, aggregate) in &mut inputs {
        if dummy.is_empty() {
            aggregate.as_mut().fill(T::ZERO);
        } else {
            aggregate.as_mut().copy_from_slice(dummy);
        }
    }
    let mut controls = NlevIter::new(selections, control_len);
    if T::BITS == 64 {
        for _ in 0..indices.len() / 4 {
            let indices: [usize; 4] =
                core::array::from_fn(|_| indices.next().expect("complete control indices"));
            let sources: [Nlev<&[T]>; 4] =
                core::array::from_fn(|_| controls.next().expect("complete block controls"));
            for (exponents, aggregate) in &mut inputs {
                aggregation::add_four_rotations_assign(
                    aggregate.as_mut(),
                    sources.each_ref().map(|control| control.as_ref()),
                    indices.map(|i| exponents[i]),
                    poly_length,
                );
            }
        }
    }
    // Finish the u64 tail (0..3 controls); u32 uses this pair/single loop for
    // the whole block. Preserve source order and per-lane wrapping arithmetic.
    let mut controls = indices.zip(controls);
    while let Some((first_index, first)) = controls.next() {
        let second = controls.next();
        for (exponents, aggregate) in &mut inputs {
            let exponent = exponents[first_index];
            if let Some((second_index, ref second)) = second {
                aggregate.add_mul_monomial_pair_assign(
                    &first,
                    exponent,
                    second,
                    exponents[second_index],
                    poly_length,
                    modulus,
                );
            } else {
                aggregate.add_mul_monomial_assign(&first, exponent, poly_length, modulus);
            }
        }
    }
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
                            &key,
                            low_bits,
                        ))
                    } else {
                        OracleWorkspace::Ordinary(AggregationWorkspace::new(&parameters, &key))
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
                                    rotate_blocks_pair(
                                        &key,
                                        workspace,
                                        &mut second,
                                        buffers,
                                        parameters.basis(),
                                        &mut fft,
                                    );
                                }
                                OracleWorkspace::Split(workspace) => {
                                    rotate_blocks_split_pair(
                                        &key,
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
