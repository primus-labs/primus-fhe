//! Bucket aggregation and reusable sparse blind-rotation workspace.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::{
    nlev::{FourierNlev, Nlev, NlevIter},
    ntru::Ntru,
};
use primus_lwe::LweDimension;
use primus_modulus::NativeModulus;
use primus_ntru::{
    FourierNtruExternalProductWorkspace, FourierNtruSplitGadget, FourierNtruSplitWorkspace,
    NlevParameters,
};
use primus_poly::Polynomial;
use primus_tfhe_ntru::NtruBlindRotationControls;

use super::SparseNtruBootstrappingKey;

/// Reusable aggregate and product scratch, independent of bucket geometry.
pub(crate) struct AggregationWorkspace<T: TorusFftValue, Transformed = Vec<Complex64>> {
    pub(crate) exponents: Vec<usize>,
    aggregate: Vec<T>,
    transformed: Transformed,
    pub(crate) external_product: FourierNtruExternalProductWorkspace<T>,
}

impl<T: TorusFftValue> AggregationWorkspace<T> {
    pub(crate) fn new(
        parameters: &NlevParameters<T, NativeModulus<T>>,
        controls: &NtruBlindRotationControls<T>,
    ) -> Self {
        Self::with_transformed(
            parameters,
            controls,
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
        controls: &NtruBlindRotationControls<T>,
        low_bits: u32,
    ) -> Self {
        Self::with_transformed(
            parameters,
            controls,
            FourierNtruSplitGadget::zero(parameters.poly_length(), parameters.basis(), low_bits),
        )
    }
}

impl<T: TorusFftValue, Transformed> AggregationWorkspace<T, Transformed> {
    /// Common geometry owns one coefficient aggregate and one product workspace;
    /// the caller supplies exactly the Fourier representation used online.
    fn with_transformed(
        parameters: &NlevParameters<T, NativeModulus<T>>,
        controls: &NtruBlindRotationControls<T>,
        transformed: Transformed,
    ) -> Self {
        Self {
            exponents: vec![0; controls.input_dimension().get()],
            aggregate: vec![T::ZERO; controls.control_len()],
            transformed,
            external_product: FourierNtruExternalProductWorkspace::new(parameters.poly_length()),
        }
    }
}

/// Split payload for direct-block rotation; sparse controls retain ordinary FFT.
pub(crate) type SplitAggregationWorkspace<T> = AggregationWorkspace<T, FourierNtruSplitGadget<T>>;

/// Additional state for a second sparse blind-rotation input.
/// Allocate through [`crate::circuit_bootstrap::OneHotCircuitBootstrapEvaluator::new_sparse_pair_workspace`].
/// Retains only exponents, an L*N coefficient aggregate and one N-coefficient
/// accumulator; the original resources provide shared transform/product scratch.
pub struct SparseBlindRotationPairWorkspace<T: TorusFftValue> {
    pub(crate) exponents: Vec<usize>,
    pub(crate) aggregate: Vec<T>,
    pub(crate) current: Ntru<Vec<T>>,
}

impl<T: TorusFftValue> SparseBlindRotationPairWorkspace<T> {
    pub(crate) fn new(
        parameters: &NlevParameters<T, NativeModulus<T>>,
        input_dimension: LweDimension,
    ) -> Self {
        Self {
            exponents: vec![0; input_dimension.get()],
            aggregate: vec![T::ZERO; parameters.nlev_len()],
            current: Ntru::zero(parameters.poly_length().get()),
        }
    }
}

/// The evaluator established key/workspace/table compatibility and quantized every mask.
/// Every bucket is processed, including empty ones and zero exponents; its encrypted
/// dummy and zero selections still contribute noise. `scratch` initially holds the
/// public rotated LUT. Bucket zero lifts it with NLEV controls; later buckets use
/// NGSW controls. Final output stays in `current`, even with just one bucket.
pub(crate) fn rotate_buckets<T: TorusFftValue, Table: FftTable>(
    key: &SparseNtruBootstrappingKey<T>,
    workspace: &mut AggregationWorkspace<T>,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
) {
    let groups = (0..key.bucket_count()).map(|bucket| {
        let (indices, data) = key.bucket_data(bucket);
        (indices.iter().copied(), data)
    });
    rotate_groups(groups, workspace, current, scratch, basis, fft);
}

/// The first group's NLEV aggregate lifts public P; subsequent groups hold
/// `NGSW[H] = NLEV[f*H]` and act on ciphertexts. Their product arithmetic agrees,
/// so sparse buckets and direct blocks share this loop without a first-group
/// branch. Every encrypted selector and dummy contributes, including zeros.
pub(crate) fn rotate_groups<'a, T, Table, I>(
    groups: impl Iterator<Item = (I, &'a [T])>,
    workspace: &mut AggregationWorkspace<T>,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
) where
    T: TorusFftValue,
    Table: FftTable,
    I: ExactSizeIterator<Item = usize>,
{
    let n = fft.poly_length().get();
    core::mem::swap(current, scratch);
    for (indices, data) in groups {
        aggregate_controls(
            indices,
            data,
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
pub(crate) fn rotate_groups_split<'a, T, Table, I>(
    groups: impl Iterator<Item = (I, &'a [T])>,
    workspace: &mut SplitAggregationWorkspace<T>,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    fft: &mut FftEngine<'_, Table>,
    split: &mut FourierNtruSplitWorkspace<T>,
) where
    T: TorusFftValue,
    Table: FftTable,
    I: ExactSizeIterator<Item = usize>,
{
    let n = fft.poly_length().get();
    core::mem::swap(current, scratch);
    for (indices, data) in groups {
        aggregate_controls(
            indices,
            data,
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

/// Both current buffers hold their independently rotated public LUT on entry.
/// Each source-control group is consumed for both inputs before advancing;
/// transforms and external products then reuse the original shared scratch.
pub(crate) fn rotate_buckets_pair<T: TorusFftValue, Table: FftTable>(
    key: &SparseNtruBootstrappingKey<T>,
    workspace: &mut AggregationWorkspace<T>,
    second: &mut SparseBlindRotationPairWorkspace<T>,
    buffers: [&mut Ntru<Vec<T>>; 2],
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
) {
    let [current, scratch] = buffers;
    let n = fft.poly_length().get();
    for bucket in 0..key.bucket_count() {
        let (indices, data) = key.bucket_data(bucket);
        aggregate_controls(
            indices.iter().copied(),
            data,
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
        // Bucket zero lifts both public LUTs with NLEV. Later NGSW controls
        // use the same external-product arithmetic, preserving every bucket.
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

/// Starts from the encrypted dummy and adds every selector in key order. The
/// iterator selects coordinates from each input's complete exponent slice;
/// sparse buckets supply public indices and direct blocks supply a range. For
/// u64, four controls share a coefficient traversal; u32 retains the pair path.
/// Remaining controls use pairs and a possible single tail. No zero exponent
/// or encrypted zero is skipped. The key/workspace establish complete, equally
/// sized controls, and native wrapping preserves the coefficient representation.
/// Instantiated only for one input or the fixed two-input window.
#[inline]
fn aggregate_controls<T: TorusFftValue, const INPUTS: usize>(
    mut indices: impl ExactSizeIterator<Item = usize>,
    data: &[T],
    mut inputs: [(&[usize], Nlev<&mut [T]>); INPUTS],
    poly_length: usize,
) {
    let modulus = NativeModulus::new();
    let control_len = inputs[0].1.as_ref().len();
    let (selections, dummy) = data.split_at(data.len() - control_len);
    debug_assert_eq!(selections.len(), indices.len() * control_len);
    for (_, aggregate) in &mut inputs {
        aggregate.as_mut().copy_from_slice(dummy);
    }
    let mut controls = NlevIter::new(selections, control_len);
    if T::BITS == 64 {
        for _ in 0..indices.len() / 4 {
            let indices: [usize; 4] =
                core::array::from_fn(|_| indices.next().expect("complete control indices"));
            let sources: [Nlev<&[T]>; 4] =
                core::array::from_fn(|_| controls.next().expect("complete grouped controls"));
            for (exponents, aggregate) in &mut inputs {
                super::aggregation::add_four_rotations_assign(
                    aggregate.as_mut(),
                    sources.each_ref().map(|control| control.as_ref()),
                    indices.map(|i| exponents[i]),
                    poly_length,
                );
            }
        }
    }
    // Finish the u64 tail (0..3 controls); u32 uses this pair/single loop for
    // the whole group. Preserve source order and per-lane wrapping arithmetic.
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
