//! Native coefficient aggregation and Fourier products for grouped blind rotation.

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
use primus_tfhe_ntru::NtruBlindRotationControls;

use crate::bootstrap::BlindRotationPairWorkspace;

mod aggregation;

/// Reusable aggregate and product scratch, independent of group geometry.
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

/// Split payload for grouped rotation using a two-limb Fourier product.
pub(crate) type SplitAggregationWorkspace<T> = AggregationWorkspace<T, FourierNtruSplitGadget<T>>;

/// `scratch` holds the rotated public LUT on entry. The first group's NLEV
/// aggregate lifts it, then later `NGSW[H] = NLEV[f*H]` aggregates act on
/// ciphertexts with the same product arithmetic. Every encrypted selector
/// and dummy contributes, including zeros. The result stays in `current`.
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

/// Aggregates a control group for both inputs before advancing, preserving
/// source order and each input's compulsory first-group public-LUT lift. Both
/// current buffers contain their rotated public LUT on entry. Ordinary transforms
/// and products run serially through one shared workspace; final results remain
/// in the two current buffers, regardless of the number of groups.
pub(crate) fn rotate_groups_pair<'a, T, Table, I>(
    groups: impl Iterator<Item = (I, &'a [T])>,
    workspace: &mut AggregationWorkspace<T>,
    second: &mut BlindRotationPairWorkspace<T>,
    buffers: [&mut Ntru<Vec<T>>; 2],
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
) where
    T: TorusFftValue,
    Table: FftTable,
    I: ExactSizeIterator<Item = usize>,
{
    let [current, scratch] = buffers;
    let n = fft.poly_length().get();
    for (indices, data) in groups {
        aggregate_controls(
            indices,
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
        // First-group NLEV and later NGSW use the same product arithmetic.
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
pub(crate) fn rotate_groups_split_pair<'a, T, Table, I>(
    groups: impl Iterator<Item = (I, &'a [T])>,
    workspace: &mut SplitAggregationWorkspace<T>,
    second: &mut BlindRotationPairWorkspace<T>,
    buffers: [&mut Ntru<Vec<T>>; 2],
    fft: &mut FftEngine<'_, Table>,
    split: &mut FourierNtruSplitWorkspace<T>,
) where
    T: TorusFftValue,
    Table: FftTable,
    I: ExactSizeIterator<Item = usize>,
{
    let [current, scratch] = buffers;
    let n = fft.poly_length().get();
    for (indices, data) in groups {
        aggregate_controls(
            indices,
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
    mut indices: impl ExactSizeIterator<Item = usize>,
    data: &[T],
    mut inputs: [(&[usize], Nlev<&mut [T]>); INPUTS],
    poly_length: usize,
) {
    let modulus = NativeModulus::new();
    let control_len = inputs[0].1.as_ref().len();
    // The owner supplies w bit controls and either one complete dummy or none.
    // An empty slice denotes absence; it is never treated as a ciphertext.
    let (selections, dummy) = data.split_at(indices.len() * control_len);
    debug_assert!(dummy.is_empty() || dummy.len() == control_len);
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
                core::array::from_fn(|_| controls.next().expect("complete grouped controls"));
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
