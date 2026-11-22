use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_lattice::{lwe::Lwe, ntru::Ntru};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;

use crate::{
    block::{AggregationWorkspace, SplitAggregationWorkspace},
    context::EvaluationContext,
    key::{BlindRotationKey, BootstrappingControls, ClassicControls},
};

/// Borrowed BR controls with owned buffers and matching product scratch.
/// The outer bootstrap resources provide the context/FFT binding; this set
/// keeps the selected controls and their matching buffers together.
pub(crate) struct BlindRotationResources<'a, T: TorusFftValue> {
    /// Coefficient-domain result under the accumulator secret after BR.
    pub(crate) current: Ntru<Vec<T>>,
    /// BR temporary storage in the accumulator domain.
    pub(crate) scratch: Ntru<Vec<T>>,
    pub(crate) rotation: RotationState<'a, T>,
    /// One optional extension shared serially by BR, trace and SS.
    pub(crate) split: Option<primus_ntru::FourierNtruSplitWorkspace<T>>,
}

impl<'a, T: TorusFftValue> BlindRotationResources<'a, T> {
    /// Allocates all blind-rotation storage once.
    pub(crate) fn new<Table: FftTable>(
        parameters: EvaluationContext<'_, T, Table>,
        blind_rotation_key: &'a BlindRotationKey<T>,
        needs_split: bool,
    ) -> Self {
        let poly_length = parameters.poly_length();
        Self {
            split: needs_split.then(|| primus_ntru::FourierNtruSplitWorkspace::new(poly_length)),
            current: Ntru::zero(poly_length.get()),
            scratch: Ntru::zero(poly_length.get()),
            rotation: match blind_rotation_key.bootstrapping_controls() {
                BootstrappingControls::Split(controls) => RotationState::Split {
                    controls,
                    combined: controls.initializer.zero_like(),
                    product: primus_ntru::FourierNtruExternalProductWorkspace::new(poly_length),
                },
                BootstrappingControls::Block { key, precision } => match precision {
                    crate::FourierPrecision::Ordinary => RotationState::Block {
                        key,
                        scratch: AggregationWorkspace::new(parameters.blind_rotation(), key),
                    },
                    crate::FourierPrecision::Split { low_bits } => RotationState::BlockSplit {
                        key,
                        scratch: AggregationWorkspace::new_split(
                            parameters.blind_rotation(),
                            key,
                            low_bits,
                        ),
                    },
                },
                BootstrappingControls::Classic(controls) => {
                    let scratch = primus_ntru::FourierNtruCmuxWorkspace::new(
                        poly_length,
                        parameters.blind_rotation().level_count(),
                    );
                    if controls.is_binary() {
                        RotationState::Binary { controls, scratch }
                    } else {
                        RotationState::Ternary { controls, scratch }
                    }
                }
            },
        }
    }
}

/// Borrowed BR material and owned scratch selected for one control layout.
/// The variant keeps Block keys or classic control views paired with their buffers.
pub(crate) enum RotationState<'a, T: TorusFftValue> {
    Split {
        controls: &'a crate::key::SplitControls<T>,
        combined: primus_ntru::FourierNtruSplitGadget<T>,
        product: primus_ntru::FourierNtruExternalProductWorkspace<T>,
    },
    Block {
        key: &'a crate::block::BlockNtruBootstrappingKey<T>,
        scratch: AggregationWorkspace<T>,
    },
    BlockSplit {
        key: &'a crate::block::BlockNtruBootstrappingKey<T>,
        scratch: SplitAggregationWorkspace<T>,
    },
    Binary {
        controls: ClassicControls<'a>,
        scratch: primus_ntru::FourierNtruCmuxWorkspace<T>,
    },
    Ternary {
        controls: ClassicControls<'a>,
        scratch: primus_ntru::FourierNtruCmuxWorkspace<T>,
    },
}

impl<'a, T: TorusFftValue> RotationState<'a, T> {
    pub(crate) fn external_product(
        &mut self,
    ) -> &mut primus_ntru::FourierNtruExternalProductWorkspace<T> {
        match self {
            Self::Split { product, .. } => product,
            Self::Block { scratch, .. } => &mut scratch.external_product,
            Self::BlockSplit { scratch, .. } => &mut scratch.external_product,
            Self::Binary { scratch, .. } => scratch.external_product_workspace(),
            Self::Ternary { scratch, .. } => scratch.external_product_workspace(),
        }
    }
}

/// Initializes and blind-rotates an encrypted native NTRU accumulator.
///
/// Writes the selected LUT phase to coefficient-domain `resources.current`
/// under `f_acc`, reusing `resources.scratch` as temporary storage. The caller
/// established input/LUT compatibility; `rotation_step` is the LUT's padded
/// output count (one for ordinary PBS).
pub(crate) fn blind_rotate_lookup_table_to<T, Table>(
    blind_rotation_key: &BlindRotationKey<T>,
    input: Lwe<&[T]>,
    lookup_table: Polynomial<&[T]>,
    rotation_step: usize,
    resources: &mut BlindRotationResources<'_, T>,
    parameters: EvaluationContext<'_, T, Table>,
    fft: &mut FftEngine<'_, Table>,
) where
    T: TorusFftValue,
    Table: FftTable,
{
    let poly_length = parameters.poly_length().get();
    let two_n = poly_length * 2;
    // Change the target domain before rounding. Rounding at step one and then
    // aligning that result would move half-grid boundaries for interleaved outputs.
    let modulus_switch = parameters
        .rotation_modulus_switch()
        .with_step(rotation_step);
    let exponent_of = |value| modulus_switch.exponent(value);
    let initial_exponent = exponent_of(input.b()).wrapping_neg() & (two_n - 1);
    lookup_table.mul_monomial_to(
        initial_exponent,
        &mut Polynomial(resources.scratch.as_mut()),
        NativeModulus::new(),
    );
    let basis = blind_rotation_key.blind_rotation_basis();
    // One public layout dispatch per BR; the coordinate loop stays specialized.
    match &mut resources.rotation {
        RotationState::Split {
            controls,
            combined,
            product,
        } => {
            let extension = resources
                .split
                .as_mut()
                .expect("split BR extension established at construction");
            combined.combine_lift(
                &controls.initializer,
                &controls.controls[0],
                exponent_of(input.a()[0]),
                fft,
                product,
            );
            combined.external_product_to(
                resources.scratch.as_ref(),
                resources.current.as_mut(),
                fft,
                product,
                extension,
            );
            for (&coefficient, control) in input.a()[1..].iter().zip(&controls.controls[1..]) {
                let exponent = exponent_of(coefficient);
                if exponent == 0 {
                    continue;
                }
                // Form (X^a-1)c in scratch; the current accumulator survives until
                // its split product is complete. Reuse the ordinary digit/product
                // buffers instead of allocating a third coefficient polynomial.
                resources.current.mul_monomial_to(
                    exponent,
                    &mut resources.scratch,
                    NativeModulus::new(),
                );
                for (v, &c) in resources
                    .scratch
                    .as_mut()
                    .iter_mut()
                    .zip(resources.current.as_ref())
                {
                    *v = v.wrapping_sub(c);
                }
                control.external_product_add_assign(
                    resources.scratch.as_ref(),
                    resources.current.as_mut(),
                    fft,
                    product,
                    extension,
                );
            }
        }
        RotationState::Block { key, scratch } => {
            modulus_switch.exponent_slice_to(input.a(), &mut scratch.exponents);
            crate::block::rotate_blocks(
                key,
                scratch,
                &mut resources.current,
                &mut resources.scratch,
                basis,
                fft,
            );
        }
        RotationState::BlockSplit { key, scratch } => {
            modulus_switch.exponent_slice_to(input.a(), &mut scratch.exponents);
            let extension = resources
                .split
                .as_mut()
                .expect("split BR extension established at construction");
            crate::block::rotate_blocks_split(
                key,
                scratch,
                &mut resources.current,
                &mut resources.scratch,
                fft,
                extension,
            );
        }
        RotationState::Binary {
            controls,
            scratch: product,
        } => {
            let (positive, negative) = controls.first_controls();
            controls.initializer().lift_monomial_to(
                &positive,
                negative.as_ref(),
                &Polynomial(resources.scratch.as_ref()),
                exponent_of(input.a()[0]),
                &mut resources.current,
                basis,
                fft,
                product,
            );
            rotate_controls(
                &input.a()[1..],
                controls.remaining_controls(),
                &mut resources.current,
                &mut resources.scratch,
                exponent_of,
                |control, exponent, input, output| {
                    control.cmux_monomial_to(
                        input,
                        exponent,
                        output,
                        basis,
                        fft,
                        product.external_product_workspace(),
                    )
                },
            );
        }
        RotationState::Ternary {
            controls,
            scratch: product,
        } => {
            let (positive, negative) = controls.first_controls();
            controls.initializer().lift_monomial_to(
                &positive,
                negative.as_ref(),
                &Polynomial(resources.scratch.as_ref()),
                exponent_of(input.a()[0]),
                &mut resources.current,
                basis,
                fft,
                product,
            );
            rotate_controls(
                &input.a()[1..],
                controls.ternary_controls(),
                &mut resources.current,
                &mut resources.scratch,
                exponent_of,
                |(positive, negative), exponent, input, output| {
                    positive.cmux_ternary_monomial_to(
                        &negative, input, exponent, output, basis, fft, product,
                    )
                },
            );
        }
    }
}

// Own both buffers so the final result can stay in `current` by swapping them.
fn rotate_controls<T: TorusFftValue, I: Iterator>(
    input: &[T],
    controls: I,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    exponent_of: impl Fn(T) -> usize,
    mut step: impl FnMut(I::Item, usize, &Ntru<Vec<T>>, &mut Ntru<Vec<T>>),
) {
    let mut output_is_current = true;
    for (&coefficient, control) in input.iter().zip(controls) {
        let exponent = exponent_of(coefficient);
        if exponent == 0 {
            continue;
        }
        if output_is_current {
            step(control, exponent, current, scratch);
        } else {
            step(control, exponent, scratch, current);
        }
        output_is_current = !output_is_current;
    }
    if !output_is_current {
        core::mem::swap(current, scratch);
    }
}
