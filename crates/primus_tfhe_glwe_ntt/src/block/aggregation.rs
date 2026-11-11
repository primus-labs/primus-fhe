//! Workspace and batched kernel for direct Block blind rotation.

use primus_integer::FheUint;
use primus_lattice::{
    ggsw::Ggsw, glwe::Glwe, lwe::Lwe, workspace::NttGlweExternalProductWorkspace,
};
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_tfhe::rotation::RotationModulusSwitch;
use primus_tfhe_glwe::GlweBlindRotationControls;

mod arithmetic;

pub(super) use arithmetic::aggregate_controls_assign;

/// Coefficient aggregation scratch. The caller supplies the block geometry.
pub(crate) struct ControlAggregationWorkspace<T: FheUint> {
    pub(crate) input_exponents: Vec<usize>,
    pub(crate) rotation_groups: Vec<arithmetic::FourRotations>,
    pub(crate) aggregate: Vec<T>,
    pub(crate) scratch: Glwe<Vec<T>>,
    pub(crate) external_product: NttGlweExternalProductWorkspace<T>,
}

impl<T: FheUint> ControlAggregationWorkspace<T> {
    pub(crate) fn with_external_product<R>(
        &mut self,
        size: primus_lattice::GadgetSize,
        operation: impl FnOnce(&mut NttGlweExternalProductWorkspace<T>) -> R,
    ) -> R {
        self.external_product.with_rebound(size, operation)
    }

    /// The typed wrapper supplies its largest group, not the full input dimension.
    /// Descriptors exist only for u64 layouts whose controls span multiple tiles.
    pub(crate) fn new(
        controls: &GlweBlindRotationControls<T, BarrettModulus<T>>,
        max_group_len: usize,
    ) -> Self {
        let size = controls.size();
        let tile_len = arithmetic::tile_len::<T>(size.glwe_size().poly_length().get());
        Self {
            input_exponents: vec![0; controls.input_dimension().get()],
            rotation_groups: vec![
                arithmetic::FourRotations::default();
                if T::BITS == 64 && size.ggsw_len() > tile_len {
                    max_group_len / 4
                } else {
                    0
                }
            ],
            aggregate: vec![T::ZERO; size.ggsw_len()],
            scratch: Glwe::zero(size.glwe_len()),
            external_product: NttGlweExternalProductWorkspace::new(size),
        }
    }
}

/// Each lane owns its exponents, aggregate and external-product scratch.
/// The key supplies one selector per block index and one trailing dummy for
/// AtMostOne. The caller has checked these layouts before entering the kernel.
///
/// Only source-group traversal is interleaved; each input's dependent group chain,
/// 16 KiB tile schedule and arithmetic/reduction boundaries remain unchanged.
/// Single-input evaluation retains its original kernel.
#[expect(
    clippy::too_many_arguments,
    reason = "keep control geometry, group traversal and per-lane resources explicit"
)]
pub(crate) fn blind_rotate_groups_batch_kernel<
    'a,
    T: FheUint,
    Table: NttTable<ValueT = T>,
    I: ExactSizeIterator<Item = usize> + Clone,
    const LANES: usize,
>(
    mut lanes: [&mut ControlAggregationWorkspace<T>; LANES],
    controls: &GlweBlindRotationControls<T, BarrettModulus<T>>,
    groups: impl Iterator<Item = (I, &'a [T])>,
    inputs: [Lwe<&[T]>; LANES],
    lookup_table: Polynomial<&[T]>,
    modulus_switch: &RotationModulusSwitch<T>,
    mut outputs: [Glwe<&mut [T]>; LANES],
    ntt: &Table,
) {
    let size = controls.size();
    let n = size.glwe_size().poly_length().get();
    let modulus = controls.ring_modulus();
    for ((lane, input), output) in lanes.iter_mut().zip(inputs).zip(&mut outputs) {
        modulus_switch.exponent_slice_to(input.a(), &mut lane.input_exponents);
        let exponent = modulus_switch.exponent(input.b()).wrapping_neg() & (2 * n - 1);
        let (mask, body) = output.a_b_mut_slices(n);
        mask.fill(T::ZERO);
        lookup_table.mul_monomial_to(exponent, &mut Polynomial(body), modulus);
    }
    let mut output_is_current = true;
    for (indices, ciphertexts) in groups {
        let count = indices.len();
        let (selections, dummy) = ciphertexts.split_at(count * size.ggsw_len());
        for lane in lanes.iter_mut() {
            // The public group layout determines initialization, never secret
            // occupancy. No-dummy groups must erase the previous NTT values too.
            if dummy.is_empty() {
                lane.aggregate.fill(T::ZERO);
            } else {
                lane.aggregate.copy_from_slice(dummy);
            }
        }
        let use_groups =
            T::BITS == 64 && count >= 4 && count <= arithmetic::max_group_len(modulus.value());
        for lane in lanes.iter_mut() {
            if use_groups && !lane.rotation_groups.is_empty() {
                let mut indices = indices.clone();
                for plan in lane.rotation_groups.iter_mut().take(count / 4) {
                    *plan = arithmetic::FourRotations::new(
                        std::array::from_fn(|_| {
                            lane.input_exponents[indices.next().expect("control index")]
                        }),
                        n,
                    );
                }
            }
        }
        arithmetic::aggregate_controls_many_assign(
            indices,
            selections,
            &mut lanes.each_mut().map(|lane| arithmetic::AggregationLane {
                prepared: &lane.rotation_groups[..if use_groups {
                    lane.rotation_groups.len().min(count / 4)
                } else {
                    0
                }],
                exponents: &lane.input_exponents,
                coefficients: &mut lane.aggregate,
            }),
            size,
            modulus,
        );
        for (lane, output) in lanes.iter_mut().zip(&mut outputs) {
            let aggregate_ntt = Ggsw::new(lane.aggregate.as_mut_slice()).into_ntt_form(ntt);
            if output_is_current {
                aggregate_ntt.external_product_to(
                    output,
                    &mut lane.scratch,
                    controls.basis(),
                    modulus,
                    ntt,
                    &mut lane.external_product,
                );
            } else {
                aggregate_ntt.external_product_to(
                    &lane.scratch,
                    output,
                    controls.basis(),
                    modulus,
                    ntt,
                    &mut lane.external_product,
                );
            }
        }
        output_is_current = !output_is_current;
    }
    if !output_is_current {
        for (lane, output) in lanes.iter().zip(&mut outputs) {
            output.as_mut().copy_from_slice(lane.scratch.as_ref());
        }
    }
}
