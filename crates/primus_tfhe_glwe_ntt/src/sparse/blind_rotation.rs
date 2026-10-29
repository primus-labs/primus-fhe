//! Reference sparse blind rotation: coefficient aggregation, NTT, external product.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::{
    ggsw::Ggsw, glwe::Glwe, lwe::Lwe, workspace::NttGlweExternalProductWorkspace,
};
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_tfhe::rotation::RotationModulusSwitch;
use primus_tfhe_glwe::GlweBlindRotationControls;

use super::SparseGlweBootstrappingKey;

/// Reusable workspace for [`SparseGlweBootstrappingKey`] blind rotation.
///
/// Stores input exponents, one aggregate transformed in place, a GLWE buffer and
/// external-product scratch. Multi-tile u64 layouts also cache rotation descriptors
/// within each bucket. It contains no secret support or matching data.
pub struct SparseGlweBlindRotationWorkspace<T: FheUint> {
    inner: ControlAggregationWorkspace<T>,
}

/// Shared coefficient aggregation state. Typed sparse/block wrappers establish
/// group geometry; this state retains no grouping or input-support metadata.
pub(crate) struct ControlAggregationWorkspace<T: FheUint> {
    pub(crate) input_exponents: Vec<usize>,
    pub(crate) rotation_groups: Vec<super::aggregation::FourRotations>,
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
        let tile_len = super::aggregation::tile_len::<T>(size.glwe_size().poly_length().get());
        Self {
            input_exponents: vec![0; controls.input_dimension().get()],
            rotation_groups: vec![
                super::aggregation::FourRotations::default();
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

impl<T: FheUint> SparseGlweBlindRotationWorkspace<T> {
    pub(crate) fn with_external_product<R>(
        &mut self,
        size: primus_lattice::GadgetSize,
        operation: impl FnOnce(&mut NttGlweExternalProductWorkspace<T>) -> R,
    ) -> R {
        self.inner.with_external_product(size, operation)
    }

    /// Allocates scratch for the controls' input dimension and gadget layout.
    /// It can be reused with other sparse keys of the same dimensions and layout.
    #[must_use]
    pub fn new(controls: &GlweBlindRotationControls<T, BarrettModulus<T>>) -> Self {
        Self {
            // A sparse bucket contains each input index at most once. Preserve
            // dimension-based capacity for reuse with different matching maps.
            inner: ControlAggregationWorkspace::new(controls, controls.input_dimension().get()),
        }
    }
}

impl<T: FheUint> SparseGlweBlindRotationWorkspace<T> {
    /// Blind-rotates an encoded LUT into a coefficient-domain GLWE ciphertext.
    ///
    /// Uses ordinary PBS quantization (rotation step one). Quantizes each input
    /// coefficient once to `2N`, initializes a trivial
    /// accumulator with `X^(-R(b)) * LUT`, then applies one external product per
    /// bucket. Its control encrypts the selected `X^R(a[i])`, or `1` if no entry
    /// is selected. All buckets and encrypted zero entries are processed.
    /// The caller owns the output; this workspace is reused without online allocation.
    ///
    /// # Correctness
    ///
    /// The input must use this key's small-LWE secret and canonical residues at
    /// [`GlweBlindRotationControls::input_modulus_value`] (q). LUT coefficients use
    /// [`GlweBlindRotationControls::ring_modulus`] (Q). The LUT has `N` encoded
    /// coefficients; the caller is responsible for its encoding and noise margin.
    /// This raw operation performs neither key switching nor sample extraction.
    ///
    /// # Panics
    ///
    /// Panics if input, LUT, output or workspace layouts, or the NTT length/modulus
    /// do not match this key, or the quantizer has a different q, rotation domain
    /// or step. These checks precede output writes.
    pub fn blind_rotate_lookup_table_to<Table, A, B, C>(
        &mut self,
        key: &SparseGlweBootstrappingKey<T, BarrettModulus<T>>,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        modulus_switch: &RotationModulusSwitch<T>,
        output: &mut Glwe<C>,
        ntt: &Table,
    ) where
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        assert_eq!(
            modulus_switch.rotation_step(),
            1,
            "ordinary blind rotation requires step one"
        );
        let size = key.controls().size();
        let poly_length = size.glwe_size().poly_length().get();
        let modulus = key.controls().ring_modulus();
        assert!(
            modulus_switch.is_compatible(key.controls().input_modulus_value(), 2 * poly_length),
            "sparse blind-rotation quantizer domain mismatch"
        );
        assert_eq!(
            (
                input.dimension(),
                lookup_table.as_ref().len(),
                output.as_ref().len()
            ),
            (key.input_dimension().get(), poly_length, size.glwe_len()),
            "sparse blind-rotation input, LUT or output layout mismatch"
        );
        assert_eq!(
            (
                self.inner.input_exponents.len(),
                self.inner.external_product.size()
            ),
            (key.input_dimension().get(), size),
            "sparse blind-rotation workspace layout mismatch"
        );
        assert_eq!(
            ntt.poly_length().get(),
            poly_length,
            "sparse blind-rotation NTT length mismatch"
        );
        assert_eq!(
            ntt.modulus(),
            modulus.value(),
            "sparse blind-rotation NTT modulus mismatch"
        );

        self.blind_rotate_interleaved_lookup_table_kernel_to(
            key,
            input.as_view(),
            lookup_table.as_view(),
            modulus_switch,
            output.as_mut_view(),
            ntt,
        );
    }

    /// The public raw wrapper or evaluator has bound the quantizer and checked layouts, table and LUT.
    /// The rotation step is the compiled LUT's padded output count; every mask
    /// and body coefficient must use this same step to preserve output slots.
    pub(crate) fn blind_rotate_interleaved_lookup_table_kernel_to<Table>(
        &mut self,
        key: &SparseGlweBootstrappingKey<T, BarrettModulus<T>>,
        input: Lwe<&[T]>,
        lookup_table: Polynomial<&[T]>,
        modulus_switch: &RotationModulusSwitch<T>,
        mut output: Glwe<&mut [T]>,
        ntt: &Table,
    ) where
        Table: NttTable<ValueT = T>,
    {
        let size = key.controls().size();
        let poly_length = size.glwe_size().poly_length().get();
        let modulus = key.controls().ring_modulus();
        let ControlAggregationWorkspace {
            input_exponents,
            rotation_groups,
            aggregate,
            scratch,
            external_product,
        } = &mut self.inner;
        modulus_switch.exponent_slice_to(input.a(), input_exponents);
        let initial_exponent =
            modulus_switch.exponent(input.b()).wrapping_neg() & (2 * poly_length - 1);
        let (mask, body) = output.a_b_mut_slices(poly_length);
        mask.fill(T::ZERO);
        lookup_table.mul_monomial_to(initial_exponent, &mut Polynomial(body), modulus);

        let mut output_is_current = true;
        for bucket_index in 0..key.bucket_count() {
            let (indices, ciphertexts) = key.bucket_data(bucket_index);
            let (selections, dummy) = ciphertexts.split_at(indices.len() * size.ggsw_len());
            // Every bucket has a dummy, even if publicly empty. It overwrites the
            // previous bucket's NTT values before adding the rotated selections.
            aggregate.copy_from_slice(dummy);
            super::aggregation::aggregate_controls_assign(
                indices.iter().map(|&index| input_exponents[index]),
                selections,
                rotation_groups,
                aggregate,
                size,
                modulus,
            );
            let aggregate_ntt = Ggsw::new(aggregate.as_mut_slice()).into_ntt_form(ntt);
            if output_is_current {
                aggregate_ntt.external_product_to(
                    &output,
                    scratch,
                    key.controls().basis(),
                    modulus,
                    ntt,
                    external_product,
                );
            } else {
                aggregate_ntt.external_product_to(
                    scratch,
                    &mut output,
                    key.controls().basis(),
                    modulus,
                    ntt,
                    external_product,
                );
            }
            output_is_current = !output_is_current;
        }
        if !output_is_current {
            output.as_mut().copy_from_slice(scratch.as_ref());
        }
    }
}

/// Batched sparse BR, sharing read-only key tiles across up to four chains.
///
/// Independent inputs share one key and LUT. Source tiles are consumed by four
/// lanes before advancing through the key, followed by a pair and a single input
/// for a short tail. u32 and u64 retain their own aggregation/reduction bounds.
/// Per-input bucket order, NTT and external products are unchanged, so each result
/// equals a single-input call. This is neither ManyLUT nor parallel execution.
///
/// Construction allocates four single-input workspaces. Outputs remain caller-owned
/// and evaluation allocates nothing. Use [`SparseGlweBlindRotationWorkspace`] for
/// workloads that only need one input; one-element tails use its original kernel.
pub struct SparseGlweBlindRotationBatchWorkspace<T: FheUint> {
    lanes: Box<[SparseGlweBlindRotationWorkspace<T>]>,
}

impl<T: FheUint> SparseGlweBlindRotationBatchWorkspace<T> {
    /// Allocates four independent lanes for this control layout.
    #[must_use]
    pub fn new(controls: &GlweBlindRotationControls<T, BarrettModulus<T>>) -> Self {
        Self {
            lanes: (0..4)
                .map(|_| SparseGlweBlindRotationWorkspace::new(controls))
                .collect(),
        }
    }

    /// Blind-rotates each input with the same encoded LUT, overwriting paired outputs.
    /// Accepts any batch length, including zero; retains input/output order.
    /// Inherits [`SparseGlweBlindRotationWorkspace::blind_rotate_lookup_table_to`]'s
    /// mathematical and representation requirements. Performs no sum, KS or extraction.
    ///
    /// # Panics
    /// Panics before writing any output if counts, ciphertext/workspace layouts,
    /// LUT, quantizer or NTT parameters do not match the key.
    pub fn blind_rotate_lookup_table_many_to<Table, A, B, C>(
        &mut self,
        key: &SparseGlweBootstrappingKey<T, BarrettModulus<T>>,
        inputs: &[Lwe<A>],
        lookup_table: &Polynomial<B>,
        modulus_switch: &RotationModulusSwitch<T>,
        outputs: &mut [Glwe<C>],
        ntt: &Table,
    ) where
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        check_lookup_table(key, lookup_table.as_view(), modulus_switch, ntt);
        // All lanes were constructed together and cannot be independently rebound.
        assert_eq!(
            (
                self.lanes[0].inner.input_exponents.len(),
                self.lanes[0].inner.external_product.size()
            ),
            (key.input_dimension().get(), key.controls().size()),
            "sparse blind-rotation workspace layout mismatch"
        );
        check_ciphertexts(key, inputs, outputs);
        let lanes = self
            .lanes
            .first_chunk_mut::<4>()
            .expect("sparse batch workspace has four lanes");
        let (input_groups, input_tail) = inputs.as_chunks::<4>();
        let (output_groups, output_tail) = outputs.as_chunks_mut::<4>();
        for (inputs, outputs) in input_groups.iter().zip(output_groups) {
            blind_rotate_batch_kernel(
                lanes.each_mut(),
                key,
                inputs.each_ref().map(Lwe::as_view),
                lookup_table.as_view(),
                modulus_switch,
                outputs.each_mut().map(Glwe::as_mut_view),
                ntt,
            );
        }
        let (input_pairs, input_tail) = input_tail.as_chunks::<2>();
        let (output_pairs, output_tail) = output_tail.as_chunks_mut::<2>();
        let (lane_pairs, _) = lanes.as_chunks_mut::<2>();
        for (inputs, outputs) in input_pairs.iter().zip(output_pairs) {
            blind_rotate_batch_kernel(
                lane_pairs[0].each_mut(),
                key,
                inputs.each_ref().map(Lwe::as_view),
                lookup_table.as_view(),
                modulus_switch,
                outputs.each_mut().map(Glwe::as_mut_view),
                ntt,
            );
        }
        let (inputs, outputs) = (input_tail, output_tail);
        for (input, output) in inputs.iter().zip(outputs) {
            self.lanes[0].blind_rotate_interleaved_lookup_table_kernel_to(
                key,
                input.as_view(),
                lookup_table.as_view(),
                modulus_switch,
                output.as_mut_view(),
                ntt,
            );
        }
    }
}

/// Validate the batch's shared LUT, quantizer and transform before any output write.
fn check_lookup_table<T: FheUint, Table: NttTable<ValueT = T>>(
    key: &SparseGlweBootstrappingKey<T, BarrettModulus<T>>,
    lookup_table: Polynomial<&[T]>,
    modulus_switch: &RotationModulusSwitch<T>,
    ntt: &Table,
) {
    let n = key.controls().size().glwe_size().poly_length().get();
    assert_eq!(
        modulus_switch.rotation_step(),
        1,
        "ordinary blind rotation requires step one"
    );
    assert!(
        modulus_switch.is_compatible(key.controls().input_modulus_value(), 2 * n),
        "sparse blind-rotation quantizer domain mismatch"
    );
    assert_eq!(
        lookup_table.as_ref().len(),
        n,
        "sparse blind-rotation LUT length mismatch"
    );
    assert_eq!(
        ntt.poly_length().get(),
        n,
        "sparse blind-rotation NTT length mismatch"
    );
    assert_eq!(
        ntt.modulus(),
        key.controls().ring_modulus().value(),
        "sparse blind-rotation NTT modulus mismatch"
    );
}

fn check_ciphertexts<T: FheUint, A: Data<Elem = T>, C: Data<Elem = T>>(
    key: &SparseGlweBootstrappingKey<T, BarrettModulus<T>>,
    inputs: &[Lwe<A>],
    outputs: &[Glwe<C>],
) {
    assert_eq!(
        inputs.len(),
        outputs.len(),
        "sparse blind-rotation input/output count mismatch"
    );
    assert!(
        inputs
            .iter()
            .all(|input| input.dimension() == key.input_dimension().get()),
        "sparse blind-rotation input layout mismatch"
    );
    assert!(
        outputs
            .iter()
            .all(|output| output.as_ref().len() == key.controls().size().glwe_len()),
        "sparse blind-rotation output layout mismatch"
    );
}

/// Each lane owns its exponents, aggregate and EP scratch. Only the source-group
/// traversal is interleaved; the dependent bucket chain stays ordered per input.
/// This path is used only for batches; the original single-input loop stays separate.
fn blind_rotate_batch_kernel<T: FheUint, Table: NttTable<ValueT = T>, const LANES: usize>(
    mut lanes: [&mut SparseGlweBlindRotationWorkspace<T>; LANES],
    key: &SparseGlweBootstrappingKey<T, BarrettModulus<T>>,
    inputs: [Lwe<&[T]>; LANES],
    lookup_table: Polynomial<&[T]>,
    modulus_switch: &RotationModulusSwitch<T>,
    mut outputs: [Glwe<&mut [T]>; LANES],
    ntt: &Table,
) {
    let size = key.controls().size();
    let n = size.glwe_size().poly_length().get();
    let modulus = key.controls().ring_modulus();
    for ((lane, input), output) in lanes.iter_mut().zip(inputs).zip(&mut outputs) {
        modulus_switch.exponent_slice_to(input.a(), &mut lane.inner.input_exponents);
        let exponent = modulus_switch.exponent(input.b()).wrapping_neg() & (2 * n - 1);
        let (mask, body) = output.a_b_mut_slices(n);
        mask.fill(T::ZERO);
        lookup_table.mul_monomial_to(exponent, &mut Polynomial(body), modulus);
    }
    let mut output_is_current = true;
    for bucket in 0..key.bucket_count() {
        let (indices, ciphertexts) = key.bucket_data(bucket);
        let (selections, dummy) = ciphertexts.split_at(indices.len() * size.ggsw_len());
        for lane in lanes.iter_mut() {
            // Overwrite the previous bucket's NTT values, including empty buckets.
            lane.inner.aggregate.copy_from_slice(dummy);
        }
        let use_groups = T::BITS == 64
            && indices.len() >= 4
            && indices.len() <= super::aggregation::max_group_len(modulus.value());
        for lane in lanes.iter_mut() {
            if use_groups && !lane.inner.rotation_groups.is_empty() {
                for (plan, indices) in lane
                    .inner
                    .rotation_groups
                    .iter_mut()
                    .zip(indices.as_chunks::<4>().0)
                {
                    *plan = super::aggregation::FourRotations::new(
                        indices.map(|i| lane.inner.input_exponents[i]),
                        n,
                    );
                }
            }
        }
        super::aggregation::aggregate_bucket_many(
            indices,
            selections,
            &mut lanes
                .each_mut()
                .map(|lane| super::aggregation::AggregationLane {
                    prepared: &lane.inner.rotation_groups[..if use_groups {
                        lane.inner.rotation_groups.len().min(indices.len() / 4)
                    } else {
                        0
                    }],
                    exponents: &lane.inner.input_exponents,
                    coefficients: &mut lane.inner.aggregate,
                }),
            size,
            modulus,
        );
        for (lane, output) in lanes.iter_mut().zip(&mut outputs) {
            let aggregate_ntt = Ggsw::new(lane.inner.aggregate.as_mut_slice()).into_ntt_form(ntt);
            if output_is_current {
                aggregate_ntt.external_product_to(
                    output,
                    &mut lane.inner.scratch,
                    key.controls().basis(),
                    modulus,
                    ntt,
                    &mut lane.inner.external_product,
                );
            } else {
                aggregate_ntt.external_product_to(
                    &lane.inner.scratch,
                    output,
                    key.controls().basis(),
                    modulus,
                    ntt,
                    &mut lane.inner.external_product,
                );
            }
        }
        output_is_current = !output_is_current;
    }
    if !output_is_current {
        for (lane, output) in lanes.iter().zip(&mut outputs) {
            output.as_mut().copy_from_slice(lane.inner.scratch.as_ref());
        }
    }
}
