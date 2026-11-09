//! Direct contiguous-block aggregation and NTT blind rotation.

use primus_data::{Data, DataMut};
use primus_glwe::BlockOccupancy;
use primus_integer::FheUint;
use primus_lattice::{
    ggsw::Ggsw, glwe::Glwe, lwe::Lwe, workspace::NttGlweExternalProductWorkspace,
};
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_tfhe::rotation::RotationModulusSwitch;

use crate::sparse::{
    ControlAggregationWorkspace, aggregation::aggregate_controls_assign,
    blind_rotate_groups_batch_kernel,
};

use super::BlockGlweBootstrappingKey;

/// Reusable single-input workspace for direct block-binary blind rotation.
///
/// Stores n public input exponents, one aggregate, GLWE output scratch and the
/// existing external-product workspace. Multi-tile u64 layouts cache at most
/// floor(w/4) rotation descriptors for the current block of width w. No bucket
/// map, secret support, repeated controls or online allocation is needed.
pub struct BlockGlweBlindRotationWorkspace<T: FheUint> {
    inner: ControlAggregationWorkspace<T>,
}

impl<T: FheUint> BlockGlweBlindRotationWorkspace<T> {
    /// Allocates scratch for this key's input dimension, block width and layout.
    #[must_use]
    pub fn new(key: &BlockGlweBootstrappingKey<T, BarrettModulus<T>>) -> Self {
        Self {
            inner: ControlAggregationWorkspace::new(key.controls(), key.block_size()),
        }
    }

    pub(crate) fn with_external_product<R>(
        &mut self,
        size: primus_lattice::GadgetSize,
        operation: impl FnOnce(&mut NttGlweExternalProductWorkspace<T>) -> R,
    ) -> R {
        self.inner.with_external_product(size, operation)
    }

    /// Blind-rotates an encoded LUT, overwriting a coefficient-domain GLWE output.
    ///
    /// Initializes X^(-R(b))*LUT, then processes every public block using
    /// sum(X^R(a_i)*GGSW(s_i)), plus GGSW(1-sum(s_i)) only for AtMostOne.
    /// All bit controls, including encrypted zeros, participate in either mode.
    /// No key switching or sample extraction is performed; evaluation reuses scratch.
    ///
    /// # Correctness
    ///
    /// Input residues are canonical at the key's input modulus q and use its
    /// block-binary control secret. LUT coefficients use the ring modulus Q and
    /// contain N encoded coefficients with a suitable encoding and noise margin.
    /// Quantization uses ordinary PBS step one.
    ///
    /// # Panics
    ///
    /// Panics before output writes if the input, LUT, output, workspace, quantizer
    /// or NTT layout does not match the key's dimensions and moduli.
    pub fn blind_rotate_lookup_table_to<Table, A, B, C>(
        &mut self,
        key: &BlockGlweBootstrappingKey<T, BarrettModulus<T>>,
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
        let controls = key.controls();
        let size = controls.size();
        let n = size.glwe_size().poly_length().get();
        check_lookup_table(key, lookup_table.as_view(), modulus_switch, ntt);
        assert_eq!(
            (
                input.dimension(),
                lookup_table.as_ref().len(),
                output.as_ref().len()
            ),
            (controls.input_dimension().get(), n, size.glwe_len()),
            "block blind-rotation input, LUT or output layout mismatch"
        );
        self.check_layout(key);
        self.blind_rotate_interleaved_lookup_table_kernel_to(
            key,
            input.as_view(),
            lookup_table.as_view(),
            modulus_switch,
            output.as_mut_view(),
            ntt,
        );
    }

    /// Buffers are private and created together; checking their bound geometry
    /// once also covers the aggregate, GLWE scratch and rotation descriptors.
    fn check_layout(&self, key: &BlockGlweBootstrappingKey<T, BarrettModulus<T>>) {
        assert_eq!(
            (
                self.inner.input_exponents.len(),
                self.inner.external_product.size()
            ),
            (
                key.controls().input_dimension().get(),
                key.controls().size()
            ),
            "block blind-rotation workspace layout mismatch"
        );
    }

    /// The public boundary or evaluator has checked layouts and bound one
    /// quantizer to all coefficients. A compiled ManyLUT can use a larger step
    /// to preserve output slots; the block aggregation itself is unchanged.
    pub(crate) fn blind_rotate_interleaved_lookup_table_kernel_to<Table>(
        &mut self,
        key: &BlockGlweBootstrappingKey<T, BarrettModulus<T>>,
        input: Lwe<&[T]>,
        lookup_table: Polynomial<&[T]>,
        modulus_switch: &RotationModulusSwitch<T>,
        mut output: Glwe<&mut [T]>,
        ntt: &Table,
    ) where
        Table: NttTable<ValueT = T>,
    {
        let controls = key.controls();
        let size = controls.size();
        let n = size.glwe_size().poly_length().get();
        let modulus = controls.ring_modulus();
        let ControlAggregationWorkspace {
            input_exponents,
            rotation_groups,
            aggregate,
            scratch,
            external_product,
        } = &mut self.inner;
        modulus_switch.exponent_slice_to(input.a(), input_exponents);
        let initial_exponent = modulus_switch.exponent(input.b()).wrapping_neg() & (2 * n - 1);
        let (mask, body) = output.a_b_mut_slices(n);
        mask.fill(T::ZERO);
        lookup_table.mul_monomial_to(initial_exponent, &mut Polynomial(body), modulus);

        let controls_per_block =
            key.block_size() + usize::from(key.occupancy() == BlockOccupancy::AtMostOne);
        let mut output_is_current = true;
        for (exponents, ciphertexts) in input_exponents.chunks_exact(key.block_size()).zip(
            controls
                .as_slice()
                .chunks_exact(controls_per_block * size.ggsw_len()),
        ) {
            let (selections, dummy) = ciphertexts.split_at(key.block_size() * size.ggsw_len());
            // Always overwrite the previous block's NTT representation. The
            // validated layout has either one full dummy or no dummy at all.
            if dummy.is_empty() {
                aggregate.fill(T::ZERO);
            } else {
                aggregate.copy_from_slice(dummy);
            }
            aggregate_controls_assign(
                exponents.iter().copied(),
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
                    controls.basis(),
                    modulus,
                    ntt,
                    external_product,
                );
            } else {
                aggregate_ntt.external_product_to(
                    scratch,
                    &mut output,
                    controls.basis(),
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

/// Batched block BR sharing read-only key tiles across independent chains.
///
/// Allocates `LANES` lanes once, with capacities four (the default) or sixteen.
/// Each lane owns exponents, aggregate, accumulator and product scratch; inputs
/// share one key and LUT. Sixteen-lane batches use 16/8/4/2/1 groups; the default
/// uses 4/2/1. Each chain preserves its block/NTT/product order and equals a
/// single-input call. This operation neither sums inputs nor performs KS or
/// extraction. Capacity changes scratch size, not the key or arithmetic.
pub struct BlockGlweBlindRotationBatchWorkspace<T: FheUint, const LANES: usize = 4> {
    lanes: Box<[BlockGlweBlindRotationWorkspace<T>; LANES]>,
}

impl<T: FheUint, const LANES: usize> BlockGlweBlindRotationBatchWorkspace<T, LANES> {
    /// Allocates `LANES` lanes for this control geometry. Keys with the same input
    /// dimension and gadget size can reuse them across block widths and occupancy
    /// modes: only scratch is retained, while each call uses the key's layout.
    /// Missing cached rotation descriptors use on-demand addressing.
    ///
    /// # Panics
    /// Panics if `LANES` is neither four nor sixteen.
    #[must_use]
    pub fn new(key: &BlockGlweBootstrappingKey<T, BarrettModulus<T>>) -> Self {
        assert!(
            LANES == 4 || LANES == 16,
            "block blind-rotation batch capacity must be four or sixteen"
        );
        Self {
            lanes: Box::new(std::array::from_fn(|_| {
                BlockGlweBlindRotationWorkspace::new(key)
            })),
        }
    }

    /// Blind-rotates paired inputs/outputs using one encoded LUT, without online
    /// allocation. Accepts any batch length, including zero, and retains order.
    ///
    /// # Correctness
    /// Inherits [`BlockGlweBlindRotationWorkspace::blind_rotate_lookup_table_to`]'s
    /// input, key, LUT and numerical requirements. Each output is a complete
    /// coefficient-domain GLWE ciphertext under the same accumulator secret.
    ///
    /// # Panics
    /// Checks all counts, input/output/workspace layouts, the LUT, quantizer and
    /// NTT parameters before writing any output, including malformed late entries.
    pub fn blind_rotate_lookup_table_many_to<Table, A, B, C>(
        &mut self,
        key: &BlockGlweBootstrappingKey<T, BarrettModulus<T>>,
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
        // Lanes have no independent mutation/rebinding path. One shape check
        // covers every private lane; caller-owned ciphertexts are checked below.
        self.lanes[0].check_layout(key);
        assert_eq!(
            inputs.len(),
            outputs.len(),
            "block blind-rotation input/output count mismatch"
        );
        assert!(
            inputs
                .iter()
                .all(|input| input.dimension() == key.controls().input_dimension().get()),
            "block blind-rotation input layout mismatch"
        );
        assert!(
            outputs
                .iter()
                .all(|output| output.as_ref().len() == key.controls().size().glwe_len()),
            "block blind-rotation output layout mismatch"
        );
        let (inputs, outputs) = if LANES == 16 {
            let (groups, input_tail) = inputs.as_chunks::<16>();
            let (output_groups, output_tail) = outputs.as_chunks_mut::<16>();
            for (inputs, outputs) in groups.iter().zip(output_groups) {
                self.blind_rotate_group_to(key, inputs, lookup_table, modulus_switch, outputs, ntt);
            }
            // A short tail still shares the key across eight chains, rather
            // than restarting two four-lane traversals.
            let (groups, input_tail) = input_tail.as_chunks::<8>();
            let (output_groups, output_tail) = output_tail.as_chunks_mut::<8>();
            for (inputs, outputs) in groups.iter().zip(output_groups) {
                self.blind_rotate_group_to(key, inputs, lookup_table, modulus_switch, outputs, ntt);
            }
            (input_tail, output_tail)
        } else {
            (inputs, outputs)
        };
        let (input_groups, input_tail) = inputs.as_chunks::<4>();
        let (output_groups, output_tail) = outputs.as_chunks_mut::<4>();
        for (inputs, outputs) in input_groups.iter().zip(output_groups) {
            self.blind_rotate_group_to(key, inputs, lookup_table, modulus_switch, outputs, ntt);
        }
        let (input_pairs, input_tail) = input_tail.as_chunks::<2>();
        let (output_pairs, output_tail) = output_tail.as_chunks_mut::<2>();
        for (inputs, outputs) in input_pairs.iter().zip(output_pairs) {
            self.blind_rotate_group_to(key, inputs, lookup_table, modulus_switch, outputs, ntt);
        }
        for (input, output) in input_tail.iter().zip(output_tail) {
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

    /// The public boundary has validated all buffers. A group borrows the first
    /// ACTIVE private lanes; construction and dispatch establish ACTIVE <= LANES.
    fn blind_rotate_group_to<Table, A, B, C, const ACTIVE: usize>(
        &mut self,
        key: &BlockGlweBootstrappingKey<T, BarrettModulus<T>>,
        inputs: &[Lwe<A>; ACTIVE],
        lookup_table: &Polynomial<B>,
        modulus_switch: &RotationModulusSwitch<T>,
        outputs: &mut [Glwe<C>; ACTIVE],
        ntt: &Table,
    ) where
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let lanes = self
            .lanes
            .as_mut_slice()
            .first_chunk_mut::<ACTIVE>()
            .expect("block batch group exceeds its allocated lanes");
        blind_rotate_groups_batch_kernel(
            lanes.each_mut().map(|lane| &mut lane.inner),
            key.controls(),
            blocks(key),
            inputs.each_ref().map(Lwe::as_view),
            lookup_table.as_view(),
            modulus_switch,
            outputs.each_mut().map(Glwe::as_mut_view),
            ntt,
        );
    }
}

/// Consecutive logical blocks directly describe the control order. Every group
/// includes a final independently encrypted dummy only for AtMostOne.
fn blocks<T: FheUint>(
    key: &BlockGlweBootstrappingKey<T, BarrettModulus<T>>,
) -> impl Iterator<Item = (core::ops::Range<usize>, &[T])> {
    let width = key.block_size();
    let count = width + usize::from(key.occupancy() == BlockOccupancy::AtMostOne);
    key.controls()
        .as_slice()
        .chunks_exact(count * key.controls().size().ggsw_len())
        .enumerate()
        .map(move |(block, controls)| (block * width..(block + 1) * width, controls))
}

/// Shared raw boundary for the key's ordinary step-one LUT and transform domain.
fn check_lookup_table<T: FheUint, Table: NttTable<ValueT = T>>(
    key: &BlockGlweBootstrappingKey<T, BarrettModulus<T>>,
    lookup_table: Polynomial<&[T]>,
    modulus_switch: &RotationModulusSwitch<T>,
    ntt: &Table,
) {
    let controls = key.controls();
    let n = controls.size().glwe_size().poly_length().get();
    assert_eq!(
        modulus_switch.rotation_step(),
        1,
        "ordinary blind rotation requires step one"
    );
    assert!(
        modulus_switch.is_compatible(controls.input_modulus_value(), 2 * n),
        "block blind-rotation quantizer domain mismatch"
    );
    assert_eq!(
        lookup_table.as_ref().len(),
        n,
        "block blind-rotation LUT length mismatch"
    );
    assert_eq!(
        (ntt.poly_length().get(), ntt.modulus()),
        (n, controls.ring_modulus().value()),
        "block blind-rotation NTT layout mismatch"
    );
}
