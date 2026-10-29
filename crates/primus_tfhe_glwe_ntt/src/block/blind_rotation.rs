//! Direct contiguous-block aggregation and NTT blind rotation.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::{
    ggsw::Ggsw, glwe::Glwe, lwe::Lwe, workspace::NttGlweExternalProductWorkspace,
};
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_tfhe::rotation::RotationModulusSwitch;

use crate::sparse::{ControlAggregationWorkspace, aggregation::aggregate_controls_assign};

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
    /// GGSW(1-sum(s_i)) + sum(X^R(a_i)*GGSW(s_i)). An empty secret block still
    /// consumes its encrypted dummy and zero selectors. No key switching or
    /// sample extraction is performed; evaluation reuses this workspace.
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
            (
                input.dimension(),
                lookup_table.as_ref().len(),
                output.as_ref().len()
            ),
            (controls.input_dimension().get(), n, size.glwe_len()),
            "block blind-rotation input, LUT or output layout mismatch"
        );
        assert_eq!(
            (
                self.inner.input_exponents.len(),
                self.inner.external_product.size()
            ),
            (controls.input_dimension().get(), size),
            "block blind-rotation workspace layout mismatch"
        );
        assert_eq!(
            (ntt.poly_length().get(), ntt.modulus()),
            (n, controls.ring_modulus().value()),
            "block blind-rotation NTT layout mismatch"
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

        let mut output_is_current = true;
        for (exponents, ciphertexts) in input_exponents.chunks_exact(key.block_size()).zip(
            controls
                .as_slice()
                .chunks_exact((key.block_size() + 1) * size.ggsw_len()),
        ) {
            let (selections, dummy) = ciphertexts.split_at(key.block_size() * size.ggsw_len());
            // The dummy overwrites the previous block's NTT representation. Its
            // independent encryption also covers all-zero secret blocks.
            aggregate.copy_from_slice(dummy);
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
