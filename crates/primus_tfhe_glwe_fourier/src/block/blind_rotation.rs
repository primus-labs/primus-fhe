//! Direct contiguous-block aggregation and ordinary Fourier blind rotation.

use primus_data::{Data, DataMut};
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_glwe::BlockOccupancy;
use primus_lattice::{glwe::TorusGlwe, lwe::Lwe, workspace::FourierGlweExternalProductWorkspace};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_tfhe::rotation::RotationModulusSwitch;

use crate::sparse::{ControlAggregationWorkspace, aggregate_controls_assign};

use super::BlockGlweBootstrappingKey;

/// Reusable single-input workspace for native-torus block-binary blind rotation.
///
/// Owns n public input exponents, coefficient and Fourier aggregates, one GLWE
/// buffer and the existing external-product scratch. Contiguous blocks need no
/// bucket map, secret support, repeated controls or online allocation.
pub struct BlockGlweBlindRotationWorkspace<T: TorusFftValue> {
    inner: ControlAggregationWorkspace<T>,
}

impl<T: TorusFftValue> BlockGlweBlindRotationWorkspace<T> {
    /// Allocates scratch for this key's logical input dimension and gadget layout.
    #[must_use]
    pub fn new(key: &BlockGlweBootstrappingKey<T, NativeModulus<T>>) -> Self {
        Self {
            inner: ControlAggregationWorkspace::new(key.controls()),
        }
    }

    pub(crate) fn with_external_product<R>(
        &mut self,
        size: primus_lattice::GadgetSize,
        operation: impl FnOnce(&mut FourierGlweExternalProductWorkspace<T>) -> R,
    ) -> R {
        self.inner.with_external_product(size, operation)
    }

    /// Blind-rotates an encoded LUT into a native coefficient GLWE ciphertext.
    ///
    /// Initializes X^(-R(b))*LUT, then processes every block using
    /// sum(X^R(a_i)*GGSW(s_i)), plus GGSW(1-sum(s_i)) only for AtMostOne.
    /// All encrypted-zero selectors participate in either mode. The
    /// output is overwritten without key switching or sample extraction.
    ///
    /// # Correctness
    ///
    /// Input residues are canonical at the key's input modulus q and use its
    /// block-binary control secret. The LUT contains N native-torus coefficients
    /// with a suitable encoding and noise margin. Quantization uses ordinary
    /// PBS step one. Coefficient aggregation is exact modulo 2^T::BITS; ordinary
    /// FFT conversion and external products retain their floating-point rounding
    /// error and finite-precision requirements.
    ///
    /// # Panics
    ///
    /// Panics before output writes if input, LUT, output, workspace, quantizer
    /// or FFT dimensions do not match the key.
    pub fn blind_rotate_lookup_table_to<Table, A, B, C>(
        &mut self,
        key: &BlockGlweBootstrappingKey<T, NativeModulus<T>>,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        modulus_switch: &RotationModulusSwitch<T>,
        output: &mut TorusGlwe<C>,
        fft: &mut FftEngine<'_, Table>,
    ) where
        Table: FftTable,
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
                output.as_ref().len(),
            ),
            (controls.input_dimension().get(), n, size.glwe_len()),
            "block blind-rotation input, LUT or output layout mismatch"
        );
        assert_eq!(
            (
                self.inner.input_exponents.len(),
                self.inner.external_product.size(),
            ),
            (controls.input_dimension().get(), size),
            "block blind-rotation workspace layout mismatch"
        );
        assert_eq!(
            fft.poly_length().get(),
            n,
            "block blind-rotation FFT length mismatch"
        );
        self.blind_rotate_interleaved_lookup_table_kernel_to(
            key,
            input.as_view(),
            lookup_table.as_view(),
            modulus_switch,
            output.as_mut_view(),
            fft,
        );
    }

    /// The public boundary or evaluator has checked layouts and bound one
    /// quantizer to all coefficients. A compiled ManyLUT may use a larger step
    /// to preserve output slots; the native aggregation is unchanged.
    pub(crate) fn blind_rotate_interleaved_lookup_table_kernel_to<Table>(
        &mut self,
        key: &BlockGlweBootstrappingKey<T, NativeModulus<T>>,
        input: Lwe<&[T]>,
        lookup_table: Polynomial<&[T]>,
        modulus_switch: &RotationModulusSwitch<T>,
        mut output: TorusGlwe<&mut [T]>,
        fft: &mut FftEngine<'_, Table>,
    ) where
        Table: FftTable,
    {
        let controls = key.controls();
        let size = controls.size();
        let n = size.glwe_size().poly_length().get();
        let modulus = controls.ring_modulus();
        let ControlAggregationWorkspace {
            input_exponents,
            aggregate,
            transformed,
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
            // ExactlyOne has no dummy; encrypted-zero selectors still take
            // part in the full aggregate. Overwrite dirty scratch in either mode.
            if dummy.is_empty() {
                aggregate.as_mut().fill(T::ZERO);
            } else {
                aggregate.as_mut().copy_from_slice(dummy);
            }
            aggregate_controls_assign(exponents.iter().copied(), selections, aggregate, n, modulus);
            // Native wrapping is exact; only the completed aggregate is lifted
            // at normalized torus scale and transformed with ordinary FFT.
            aggregate.write_fourier_form(transformed, fft);
            if output_is_current {
                transformed.external_product_to(
                    &output,
                    scratch,
                    controls.basis(),
                    fft,
                    external_product,
                );
            } else {
                transformed.external_product_to(
                    scratch,
                    &mut output,
                    controls.basis(),
                    fft,
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
