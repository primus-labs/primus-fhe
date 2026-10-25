//! Sparse blind rotation: native coefficient aggregation, FFT, external product.

use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::{
    ggsw::{FourierGgsw, Ggsw},
    glwe::TorusGlwe,
    lwe::Lwe,
    workspace::FourierGlweExternalProductWorkspace,
};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_tfhe::rotation::RotationModulusSwitch;

use super::SparseGlweBootstrappingKey;

/// Reusable workspace for Fourier [`SparseGlweBootstrappingKey`] blind rotation.
///
/// Stores public input exponents, coefficient and Fourier aggregate buffers,
/// one coefficient GLWE buffer and external-product scratch. It contains no
/// plaintext secret support or matching, and allocates only during construction.
pub struct SparseGlweBlindRotationWorkspace<T: TorusFftValue> {
    input_exponents: Vec<usize>,
    aggregate: Ggsw<Vec<T>>,
    transformed: FourierGgsw<Vec<Complex64>>,
    scratch: TorusGlwe<Vec<T>>,
    external_product: FourierGlweExternalProductWorkspace<T>,
}

impl<T: TorusFftValue> SparseGlweBlindRotationWorkspace<T> {
    pub(crate) fn with_external_product<R>(
        &mut self,
        size: primus_lattice::GadgetSize,
        operation: impl FnOnce(&mut FourierGlweExternalProductWorkspace<T>) -> R,
    ) -> R {
        self.external_product.with_rebound(size, operation)
    }

    /// Allocates scratch for this key's input dimension and gadget layout.
    /// Reusable with other sparse keys of the same dimensions and layout.
    #[must_use]
    pub fn new(key: &SparseGlweBootstrappingKey<T, NativeModulus<T>>) -> Self {
        let size = key.size();
        Self {
            input_exponents: vec![0; key.input_dimension().get()],
            aggregate: Ggsw::zero(size.ggsw_len()),
            transformed: FourierGgsw::zero(size.fourier_ggsw_len()),
            scratch: TorusGlwe::zero(size.glwe_len()),
            external_product: FourierGlweExternalProductWorkspace::new(size),
        }
    }
}

impl<T: TorusFftValue> SparseGlweBlindRotationWorkspace<T> {
    /// Blind-rotates an encoded LUT into a native coefficient GLWE ciphertext.
    ///
    /// Uses ordinary PBS quantization (rotation step one), initializing a trivial
    /// accumulator with `X^(-R(b)) * LUT`. Each bucket's control encrypts its
    /// selected `X^R(a[i])`, or `1` if unoccupied. All encrypted zero entries and
    /// dummies contribute to the control's noise; none are skipped.
    /// The output is overwritten and scratch is reused without online allocation.
    ///
    /// # Correctness
    ///
    /// Input must use this key's small-LWE secret and canonical residues at q.
    /// The LUT contains `N` encoded
    /// native-torus coefficients with sufficient input and output noise margins.
    /// This raw operation performs neither key switching nor sample extraction.
    /// Coefficient aggregation is exact modulo `2^T::BITS`; conversion to Fourier
    /// form and external products add floating-point rounding error.
    ///
    /// # Panics
    ///
    /// Panics if input, LUT, output, workspace or FFT polynomial lengths do not
    /// match this key, or the quantizer has a different q, rotation domain or
    /// (for ordinary PBS) step. Checks precede output writes.
    pub fn blind_rotate_lookup_table_to<Table, A, B, C>(
        &mut self,
        key: &SparseGlweBootstrappingKey<T, NativeModulus<T>>,
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
        assert_eq!(
            modulus_switch.rotation_step(),
            1,
            "ordinary blind rotation requires step one"
        );
        self.blind_rotate_interleaved_lookup_table_to(
            key,
            input,
            lookup_table,
            modulus_switch,
            output,
            fft,
        );
    }

    /// Blind-rotates an interleaved LUT, preserving its output columns.
    ///
    /// Quantizes every mask and body coefficient to `2N / rotation_step`, then
    /// multiplies by `rotation_step`. This must be the LUT's padded output count:
    /// a nonzero power of two dividing `N`.
    /// Inherits [`Self::blind_rotate_lookup_table_to`]'s requirements, except that
    /// the quantizer uses the LUT's slot spacing instead of step one.
    /// A quantizer for a different q or rotation domain panics before output writes.
    pub fn blind_rotate_interleaved_lookup_table_to<Table, A, B, C>(
        &mut self,
        key: &SparseGlweBootstrappingKey<T, NativeModulus<T>>,
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
        let size = key.size();
        let poly_length = size.glwe_size().poly_length().get();
        assert!(
            modulus_switch.is_compatible(key.input_modulus_value(), 2 * poly_length),
            "sparse blind-rotation quantizer domain mismatch"
        );
        assert_eq!(
            (
                input.dimension(),
                lookup_table.as_ref().len(),
                output.as_ref().len(),
            ),
            (key.input_dimension().get(), poly_length, size.glwe_len()),
            "sparse blind-rotation input, LUT or output layout mismatch"
        );
        assert_eq!(
            (self.input_exponents.len(), self.external_product.size()),
            (key.input_dimension().get(), size),
            "sparse blind-rotation workspace layout mismatch"
        );
        assert_eq!(
            fft.poly_length().get(),
            poly_length,
            "sparse blind-rotation FFT length mismatch"
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

    /// The public raw wrapper or evaluator has bound the quantizer and checked layouts, FFT and LUT.
    /// Mask and body use the same step so every rotation preserves output slots.
    pub(crate) fn blind_rotate_interleaved_lookup_table_kernel_to<Table>(
        &mut self,
        key: &SparseGlweBootstrappingKey<T, NativeModulus<T>>,
        input: Lwe<&[T]>,
        lookup_table: Polynomial<&[T]>,
        modulus_switch: &RotationModulusSwitch<T>,
        mut output: TorusGlwe<&mut [T]>,
        fft: &mut FftEngine<'_, Table>,
    ) where
        Table: FftTable,
    {
        let size = key.size();
        let poly_length = size.glwe_size().poly_length().get();
        let modulus = key.ring_modulus();
        let SparseGlweBlindRotationWorkspace {
            input_exponents,
            aggregate,
            transformed,
            scratch,
            external_product,
        } = self;
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
            // A bucket always has one dummy, including publicly empty buckets.
            // Start from it so no aggregation state survives the previous bucket.
            aggregate.as_mut().copy_from_slice(dummy);
            let ggsw_len = size.ggsw_len();
            // Fuse two rotations so each accumulator coefficient is loaded and
            // stored once per pair; each modular contribution remains canonical.
            let (index_pairs, index_tail) = indices.as_chunks::<2>();
            let mut selection_pairs = selections.chunks_exact(2 * ggsw_len);
            for (indices, pair) in index_pairs.iter().zip(selection_pairs.by_ref()) {
                let (a, b) = pair.split_at(ggsw_len);
                aggregate.add_mul_monomial_pair_assign(
                    &Ggsw::new(a),
                    input_exponents[indices[0]],
                    &Ggsw::new(b),
                    input_exponents[indices[1]],
                    poly_length,
                    modulus,
                );
            }
            if let Some(&index) = index_tail.first() {
                let selection = selection_pairs.remainder();
                for (acc, source) in aggregate
                    .as_mut()
                    .chunks_exact_mut(poly_length)
                    .zip(selection.chunks_exact(poly_length))
                {
                    Polynomial(acc).add_mul_monomial_assign(
                        &Polynomial(source),
                        input_exponents[index],
                        modulus,
                    );
                }
            }
            // Transform only the completed aggregate. Native wrapping above is
            // exact; each polynomial is lifted at the normalized torus scale.
            aggregate.write_fourier_form(transformed, fft);
            if output_is_current {
                transformed.external_product_to(
                    &output,
                    scratch,
                    key.basis(),
                    fft,
                    external_product,
                );
            } else {
                transformed.external_product_to(
                    scratch,
                    &mut output,
                    key.basis(),
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
