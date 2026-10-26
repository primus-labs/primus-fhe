//! Single-modulus GLWE key switching in the Fourier domain.

use aligned_vec::{ABox, avec};
use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::SignedInteger;
use primus_lattice::GlweDimension;
use primus_lattice::{
    GadgetSize, GlweSize,
    glev::FourierGlev,
    glwe::{FourierGlwe, Glwe},
};
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomial, Polynomial};
use primus_reduce::ReduceAddSlice;
use primus_shape::PolyLength;
use zeroize::Zeroizing;

use crate::{FourierGlweEncryptor, GlevParameters, GlweKeySwitchingParameters, GlweSecretKey};

/// A Fourier-domain GLWE key-switching key for the native torus modulus.
#[derive(Clone)]
pub struct FourierGlweKeySwitchingKey<T: TorusFftValue> {
    data: Vec<Complex64>,
    input_size: GlweSize,
    output_size: GadgetSize,
    basis: ApproxSignedBasis<T>,
}

impl<T: TorusFftValue> FourierGlweKeySwitchingKey<T> {
    /// Generates a Fourier GLWE key-switching key.
    /// Input and output keys must match the layouts bound by `parameters`;
    /// their polynomial length is shared, but their dimensions may differ.
    ///
    /// # Correctness
    ///
    /// Evaluation must use the FFT table instance supplied during generation.
    ///
    /// # Panics
    ///
    /// Panics if input/output key layouts, FFT do not match
    /// `parameters`. Compatibility checks precede sampling.
    #[must_use]
    pub fn generate<Table, R>(
        input_secret_key: &GlweSecretKey<T>,
        output_encryptor: &mut FourierGlweEncryptor<'_, T>,
        parameters: &GlweKeySwitchingParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> Self
    where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        assert_eq!(
            input_secret_key.glwe_size(),
            parameters.input_size(),
            "input GLWE secret layout mismatch"
        );
        let output = parameters.output();
        output_encryptor.assert_gadget_compatible(output, fft);

        Self::generate_kernel(input_secret_key, output_encryptor, output, fft, rng)
    }

    /// Caller checked the source layout, target and FFT against `parameters`.
    /// Automorphism also uses this path without preparing a separate KSK owner;
    /// the combined storage length is checked here for both callers.
    pub(crate) fn generate_kernel<Table, R>(
        input_secret_key: &GlweSecretKey<T>,
        output_encryptor: &mut FourierGlweEncryptor<'_, T>,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> Self
    where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        let output = parameters;

        let input_size = input_secret_key.glwe_size();
        let output_size = output.size();
        let fourier_glev_len = output_size.fourier_glev_len();

        let mut data = vec![
            Complex64::default();
            input_size
                .dimension()
                .get()
                .checked_mul(fourier_glev_len)
                .expect("Fourier GLWE key-switching key length overflow")
        ];
        let mut encoded_secret = Zeroizing::new(vec![T::ZERO; output.poly_length().get()]);

        for (secret_poly, entry) in input_secret_key
            .iter()
            .zip(data.chunks_exact_mut(fourier_glev_len))
        {
            encoded_secret
                .as_mut_slice()
                .iter_mut()
                .zip(secret_poly)
                .for_each(|(output, &coefficient)| {
                    *output = coefficient.cast_to_unsigned();
                });
            output_encryptor.encrypt_glev_kernel_to(
                Polynomial::new(encoded_secret.as_slice()),
                FourierGlev::new(entry),
                output,
                fft,
                rng,
            );
        }

        Self {
            data,
            input_size,
            output_size,
            basis: output.basis().clone(),
        }
    }

    /// Returns the input GLWE dimension.
    #[must_use]
    #[inline]
    pub fn input_dimension(&self) -> GlweDimension {
        self.input_size.dimension()
    }

    /// Returns the output GLWE dimension.
    #[must_use]
    #[inline]
    pub fn output_dimension(&self) -> GlweDimension {
        self.output_size.glwe_size().dimension()
    }

    /// Returns the polynomial length.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.input_size.poly_length()
    }

    /// Returns the output gadget layout bound to this key.
    #[must_use]
    #[inline]
    pub fn output_size(&self) -> GadgetSize {
        self.output_size
    }

    /// Returns the decomposition basis bound to this key and integer width.
    #[must_use]
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the raw Fourier-domain key data.
    #[inline]
    pub fn as_slice(&self) -> &[Complex64] {
        &self.data
    }

    /// Key-switches a coefficient-domain native-torus GLWE ciphertext.
    ///
    /// Uses the decomposition basis and layouts stored during key generation.
    ///
    /// # Correctness
    ///
    /// The FFT must use the table instance used during key generation.
    /// Floating-point and decomposition errors must fit the caller's precision budget.
    ///
    /// # Panics
    ///
    /// Panics if the input/output layouts, FFT length,
    /// or workspace layout are incompatible. Checks precede output writes.
    pub fn key_switch_to<Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweKeySwitchingWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(input.as_ref().len(), self.input_size.glwe_len());
        assert_eq!(output.as_ref().len(), self.output_size.glwe_len());

        self.assert_compatible(fft, workspace);
        self.key_switch_kernel_to(input.as_view(), output.as_mut_view(), fft, workspace);
    }

    /// Validates the transform and private workspace before composite evaluation.
    pub(crate) fn assert_compatible<Table: FftTable>(
        &self,
        fft: &FftEngine<'_, Table>,
        workspace: &FourierGlweKeySwitchingWorkspace<T>,
    ) {
        let poly_length = self.input_size.poly_length().get();
        assert_eq!(
            fft.poly_length().get(),
            poly_length,
            "FFT polynomial length mismatch"
        );
        assert_eq!(
            workspace.accumulator.as_ref().len(),
            self.output_size.glwe_size().fourier_glwe_len(),
            "key-switch workspace layout mismatch"
        );
        assert_eq!(
            workspace.decomposed_poly.len(),
            poly_length,
            "key-switch workspace polynomial length mismatch"
        );
    }

    /// Switches after input/output, transform and workspace have been validated.
    pub(crate) fn key_switch_kernel_to<Table: FftTable>(
        &self,
        input: Glwe<&[T]>,
        mut output: Glwe<&mut [T]>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweKeySwitchingWorkspace<T>,
    ) {
        let poly_length = self.poly_length().get();
        let (input_mask, input_body) = input.a_b_slices(poly_length);
        self.accumulate_mask_kernel(input_mask, fft, workspace);

        workspace.accumulator.write_torus_form(&mut output, fft);
        let modulus = NativeModulus::new();
        output.neg_assign(modulus);
        let (_, output_body) = output.a_b_mut_slices(poly_length);
        modulus.reduce_add_slice_assign(output_body, input_body);
    }

    /// Key-switches validated coefficient masks and a Fourier body into Fourier
    /// output, retaining the accumulator in frequency form. Inputs use this key's
    /// layouts and FFT representation; the owning boundary checks compatibility.
    pub(crate) fn key_switch_fourier_kernel_to<Table: FftTable>(
        &self,
        input_mask: &[T],
        input_body: FourierPolynomial<&[Complex64]>,
        mut output: FourierGlwe<&mut [Complex64]>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweKeySwitchingWorkspace<T>,
    ) {
        self.accumulate_mask_kernel(input_mask, fft, workspace);
        let (acc_mask, acc_body) = workspace.accumulator.a_b_slices(fft.fourier_length());
        let (output_mask, output_body) = output.a_b_mut_slices(fft.fourier_length());
        for (output, &acc) in output_mask.iter_mut().zip(acc_mask) {
            *output = -acc;
        }
        for ((output, &body), &acc) in output_body
            .iter_mut()
            .zip(input_body.as_ref())
            .zip(acc_body)
        {
            *output = body - acc;
        }
    }

    /// Computes the positive switching-key product after layout/backend validation.
    fn accumulate_mask_kernel<Table: FftTable>(
        &self,
        input_mask: &[T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweKeySwitchingWorkspace<T>,
    ) {
        let poly_length = self.poly_length().get();
        let basis = &self.basis;
        let fourier_glwe_len = self.output_size.glwe_size().fourier_glwe_len();
        workspace.accumulator.set_zero();
        for (mask_poly, entry) in input_mask
            .chunks_exact(poly_length)
            .zip(self.data.chunks_exact(self.output_size.fourier_glev_len()))
        {
            basis.init_carry_slice(mask_poly, &mut workspace.carries);
            let entry = FourierGlev::new(entry);
            for (decomposer, key_glwe) in basis
                .decomposer_iter()
                .zip(entry.iter_glwe(fourier_glwe_len))
            {
                decomposer.decompose_slice_to(
                    mask_poly,
                    &mut workspace.decomposed_poly,
                    &mut workspace.carries,
                );
                fft.forward_as_integer(
                    &workspace.decomposed_poly,
                    &mut workspace.decomposed_fourier,
                );
                workspace.accumulator.add_mul_fourier_polynomial_assign(
                    &key_glwe,
                    &FourierPolynomial::new(workspace.decomposed_fourier.as_slice()),
                );
            }
        }
    }

    /// Key-switches into a newly allocated coefficient-domain ciphertext.
    /// Inherits [`Self::key_switch_to`]'s representation and precision requirements.
    ///
    /// # Panics
    ///
    /// Panics on the compatibility mismatches described by [`Self::key_switch_to`].
    pub fn key_switch<Table, A>(
        &self,
        input: &Glwe<A>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweKeySwitchingWorkspace<T>,
    ) -> Glwe<Vec<T>>
    where
        Table: FftTable,
        A: Data<Elem = T>,
    {
        let mut output = Glwe::zero(self.output_size.glwe_len());
        self.key_switch_to(input, &mut output, fft, workspace);
        output
    }
}

/// Reusable Fourier workspace for GLWE key switching and LWE packing key switching.
/// Owned Fourier buffers use cache-line alignment for repeated FFT and product passes.
pub struct FourierGlweKeySwitchingWorkspace<T: TorusFftValue> {
    pub(crate) carries: Box<[bool]>,
    pub(crate) decomposed_poly: Box<[T]>,
    pub(crate) decomposed_fourier: ABox<[Complex64]>,
    pub(crate) accumulator: FourierGlwe<ABox<[Complex64]>>,
}

impl<T: TorusFftValue> FourierGlweKeySwitchingWorkspace<T> {
    /// Creates a workspace for the output GLWE layout.
    pub fn new(glwe_size: GlweSize) -> Self {
        let poly_length = glwe_size.poly_length().get();
        Self {
            carries: vec![false; poly_length].into_boxed_slice(),
            decomposed_poly: vec![T::ZERO; poly_length].into_boxed_slice(),
            decomposed_fourier: avec![Complex64::default(); glwe_size.fourier_poly_len()]
                .into_boxed_slice(),
            accumulator: FourierGlwe(
                avec![
                    Complex64::default();
                    glwe_size.fourier_glwe_len()
                ]
                .into_boxed_slice(),
            ),
        }
    }
}
