//! Native-torus automorphisms using Fourier key switching.

use crate::{
    FourierGlweEncryptor, FourierGlweKeySwitchingKey, FourierGlweKeySwitchingWorkspace,
    GlevParameters, GlweSecretKey, GlweSize,
};
use num_traits::ConstZero;
use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::glwe::{FourierGlwe, Glwe};
use primus_modulus::NativeModulus;
use primus_poly::{CoeffAutomorphismPermutation, FourierPolynomial, PolynomialIterMut};

/// Reusable workspace for coefficient- and Fourier-domain automorphisms.
pub struct FourierGlweAutomorphismWorkspace<T: TorusFftValue> {
    transformed: Glwe<Vec<T>>,
    permuted_fourier: Vec<Complex64>,
    key_switching: FourierGlweKeySwitchingWorkspace<T>,
}
impl<T: TorusFftValue> FourierGlweAutomorphismWorkspace<T> {
    /// Allocates buffers for one immutable GLWE layout.
    #[must_use]
    pub fn new(size: GlweSize) -> Self {
        Self {
            transformed: Glwe::zero(size.glwe_len()),
            permuted_fourier: vec![Complex64::default(); size.fourier_poly_len()],
            key_switching: FourierGlweKeySwitchingWorkspace::new(size),
        }
    }
}

/// Evaluation key for `X -> X^degree`, returning to the original GLWE key.
#[derive(Clone)]
pub struct FourierGlweAutomorphismKey<T: TorusFftValue> {
    degree: usize,
    permutation: CoeffAutomorphismPermutation,
    fourier_permutation: Vec<(usize, bool)>,
    key_switching: FourierGlweKeySwitchingKey<T>,
}
impl<T: TorusFftValue> FourierGlweAutomorphismKey<T> {
    /// Generates an automorphism key.
    ///
    /// # Correctness
    /// Evaluation must use the FFT table instance supplied during generation.
    /// Coefficients negated by the automorphism must have representable signed
    /// negations, as required by [`CoeffAutomorphismPermutation::apply_signed_to`].
    ///
    /// # Panics
    /// Panics if degree is not odd and below `2N`, or key, parameter, FFT
    /// layouts differ. Checks precede sampling.
    #[must_use]
    pub fn generate<Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        degree: usize,
        encryptor: &mut FourierGlweEncryptor<'_, T>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> Self {
        encryptor.assert_gadget_compatible(params, fft);

        Self::generate_kernel(degree, encryptor, params, fft, rng)
    }

    /// Caller checked the target layout and FFT against `params`; the
    /// permutation still validates the odd automorphism degree.
    pub(crate) fn generate_kernel<Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        degree: usize,
        encryptor: &mut FourierGlweEncryptor<'_, T>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> Self {
        let secret = encryptor.coefficient_secret();
        let size = secret.glwe_size();
        let permutation = CoeffAutomorphismPermutation::new(degree, size.poly_length());
        let mut transformed = GlweSecretKey::new(
            vec![T::SignedInteger::ZERO; size.mask_len()],
            size,
            secret.distr(),
        );
        for (input, output) in secret
            .iter()
            .zip(transformed.key.chunks_exact_mut(size.poly_length().get()))
        {
            permutation.apply_signed_to::<T>(input, output);
        }
        let key_switching =
            FourierGlweKeySwitchingKey::generate_kernel(&transformed, encryptor, params, fft, rng);
        Self {
            fourier_permutation: fft.table().automorphism_map(degree),
            degree,
            permutation,
            key_switching,
        }
    }
    /// Returns the odd automorphism exponent.
    #[must_use]
    pub fn degree(&self) -> usize {
        self.degree
    }
    /// Returns the decomposition basis bound to this key.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.key_switching.basis()
    }
    /// Applies the automorphism to a coefficient-domain torus GLWE.
    ///
    /// Use the FFT table instance from key generation. Output is overwritten.
    /// Panics before writes on incompatible input/output, FFT or workspace layout.
    pub fn apply_to<Table: FftTable, A: Data<Elem = T>, B: DataMut<Elem = T>>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweAutomorphismWorkspace<T>,
    ) {
        let len = self.key_switching.output_size().glwe_len();
        assert_eq!(
            input.as_ref().len(),
            len,
            "automorphism input layout mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            len,
            "automorphism output layout mismatch"
        );
        self.assert_compatible(fft, workspace);
        self.apply_kernel_to(input.as_view(), output.as_mut_view(), fft, workspace);
    }
    /// Applies the automorphism to a Fourier-domain torus GLWE, returning a
    /// Fourier GLWE under the original secret. Only masks are inverse-transformed
    /// for coefficient decomposition; the body and final result stay in Fourier form.
    /// Reuses the evaluation key and workspace without allocation.
    ///
    /// # Correctness
    /// Input, key generation and evaluation must use the same FFT table instance.
    /// Floating-point conversion and decomposition errors must fit the caller's
    /// precision budget; this need not be bit-identical to a coefficient roundtrip.
    ///
    /// # Panics
    /// Panics before writes if ciphertext, FFT or workspace layouts differ from the key.
    pub fn apply_fourier_to<
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = Complex64>,
    >(
        &self,
        input: &FourierGlwe<A>,
        output: &mut FourierGlwe<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweAutomorphismWorkspace<T>,
    ) {
        let len = self
            .key_switching
            .output_size()
            .glwe_size()
            .fourier_glwe_len();
        assert_eq!(
            input.as_ref().len(),
            len,
            "Fourier automorphism input layout mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            len,
            "Fourier automorphism output layout mismatch"
        );
        self.assert_compatible(fft, workspace);
        self.apply_fourier_kernel_to(input.as_view(), output.as_mut_view(), fft, workspace);
    }

    /// Requires validated ciphertext layouts and matching FFT/key/workspace resources.
    /// Only masks return to coefficients for decomposition; the body stays in Fourier form.
    fn apply_fourier_kernel_to<Table: FftTable>(
        &self,
        input: FourierGlwe<&[Complex64]>,
        output: FourierGlwe<&mut [Complex64]>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweAutomorphismWorkspace<T>,
    ) {
        let h = fft.fourier_length();
        let n = fft.poly_length().get();
        let (input_mask, input_body) = input.a_b(h);
        let (transformed_mask, _) = workspace.transformed.a_b_mut_slices(n);
        for (input, mut coeff) in input_mask.zip(PolynomialIterMut::new(transformed_mask, n)) {
            self.permute_fourier_to(input.as_ref(), &mut workspace.permuted_fourier);
            fft.backward_as_torus(&workspace.permuted_fourier, coeff.as_mut());
        }
        self.permute_fourier_to(input_body.as_ref(), &mut workspace.permuted_fourier);
        self.key_switching.key_switch_fourier_kernel_to(
            transformed_mask,
            FourierPolynomial::new(workspace.permuted_fourier.as_slice()),
            output,
            fft,
            &mut workspace.key_switching,
        );
    }

    /// Uses the validated, generation-time map for one polynomial in the bound FFT order.
    fn permute_fourier_to(&self, input: &[Complex64], output: &mut [Complex64]) {
        for (output, &(source, conjugate)) in output.iter_mut().zip(&self.fourier_permutation) {
            let value = input[source];
            *output = if conjugate { value.conj() } else { value };
        }
    }

    pub(crate) fn assert_compatible<Table: FftTable>(
        &self,
        fft: &FftEngine<'_, Table>,
        workspace: &FourierGlweAutomorphismWorkspace<T>,
    ) {
        self.key_switching
            .assert_compatible(fft, &workspace.key_switching);
    }
    /// Applies after the owning boundary validates ciphertexts, FFT and workspace.
    pub(crate) fn apply_kernel_to<Table: FftTable>(
        &self,
        input: Glwe<&[T]>,
        output: Glwe<&mut [T]>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweAutomorphismWorkspace<T>,
    ) {
        let n = self.key_switching.poly_length().get();
        for (input, mut output) in input
            .iter_poly(n)
            .zip(workspace.transformed.iter_poly_mut(n))
        {
            self.permutation
                .apply_to(input.as_ref(), output.as_mut(), NativeModulus::new());
        }
        self.key_switching.key_switch_kernel_to(
            workspace.transformed.as_view(),
            output,
            fft,
            &mut workspace.key_switching,
        );
    }
}
