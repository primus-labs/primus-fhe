//! Fourier packing key switching with one GLev per input LWE secret coefficient.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::LweDimension;
use primus_lattice::{GadgetSize, glev::FourierGlev, glwe::Glwe, lwe::Lwe};
use primus_lwe::LweSecretKeyRef;
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomial, Polynomial};
use primus_reduce::ReduceAddAssign;
use zeroize::Zeroizing;

use crate::{
    FourierGlweGadgetEncryptWorkspace, FourierGlweKeySwitchingWorkspace, FourierGlweSecretKey,
    GlevParameters,
};

/// Fourier GLev encryptions of an independent input LWE secret's scalar coefficients.
///
/// Storage follows `[input coefficient][level][GLWE component][Fourier coefficient]`.
/// Each GLev encrypts a constant polynomial under the output GLWE secret.
/// Input and output use the same ciphertext modulus and message encoding.
#[derive(Clone)]
pub struct FourierLwePackingKeySwitchingKey<T: TorusFftValue> {
    data: Vec<Complex64>,
    input_dimension: LweDimension,
    output_size: GadgetSize,
    basis: ApproxSignedBasis<T>,
}

impl<T: TorusFftValue> FourierLwePackingKeySwitchingKey<T> {
    /// Generates a packing key from an arbitrary LWE secret to the output GLWE secret.
    ///
    /// # Correctness
    ///
    /// The input secret uses native-torus coefficients. The output secret must
    /// have been constructed with the supplied FFT table instance.
    ///
    /// # Panics
    ///
    /// Panics before sampling if the input dimension is zero, storage length
    /// overflows, or the output key, FFT or workspace do not match `params`.
    pub fn generate<Table, R>(
        input_secret_key: LweSecretKeyRef<'_, T>,
        output_secret_key: &FourierGlweSecretKey,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierGlweGadgetEncryptWorkspace<T>,
    ) -> Self
    where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        let input_dimension = LweDimension::new(input_secret_key.dimension());
        output_secret_key.assert_gadget_compatible(params, fft);
        workspace.assert_glev_compatible(params.size());
        let length = input_dimension
            .get()
            .checked_mul(params.fourier_glev_len())
            .expect("packing key length overflow");
        let mut data = vec![Complex64::default(); length];
        let mut message = Zeroizing::new(vec![T::ZERO; params.poly_length().get()]);
        let mut entries = data.chunks_exact_mut(params.fourier_glev_len());
        super::for_each_secret(input_secret_key, params.cipher_modulus(), |secret| {
            message[0] = secret;
            output_secret_key.encrypt_glev_kernel_to(
                Polynomial::new(message.as_slice()),
                FourierGlev::new(entries.next().expect("one GLev per secret coefficient")),
                params,
                fft,
                rng,
                workspace,
            );
        });
        Self {
            data,
            input_dimension,
            output_size: params.size(),
            basis: params.basis().clone(),
        }
    }

    /// Returns the input LWE dimension.
    #[must_use]
    pub fn input_dimension(&self) -> LweDimension {
        self.input_dimension
    }

    /// Returns the output GLWE layout and key decomposition level count.
    #[must_use]
    pub fn output_size(&self) -> GadgetSize {
        self.output_size
    }

    /// Returns the decomposition basis stored with this key.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the Fourier key data in coefficient/level/component order.
    #[must_use]
    pub fn as_slice(&self) -> &[Complex64] {
        &self.data
    }

    /// Converts one LWE to a GLWE whose target message is constant.
    ///
    /// Inherits [`Self::pack_lwes_to`]'s correctness and workspace contracts.
    ///
    /// # Panics
    ///
    /// Inherits [`Self::pack_lwes_to`]'s checks and also rejects input that is
    /// not exactly one LWE of this key's input dimension, before output writes.
    pub fn key_switch_to<Table, A, B>(
        &self,
        input: &Lwe<A>,
        output: &mut Glwe<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweKeySwitchingWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.input_dimension.ciphertext_len(),
            "packing input LWE dimension mismatch"
        );
        self.pack_lwes_to(input.as_ref(), output, fft, workspace);
    }

    /// Packs `p` LWEs into a coefficient-domain GLWE targeting `sum_i m_i X^i`.
    ///
    /// Input is a flat slice of complete `[mask, body]` LWEs. Any `p` in
    /// `1..=N` is accepted. The target message tail `p..N` is zero; the noisy
    /// phase need not be zero there. All output coefficients are overwritten.
    /// Uses an output-layout GLWE key-switch workspace without allocating.
    ///
    /// # Correctness
    ///
    /// Inputs must use the secret from key generation and canonical residues
    /// under the native modulus. Use the FFT table instance from key generation.
    /// No message rescaling is applied. The phase includes input noise,
    /// secret-weighted decomposition error, accumulated key noise and floating-point
    /// error, including in the tail. Parameters must provide enough decoding margin for the batch size.
    ///
    /// # Panics
    ///
    /// Panics before writes if the batch is empty, incomplete or larger than N,
    /// or the output, FFT or workspace do not match this key.
    pub fn pack_lwes_to<Table, B>(
        &self,
        input: &[T],
        output: &mut Glwe<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweKeySwitchingWorkspace<T>,
    ) where
        Table: FftTable,
        B: DataMut<Elem = T>,
    {
        let size = self.output_size.glwe_size();
        let poly_length = size.poly_length().get();
        let count = super::check_batch(input.len(), self.input_dimension.get(), poly_length);
        assert_eq!(
            output.as_ref().len(),
            size.glwe_len(),
            "packing output GLWE layout mismatch"
        );
        assert_eq!(
            fft.poly_length().get(),
            poly_length,
            "packing FFT polynomial length mismatch"
        );
        assert_eq!(
            workspace.decomposed_poly.len(),
            poly_length,
            "packing workspace polynomial length mismatch"
        );
        assert_eq!(
            workspace.accumulator.as_ref().len(),
            size.fourier_glwe_len(),
            "packing workspace GLWE layout mismatch"
        );

        // For D[j,l](X) = sum_i digit_l(a[i,j]) X^i, compute
        // (0, sum_i b_i X^i) - sum_{j,l} D[j,l](X) * K[j,l].
        let lwe_len = self.input_dimension.ciphertext_len();
        workspace.accumulator.set_zero();
        workspace.decomposed_poly[count..].fill(T::ZERO);
        if count == 1 {
            self.accumulate_single(input, workspace);
        } else {
            for (j, entry) in self
                .data
                .chunks_exact(self.output_size.fourier_glev_len())
                .enumerate()
            {
                for (carry, lwe) in workspace.carries[..count]
                    .iter_mut()
                    .zip(input.chunks_exact(lwe_len))
                {
                    *carry = self.basis.init_value_carry(lwe[j]).1;
                }
                for (decomposer, key_glwe) in self
                    .basis
                    .decomposer_iter()
                    .zip(FourierGlev::new(entry).iter_glwe(size.fourier_glwe_len()))
                {
                    // Native decomposition uses the original mask at every level; only carry changes.
                    for ((digit, carry), lwe) in workspace.decomposed_poly[..count]
                        .iter_mut()
                        .zip(&mut workspace.carries[..count])
                        .zip(input.chunks_exact(lwe_len))
                    {
                        (*digit, *carry) = decomposer.decompose(lwe[j], *carry);
                    }
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
        workspace.accumulator.write_torus_form(output, fft);
        let modulus = NativeModulus::new();
        output.neg_assign(modulus);
        let (_, body) = output.a_b_mut_slices(poly_length);
        for (output, lwe) in body[..count].iter_mut().zip(input.chunks_exact(lwe_len)) {
            modulus.reduce_add_assign(output, lwe[self.input_dimension.get()]);
        }
    }

    /// Accumulates one validated LWE mask using scalar digits, without digit transforms.
    fn accumulate_single(&self, input: &[T], workspace: &mut FourierGlweKeySwitchingWorkspace<T>) {
        let glwe_len = self.output_size.glwe_size().fourier_glwe_len();
        for (&coefficient, entry) in input[..self.input_dimension.get()]
            .iter()
            .zip(self.data.chunks_exact(self.output_size.fourier_glev_len()))
        {
            let (adjusted, mut carry) = self.basis.init_value_carry(coefficient);
            for (decomposer, key_glwe) in self
                .basis
                .decomposer_iter()
                .zip(entry.chunks_exact(glwe_len))
            {
                let (digit, next_carry) = decomposer.decompose(adjusted, carry);
                carry = next_carry;
                // Zero skips all reads of this key block. Unlike NTT modular
                // products, Fourier scaling is cheap relative to large-key reads;
                // specializing ±1/±2 did not consistently improve benchmarks.
                if digit.is_zero() {
                    continue;
                }
                let scalar = digit.into_signed_f64();
                for (output, &key) in workspace.accumulator.as_mut().iter_mut().zip(key_glwe) {
                    *output += key * scalar;
                }
            }
        }
    }
}
