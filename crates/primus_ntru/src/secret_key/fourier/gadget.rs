//! NLev and NGSW encryption.

use super::{FourierNtruGadgetEncryptWorkspace, FourierNtruSecretKey};
use crate::{FourierNgswCiphertext, FourierNlevCiphertext, NlevParameters};
use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::SignedInteger;
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomial, Polynomial};

impl FourierNtruSecretKey {
    /// Generates a Fourier NLev encryption of an already encoded native-torus polynomial.
    pub fn encrypt_nlev_to<T, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut FourierNlevCiphertext<B>,
        params: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruGadgetEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        self.assert_gadget_domain(params, fft, workspace);
        assert_eq!(
            message.as_ref().len(),
            self.poly_length(),
            "gadget input length mismatch"
        );
        assert_eq!(
            result.as_ref().len(),
            params.fourier_nlev_len(),
            "gadget output length mismatch"
        );

        self.encrypt_nlev_kernel_to(
            message.as_view(),
            result.as_mut_view(),
            params,
            fft,
            rng,
            workspace,
        );
    }

    /// Adds each scaled message before multiplication by the inverse secret, giving
    /// NLev phase `g_l * message + e_l` up to FFT rounding. The caller validates
    /// complete operands, the FFT domain and polynomial scratch.
    pub(crate) fn encrypt_nlev_kernel_to<T, Table, R>(
        &self,
        message: Polynomial<&[T]>,
        mut result: FourierNlevCiphertext<&mut [Complex64]>,
        params: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruGadgetEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        let ntru_params = params.encryption_parameters();
        let modulus = ntru_params.cipher_modulus();
        for (scalar, level) in params
            .basis()
            .scalar_iter()
            .zip(result.iter_ntru_mut(fft.fourier_length()))
        {
            message.mul_scalar_to(scalar, &mut workspace.encoded, modulus);
            self.encrypt_encoded_to_unchecked(
                workspace.encoded.as_view(),
                level,
                ntru_params,
                fft,
                rng,
                &mut workspace.ntru,
            );
        }
    }

    /// Encrypts a constant ring element as NLev without plaintext scaling.
    /// Each level has phase `g_l * input + e_l`; input `1` initializes an
    /// encrypted accumulator through an NLev external product.
    /// Reuses output and scratch, zeroing the coefficient tail once per call.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes for incompatible key/parameter/table,
    /// output or workspace lengths.
    ///
    /// # Correctness
    ///
    /// The secret key must use the supplied FFT table instance.
    pub fn encrypt_nlev_constant_to<T, Table, R, B>(
        &self,
        input: T,
        output: &mut FourierNlevCiphertext<B>,
        params: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruGadgetEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = Complex64>,
    {
        self.assert_gadget_domain(params, fft, workspace);
        assert_eq!(
            output.as_ref().len(),
            params.fourier_nlev_len(),
            "NLev output length mismatch"
        );
        self.encrypt_nlev_constant_kernel_to(
            input,
            output.as_mut_view(),
            params,
            fft,
            rng,
            workspace,
        );
    }

    /// Encrypts a native-torus constant after the caller checks resources and output.
    /// Clears the coefficient scratch once, then changes only its constant term per level.
    fn encrypt_nlev_constant_kernel_to<T, Table, R>(
        &self,
        input: T,
        mut output: FourierNlevCiphertext<&mut [Complex64]>,
        params: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruGadgetEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        workspace.encoded.as_mut().fill(T::ZERO);
        for (scalar, level) in params
            .basis()
            .scalar_iter()
            .zip(output.iter_ntru_mut(fft.fourier_length()))
        {
            workspace.encoded.as_mut()[0] = input.wrapping_mul(scalar);
            self.encrypt_encoded_to_unchecked(
                workspace.encoded.as_view(),
                level,
                params.encryption_parameters(),
                fft,
                rng,
                &mut workspace.ntru,
            );
        }
    }

    /// Generates a Fourier NGSW encryption of an already encoded native-torus polynomial.
    pub fn encrypt_ngsw_to<T, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut FourierNgswCiphertext<B>,
        params: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruGadgetEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        self.assert_gadget_domain(params, fft, workspace);
        assert_eq!(
            message.as_ref().len(),
            self.poly_length(),
            "gadget input length mismatch"
        );
        assert_eq!(
            result.as_ref().len(),
            params.fourier_nlev_len(),
            "gadget output length mismatch"
        );

        self.encrypt_ngsw_kernel_to(
            message.as_view(),
            result.as_mut_view(),
            params,
            fft,
            rng,
            workspace,
        );
    }

    /// Adds the scaled message in Fourier form after encrypting zero, giving NGSW phase
    /// `f * g_l * message + e_l` up to FFT rounding. The caller validates
    /// complete operands, the FFT domain and polynomial scratch.
    fn encrypt_ngsw_kernel_to<T, Table, R>(
        &self,
        message: Polynomial<&[T]>,
        mut result: FourierNgswCiphertext<&mut [Complex64]>,
        params: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruGadgetEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        let ntru_params = params.encryption_parameters();
        let modulus = ntru_params.cipher_modulus();
        for (scalar, mut level) in params
            .basis()
            .scalar_iter()
            .zip(result.iter_ntru_mut(fft.fourier_length()))
        {
            message.mul_scalar_to(scalar, &mut workspace.encoded, modulus);
            fft.forward_as_torus(workspace.encoded.as_ref(), &mut workspace.transformed);
            self.encrypt_zeros_to_unchecked(
                level.as_mut_view(),
                ntru_params,
                fft,
                rng,
                &mut workspace.ntru,
            );
            FourierPolynomial(level.as_mut())
                .add_assign(&FourierPolynomial(workspace.transformed.as_slice()));
        }
    }

    /// Encrypts signed constants into contiguous Fourier NGSWs without plaintext scaling.
    ///
    /// Accepts coefficient-secret slices directly. Output uses
    /// `[input][level][Fourier coefficient]` layout and must contain exactly
    /// `input.len() * params.fourier_nlev_len()` values. Resources are checked
    /// once per batch. Empty input/output consumes no randomness.
    /// Reuses output and the supplied workspace without allocating.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes on incompatible key/parameters/FFT,
    /// output or workspace lengths, or a batch length overflow.
    /// A panicking RNG or FFT can leave partial output and modified scratch.
    ///
    /// # Correctness
    ///
    /// Use the FFT table instance with which this secret key was constructed.
    pub fn encrypt_ngsw_signed_constant_batch_to<T, Table, R>(
        &self,
        input: &[T::SignedInteger],
        output: &mut [Complex64],
        params: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruGadgetEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        self.assert_gadget_domain(params, fft, workspace);
        let nlev_len = params.fourier_nlev_len();
        let expected = input
            .len()
            .checked_mul(nlev_len)
            .expect("Fourier NGSW batch length overflow");
        assert_eq!(
            output.len(),
            expected,
            "Fourier NGSW batch output length mismatch"
        );
        workspace.encoded.as_mut().fill(T::ZERO);
        for (&value, block) in input.iter().zip(output.chunks_exact_mut(nlev_len)) {
            let constant = value.cast_to_unsigned();
            for (scalar, level) in params
                .basis()
                .scalar_iter()
                .zip(block.chunks_exact_mut(fft.fourier_length()))
            {
                workspace.encoded.as_mut()[0] = constant.wrapping_mul(scalar);
                // Native-ring multiplication precedes torus lifting; preserve
                // the same per-level FFT rounding as polynomial encryption.
                fft.forward_as_torus(workspace.encoded.as_ref(), &mut workspace.transformed);
                let mut level = crate::FourierNtruCiphertext::new(level);
                self.encrypt_zeros_to_unchecked(
                    level.as_mut_view(),
                    params.encryption_parameters(),
                    fft,
                    rng,
                    &mut workspace.ntru,
                );
                FourierPolynomial(level.as_mut())
                    .add_assign(&FourierPolynomial(workspace.transformed.as_slice()));
            }
        }
    }

    /// Checks shared generation resources before standalone or batched sampling.
    pub(crate) fn assert_gadget_domain<T, Table>(
        &self,
        params: &NlevParameters<T, NativeModulus<T>>,
        fft: &FftEngine<'_, Table>,
        workspace: &FourierNtruGadgetEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
    {
        self.assert_domain(params.encryption_parameters(), fft);
        assert_eq!(workspace.encoded.as_ref().len(), self.poly_length());
        assert_eq!(workspace.transformed.len(), fft.fourier_length());
    }
}
