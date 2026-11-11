//! NLev and NGSW encryption.

use super::{FourierNtruEncryptWorkspace, FourierNtruGadgetEncryptWorkspace, FourierNtruSecretKey};
use crate::{
    FourierNgswCiphertext, FourierNlevCiphertext, NlevCiphertext, NlevParameters,
    NtruEncryptionParameters,
};
use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::SignedInteger;
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;

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
        for (scalar, mut level) in params
            .basis()
            .scalar_iter()
            .zip(result.iter_ntru_mut(fft.fourier_length()))
        {
            self.encrypt_coefficients_to_workspace(
                ntru_params,
                rng,
                &mut workspace.ntru,
                |phase| {
                    Polynomial(phase).add_mul_scalar_assign(&message, scalar, modulus);
                },
            );
            fft.forward_as_torus(workspace.ntru.coeff.as_ref(), level.as_mut());
        }
    }

    /// Encrypts a constant ring element as NLev without plaintext scaling.
    /// Each level has phase `g_l * input + e_l`; input `1` initializes an
    /// encrypted accumulator through an NLev external product.
    /// Generates each row in the native ring before the FFT, reusing scratch.
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
        for (scalar, mut level) in params
            .basis()
            .scalar_iter()
            .zip(output.iter_ntru_mut(fft.fourier_length()))
        {
            self.encrypt_gadget_constant_to_workspace(
                input.wrapping_mul(scalar),
                true,
                params.encryption_parameters(),
                rng,
                &mut workspace.ntru,
            );
            fft.forward_as_torus(workspace.ntru.coeff.as_ref(), level.as_mut());
        }
    }

    /// Writes the exact coefficient rows for a gadget bit without transforming.
    ///
    /// With `lift`, the NLev phase is `g_l * bit + e_l`. Otherwise the NGSW
    /// phase is `f * g_l * bit + e_l`. Each row draws independent error.
    /// The caller selects the later Fourier representation if required.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes on incompatible native word width or
    /// key/parameter/output/workspace lengths.
    pub fn encrypt_gadget_bit_coeff_to<T, R>(
        &self,
        bit: bool,
        lift: bool,
        mut output: NlevCiphertext<&mut [T]>,
        params: &NlevParameters<T, NativeModulus<T>>,
        rng: &mut R,
        workspace: &mut FourierNtruGadgetEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        R: rand::Rng + rand::CryptoRng,
    {
        self.assert_native_domain(params.encryption_parameters());
        self.assert_encrypt_workspace(&workspace.ntru);
        assert_eq!(
            output.as_ref().len(),
            params.nlev_len(),
            "native gadget output length mismatch"
        );
        for (scalar, row) in params
            .basis()
            .scalar_iter()
            .zip(output.as_mut().chunks_exact_mut(self.poly_length()))
        {
            self.encrypt_gadget_constant_to_workspace(
                if bit { scalar } else { T::ZERO },
                lift,
                params.encryption_parameters(),
                rng,
                &mut workspace.ntru,
            );
            row.copy_from_slice(workspace.ntru.coeff.as_ref());
        }
    }

    // Lift rows inject the scaled message into the phase. NGSW rows add it
    // to the reduced encryption of zero, still in the native ring.
    fn encrypt_gadget_constant_to_workspace<T, R>(
        &self,
        scaled_message: T,
        lift: bool,
        params: &NtruEncryptionParameters<T, NativeModulus<T>>,
        rng: &mut R,
        workspace: &mut FourierNtruEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        R: rand::Rng + rand::CryptoRng,
    {
        self.encrypt_coefficients_to_workspace(params, rng, workspace, |coefficients| {
            if lift {
                coefficients[0] = coefficients[0].wrapping_add(scaled_message);
            }
        });
        if !lift {
            let constant = &mut workspace.coeff.as_mut()[0];
            *constant = constant.wrapping_add(scaled_message);
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

    /// Adds the scaled message to exact native coefficients before the FFT,
    /// giving NGSW phase `f * g_l * message + e_l` up to FFT rounding.
    /// The caller validates complete operands and the key/parameter/FFT domain
    /// and workspace.
    pub(crate) fn encrypt_ngsw_kernel_to<T, Table, R>(
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
            self.encrypt_coefficients_to_workspace(ntru_params, rng, &mut workspace.ntru, |_| {});
            workspace
                .ntru
                .coeff
                .add_mul_scalar_assign(&message, scalar, modulus);
            fft.forward_as_torus(workspace.ntru.coeff.as_ref(), level.as_mut());
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
        for (&value, block) in input.iter().zip(output.chunks_exact_mut(nlev_len)) {
            let constant = value.cast_to_unsigned();
            for (scalar, level) in params
                .basis()
                .scalar_iter()
                .zip(block.chunks_exact_mut(fft.fourier_length()))
            {
                self.encrypt_gadget_constant_to_workspace(
                    constant.wrapping_mul(scalar),
                    false,
                    params.encryption_parameters(),
                    rng,
                    &mut workspace.ntru,
                );
                fft.forward_as_torus(workspace.ntru.coeff.as_ref(), level);
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
        self.assert_encrypt_workspace(&workspace.ntru);
    }
}
