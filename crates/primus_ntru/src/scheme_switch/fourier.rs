//! Native-torus NLev-to-NGSW scheme switching under one NTRU secret.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_reduce::EncodeSigned;
use zeroize::Zeroizing;

use crate::{
    FourierNgswCiphertext, FourierNtruExternalProductWorkspace, FourierNtruGadgetEncryptWorkspace,
    FourierNtruSecretKey, NlevCiphertext, NlevParameters, NtruSecretKey,
};

/// Converts coefficient `NLev_f[m]` to Fourier `NGSW_f[m]` with unchanged scalars.
///
/// The stored key is `NGSW_f[f]`. For input phase `g_out,l*m+e_l` and
/// decomposition reconstruction `c_l+delta_l`, the output phase is
/// `g_out,l*f*m + f*e_l + f²*delta_l + sum_j digit_j*E_j`, plus FFT error.
/// Key and output bases are independent. Native wrapping arithmetic, Fourier
/// precision and multiplication of errors by f/f² require their own budget.
///
/// Publishing this secret-dependent evaluation key requires an appropriate
/// key-dependent-message/circular-security assumption; the phase equation
/// alone establishes neither security nor a useful parameter set.
#[derive(Clone)]
pub struct FourierNtruSchemeSwitchKey<T: TorusFftValue> {
    data: FourierNgswCiphertext<Vec<Complex64>>,
    poly_length: usize,
    key_basis: ApproxSignedBasis<T>,
    output_basis: ApproxSignedBasis<T>,
    output_len: usize,
}

impl<T: TorusFftValue> FourierNtruSchemeSwitchKey<T> {
    /// Generates `NGSW_f[f]` without explicitly forming the polynomial `f²`.
    ///
    /// # Correctness
    /// Both secrets represent the same polynomial. The transformed secret uses
    /// this exact FFT table instance. The caller must justify publishing this
    /// secret-dependent key and select a noise/precision budget as on [`Self`].
    ///
    /// # Panics
    /// Panics before sampling if the secret lengths, native basis domain, FFT
    /// or generation workspace disagree, or the coefficient output size overflows.
    #[must_use]
    pub fn generate<Table, R>(
        secret_key: &NtruSecretKey<T>,
        fourier_secret_key: &FourierNtruSecretKey,
        output_basis: &ApproxSignedBasis<T>,
        key_parameters: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruGadgetEncryptWorkspace<T>,
    ) -> Self
    where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        let n = key_parameters.poly_length().get();
        assert_eq!(
            secret_key.poly_length(),
            n,
            "scheme-switch secret length mismatch"
        );
        assert_eq!(
            output_basis.modulus(),
            None,
            "scheme-switch output basis must be native"
        );
        let output_len = n
            .checked_mul(output_basis.level_count().get())
            .expect("scheme-switch output length overflow");
        let mut encoded = Zeroizing::new(vec![T::ZERO; n]);
        NativeModulus::new().encode_signed_slice_to(secret_key.as_slice(), encoded.as_mut_slice());
        let mut data = FourierNgswCiphertext::zero(key_parameters.fourier_nlev_len());
        // Gadget encryption validates the remaining resources before sampling.
        // Each ciphertext receives g_j*f; the phase therefore receives g_j*f².
        fourier_secret_key.encrypt_ngsw_to(
            &Polynomial(encoded.as_slice()),
            &mut data,
            key_parameters,
            fft,
            rng,
            workspace,
        );
        Self {
            data,
            poly_length: n,
            key_basis: key_parameters.basis().clone(),
            output_basis: output_basis.clone(),
            output_len,
        }
    }

    /// Returns the unchanged coefficient polynomial length.
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the native basis that decomposes each input ciphertext polynomial.
    #[must_use]
    pub fn key_basis(&self) -> &ApproxSignedBasis<T> {
        &self.key_basis
    }

    /// Returns the basis shared by the input NLev and output NGSW.
    #[must_use]
    pub fn output_basis(&self) -> &ApproxSignedBasis<T> {
        &self.output_basis
    }

    /// Returns the raw Fourier evaluation-key rows in key-basis order.
    #[must_use]
    pub fn as_slice(&self) -> &[Complex64] {
        self.data.as_ref()
    }

    /// Overwrites Fourier NGSW from coefficient NLev, without online allocation.
    ///
    /// # Correctness
    /// Input levels use [`Self::output_basis`] scalars, order and the same f as
    /// this key. A matching row count does not establish that basis/secret.
    /// FFT values and scratch use the table instance used during generation.
    /// The caller budgets the f/f²-weighted errors on [`Self`] and FFT precision.
    /// Output stays at normalized Fourier torus scale without output rounding;
    /// it need not be bit-identical to a coefficient inverse/forward roundtrip.
    ///
    /// # Panics
    /// Panics before writes if input has other than N*L_output coefficients,
    /// output has other than N*L_output/2 complex values, or FFT/workspace
    /// lengths do not match this key.
    pub fn apply_to<Table, A, B>(
        &self,
        input: &NlevCiphertext<A>,
        output: &mut FourierNgswCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruExternalProductWorkspace<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.output_len,
            "scheme-switch input length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.output_len / 2,
            "scheme-switch output length mismatch"
        );
        assert_eq!(
            workspace.poly_length().get(),
            self.poly_length,
            "scheme-switch workspace length mismatch"
        );
        assert_eq!(
            fft.poly_length().get(),
            self.poly_length,
            "scheme-switch FFT length mismatch"
        );
        for (input, mut output) in input
            .iter_ntru(self.poly_length)
            .zip(output.iter_ntru_mut(self.poly_length / 2))
        {
            self.data.external_product_fourier_to(
                &input,
                &mut output,
                &self.key_basis,
                fft,
                workspace,
            );
        }
    }
}
