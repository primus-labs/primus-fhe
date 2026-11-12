use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::PowOf2Modulus;
use primus_ntru::{
    FourierNtruCiphertext, FourierNtruDecryptWorkspace, FourierNtruSecretKey, LweDimension,
    NtruCiphertext, NtruSecretKey, SecretKeyDistr,
};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use primus_tfhe::DecompositionBaseLog;
use primus_tfhe_ntru_fourier::{
    AccumulatorClient, BlindRotationMethod, DecompositionConfig, GadgetEncryptionConfig, LweConfig,
    ModulusConfig, PbsConfig, PbsMessageConfig, TfheContext,
};
use rand::rngs::StdRng;

pub(super) fn decomposition() -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: None,
    }
}

/// Keep rounding and transform error far below the test message spacing.
/// The default uses fixed-weight binary secrets. Block fixtures supply their own distribution.
pub(super) fn config<T: TorusFftValue>(
    method: BlindRotationMethod,
) -> PbsConfig<T, PowOf2Modulus<T>> {
    let modulus = ModulusConfig::Native;
    // The independent external LWE secret may have even weight.
    let secret = SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 2 };
    PbsConfig {
        external_lwe: LweConfig {
            dimension: LweDimension::new(8),
            cipher_modulus: ModulusConfig::Explicit(T::as_from(1u32 << 24)),
            secret_key_distr: secret,
            noise_standard_deviation: 1.0,
        },
        ring_modulus: modulus,
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        method,
        bsk_poly_length: PolyLength::new(128),
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: decomposition(),
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: decomposition(),
            noise_standard_deviation: 1.0,
        },
        messages: PbsMessageConfig::new(T::as_from(8)),
    }
}

/// Encrypted branch candidates and the coefficient buffers used to check selection.
pub(super) struct RingSelection<'a, T: TorusFftValue, Table: FftTable> {
    pub(super) client: AccumulatorClient<'a, T, Table, PowOf2Modulus<T>>,
    pub(super) messages: Vec<Vec<T>>,
    pub(super) candidates: Vec<NtruCiphertext<Vec<T>>>,
    pub(super) selected: NtruCiphertext<Vec<T>>,
    pub(super) decoded: Vec<T>,
}

impl<'a, T: TorusFftValue, Table: FftTable> RingSelection<'a, T, Table> {
    pub(super) fn new(
        context: &'a TfheContext<T, Table, PowOf2Modulus<T>>,
        secret: &NtruSecretKey<T>,
        messages: Vec<Vec<T>>,
        rng: &mut StdRng,
    ) -> Self {
        let mut client = context.accumulator_client(secret, T::as_from(8)).unwrap();
        let candidates = messages.iter().map(|m| client.encrypt(m, rng)).collect();
        Self {
            client,
            messages,
            candidates,
            selected: context.allocate_accumulator_ciphertext(),
            decoded: vec![T::ZERO; context.parameters().poly_length().get()],
        }
    }
}

/// Decrypts the Fourier rows and coefficient-domain probes from the same control.
pub(super) struct PhaseDecryptor<'a, T: TorusFftValue, Table: FftTable> {
    pub(super) fft: FftEngine<'a, Table>,
    secret: FourierNtruSecretKey,
    decrypt: FourierNtruDecryptWorkspace,
    probe: FourierNtruCiphertext<Vec<Complex64>>,
    phase: Polynomial<Vec<T>>,
}

impl<'a, T: TorusFftValue, Table: FftTable> PhaseDecryptor<'a, T, Table> {
    pub(super) fn new(
        context: &'a TfheContext<T, Table, PowOf2Modulus<T>>,
        secret: &NtruSecretKey<T>,
    ) -> Self {
        let poly_length = context.parameters().poly_length();
        let mut fft = context.new_fft_engine();
        let secret = FourierNtruSecretKey::try_from_coeff_secret_key(secret, &mut fft).unwrap();
        Self {
            fft,
            secret,
            decrypt: FourierNtruDecryptWorkspace::new(poly_length),
            probe: FourierNtruCiphertext::new(vec![Complex64::default(); poly_length.get() / 2]),
            phase: Polynomial::new(vec![T::ZERO; poly_length.get()]),
        }
    }

    pub(super) fn row_phase(&mut self, row: &FourierNtruCiphertext<&[Complex64]>) -> &[T] {
        self.secret
            .decrypt_phase_to(row, &mut self.phase, &mut self.fft, &mut self.decrypt);
        self.phase.as_ref()
    }

    pub(super) fn coefficient_phase(&mut self, probe: &NtruCiphertext<Vec<T>>) -> &[T] {
        probe.write_fourier_form(&mut self.probe, &mut self.fft);
        self.secret.decrypt_phase_to(
            &self.probe,
            &mut self.phase,
            &mut self.fft,
            &mut self.decrypt,
        );
        self.phase.as_ref()
    }
}

/// Exact schoolbook native phase of a stored coefficient row. This oracle
/// deliberately avoids FFT inversion so a rounded reconstruction cannot hide here.
pub(super) fn native_phase<T: TorusFftValue>(
    ciphertext: &[T],
    secret: &[T::SignedInteger],
) -> Vec<T> {
    let n = secret.len();
    let mut output = vec![T::ZERO; n];
    for (i, &coefficient) in ciphertext.iter().enumerate() {
        for (j, &secret) in secret.iter().enumerate() {
            let product = coefficient.wrapping_mul(T::cast_from_signed(secret));
            if i + j < n {
                output[i + j] = output[i + j].wrapping_add(product);
            } else {
                output[i + j - n] = output[i + j - n].wrapping_sub(product);
            }
        }
    }
    output
}
