//! Public Fourier material must be the transform of an exact native ciphertext.
#![cfg(any(feature = "rustfft", feature = "tfhe-fft"))]

use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_encoding::PlaintextEmbedding;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_glwe::{
    FourierGgswCiphertext, FourierGlevCiphertext, FourierGlweCiphertext, FourierGlweEncryptor,
    FourierGlweEncryptorError, GlevParameters, GlweCiphertext, GlweDimension, GlweParameters,
    GlweSecretKey, SecretKeyDistr,
};
use primus_integer::{AsInto, SignedInteger};
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomialIterMut, Polynomial, PolynomialIter};
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};

/// Independently gather each output coefficient. Sampling uses the production
/// distributions in their prescribed order; multiplication is native schoolbook.
fn reference_row<T: TorusFftValue>(
    secret: &GlweSecretKey<T>,
    params: &GlweParameters<T, NativeModulus<T>>,
    message: &[T],
    rng: &mut StdRng,
) -> Vec<T> {
    let n = secret.poly_length().get();
    let mut row = vec![T::ZERO; secret.glwe_size().glwe_len()];
    let (mask, body) = row.split_at_mut(secret.glwe_size().mask_len());
    primus_distr::sample_gaussian_values_to(
        body,
        params.encryption_parameters().noise_distribution(),
        rng,
    );
    for (b, &m) in body.iter_mut().zip(message) {
        *b = b.wrapping_add(m);
    }
    let uniform = params
        .encryption_parameters()
        .cipher_modulus_uniform_distr();
    for (a, s) in mask.chunks_exact_mut(n).zip(secret.iter()) {
        primus_distr::sample_uniform_values_to(a, &uniform, rng);
        for (degree, b) in body.iter_mut().enumerate() {
            for (j, &s) in s.iter().enumerate() {
                let i = (degree + n - j) & (n - 1);
                let product = a[i].wrapping_mul(s.cast_to_unsigned());
                *b = if i + j < n {
                    b.wrapping_add(product)
                } else {
                    b.wrapping_sub(product)
                };
            }
        }
    }
    row
}

/// Compare public spectra directly; inverse-and-wrap could hide the old defect.
fn assert_spectrum<T: TorusFftValue, Table: FftTable>(
    coefficients: &[T],
    actual: &[Complex64],
    fft: &mut FftEngine<'_, Table>,
) {
    let n = fft.poly_length().get();
    let mut expected = vec![Complex64::default(); coefficients.len() / 2];
    for (input, mut output) in PolynomialIter::new(coefficients, n)
        .zip(FourierPolynomialIterMut::new(&mut expected, n / 2))
    {
        fft.forward_as_torus(input.as_ref(), output.as_mut());
    }
    assert_eq!(actual, expected);
}

fn check<T: TorusFftValue, Table: FftTable>() {
    let n = PolyLength::new(32);
    let distr = SecretKeyDistr::gaussian(1.0);
    let params = GlweParameters::new(
        GlweDimension::new(2),
        n,
        16u64.as_into(),
        NativeModulus::new(),
        distr,
        0.7,
    );
    let coefficients = (0..params.size().mask_len())
        .map(|i| {
            let s: T::SignedInteger = [-2i64, -1, 0, 1, 2][i % 5].as_into();
            s
        })
        .collect();
    let secret = GlweSecretKey::<T>::new(coefficients, params.size(), distr);
    let mut encryptor =
        FourierGlweEncryptor::try_new(&secret, params.encryption_parameters()).unwrap();
    let table = Table::new(n);
    let mut fft = FftEngine::new(&table);
    let mut output = FourierGlweCiphertext::<Vec<Complex64>>::zero(params.fourier_glwe_len());
    let zero = vec![T::ZERO; n.get()];
    let seed = || StdRng::seed_from_u64(93);
    let mut expected_rng = seed();
    let expected = reference_row(&secret, &params, &zero, &mut expected_rng);
    let mut rng = seed();
    encryptor.encrypt_zeros_to(
        &mut output,
        params.encryption_parameters(),
        &mut fft,
        &mut rng,
    );
    assert_spectrum(&expected, output.as_ref(), &mut fft);
    assert_eq!(rng.next_u64(), expected_rng.next_u64());

    let message: Vec<T> = (0..n.get())
        .map(|i| (((i * 7) & 15) as u64).as_into())
        .collect();
    for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
        let mut encoded = zero.clone();
        params
            .plaintext_codec()
            .encode_slice_to(&message, &mut encoded, embedding);
        let mut expected_rng = seed();
        let expected = reference_row(&secret, &params, &encoded, &mut expected_rng);
        let next = expected_rng.next_u64();
        let mut rng = seed();
        encryptor.encrypt_message_to(
            &Polynomial::new(message.as_slice()),
            &mut output,
            &params,
            embedding,
            &mut fft,
            &mut rng,
        );
        assert_spectrum(&expected, output.as_ref(), &mut fft);
        assert_eq!(rng.next_u64(), next);
        let mut rng = seed();
        encryptor.encrypt_encoded_to(
            &Polynomial::new(encoded.as_slice()),
            &mut output,
            params.encryption_parameters(),
            &mut fft,
            &mut rng,
        );
        assert_spectrum(&expected, output.as_ref(), &mut fft);
        assert_eq!(rng.next_u64(), next);
        let mut rng = seed();
        let mut native = GlweCiphertext::<Vec<T>>::zero(params.glwe_len());
        encryptor.encrypt_message_coeff_to(
            &Polynomial::new(message.as_slice()),
            &mut native,
            &params,
            embedding,
            &mut rng,
        );
        assert_eq!(native.as_ref(), expected);
        assert_eq!(rng.next_u64(), next);
    }

    let gadget = GlevParameters::with_glwe_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(2)),
        },
    );
    // Full native messages force wrapping in every component, including the
    // nonconstant tail. This also detects diagonal-before-body cancellation.
    let raw: Vec<_> = (0..n.get())
        .map(|i| T::MAX.wrapping_mul(((i * 7919 + 137) as u64).as_into()))
        .collect();
    let mut expected_rng = seed();
    let mut expected_glev = Vec::new();
    for scalar in gadget.basis().scalar_iter() {
        let encoded: Vec<_> = raw.iter().map(|&m| m.wrapping_mul(scalar)).collect();
        expected_glev.extend(reference_row(&secret, &params, &encoded, &mut expected_rng));
    }
    let mut glev = FourierGlevCiphertext::<Vec<Complex64>>::zero(gadget.fourier_glev_len());
    let mut rng = seed();
    encryptor.encrypt_glev_to(
        &Polynomial::new(raw.as_slice()),
        &mut glev,
        &gadget,
        &mut fft,
        &mut rng,
    );
    assert_spectrum(&expected_glev, glev.as_ref(), &mut fft);
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
    let mut expected_rng = seed();
    let mut expected_ggsw = Vec::new();
    for diagonal in 0..=secret.dimension().get() {
        for scalar in gadget.basis().scalar_iter() {
            let mut row = reference_row(&secret, &params, &zero, &mut expected_rng);
            for (out, &m) in row[diagonal * n.get()..(diagonal + 1) * n.get()]
                .iter_mut()
                .zip(&raw)
            {
                *out = out.wrapping_add(m.wrapping_mul(scalar));
            }
            expected_ggsw.extend(row);
        }
    }
    let mut ggsw = FourierGgswCiphertext::<Vec<Complex64>>::zero(gadget.fourier_ggsw_len());
    let mut rng = seed();
    encryptor.encrypt_ggsw_to(
        &Polynomial::new(raw.as_slice()),
        &mut ggsw,
        &gadget,
        &mut fft,
        &mut rng,
    );
    assert_spectrum(&expected_ggsw, ggsw.as_ref(), &mut fft);
    assert_eq!(rng.next_u64(), expected_rng.next_u64());

    let constants = [T::ZERO, T::ONE, T::ONE, T::MAX];
    let mut expected_rng = seed();
    let mut expected_batch = Vec::new();
    for constant in constants {
        for diagonal in 0..=secret.dimension().get() {
            for scalar in gadget.basis().scalar_iter() {
                let mut row = reference_row(&secret, &params, &zero, &mut expected_rng);
                row[diagonal * n.get()] =
                    row[diagonal * n.get()].wrapping_add(constant.wrapping_mul(scalar));
                expected_batch.extend(row);
            }
        }
    }
    let mut actual = vec![T::ZERO; expected_batch.len()];
    let mut rng = seed();
    encryptor.encrypt_ggsw_constant_batch_coeff_to(&constants, &mut actual, &gadget, &mut rng);
    assert_eq!(actual, expected_batch);
    let next = expected_rng.next_u64();
    assert_eq!(rng.next_u64(), next);
    let mut actual = vec![Complex64::default(); expected_batch.len() / 2];
    let mut rng = seed();
    encryptor.encrypt_ggsw_constant_batch_to(&constants, &mut actual, &gadget, &mut fft, &mut rng);
    assert_spectrum(&expected_batch, &actual, &mut fft);
    assert_eq!(rng.next_u64(), next);
}

#[test]
fn native_rows_and_public_spectra_match_the_same_coin_oracle() {
    #[cfg(feature = "rustfft")]
    {
        check::<u16, primus_fft::RustFftTable>();
        check::<u32, primus_fft::RustFftTable>();
        check::<u64, primus_fft::RustFftTable>();
    }
    #[cfg(feature = "tfhe-fft")]
    {
        check::<u16, primus_fft::TfheFftTable>();
        check::<u32, primus_fft::TfheFftTable>();
        check::<u64, primus_fft::TfheFftTable>();
    }
}

#[test]
fn preparation_distinguishes_declared_support_from_unrestricted_imports() {
    let params = GlweParameters::new(
        GlweDimension::new(1),
        PolyLength::new(32),
        16u64,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let key = GlweSecretKey::new(vec![2; 32], params.size(), SecretKeyDistr::UniformBinary);
    assert!(matches!(
        FourierGlweEncryptor::try_new(&key, params.encryption_parameters()),
        Err(FourierGlweEncryptorError::SecretMagnitudeTooLarge)
    ));
    let _unrestricted = FourierGlweEncryptor::from_coeff_secret_key(&key);
    let key = GlweSecretKey::new(vec![0; 32], params.size(), SecretKeyDistr::UniformTernary);
    assert!(matches!(
        FourierGlweEncryptor::try_new(&key, params.encryption_parameters()),
        Err(FourierGlweEncryptorError::SecretDistributionMismatch)
    ));
}
