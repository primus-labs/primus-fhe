//! Encoding entry points, NTRU key acceptance and validation before mutation.
//! Arithmetic kernels and fused-lift phase identities have separate oracles.

use primus_distr::sample_gaussian_values_to;
use primus_encoding::{PlaintextEmbedding, phase_error_magnitude_slice_to};
use primus_fft::{FftEngine, FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNtruDecryptWorkspace, FourierNtruEncryptWorkspace, FourierNtruSecretKey, NtruError,
    NtruParameters, NtruSecretKey, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};

// Small functional ring; both word widths retain their original moduli and noise.
const POLY_LENGTH: usize = 64;
const PLAIN_MODULUS: usize = 16;

// Include both sides of the centered encoding boundary.
fn messages<T: FheUint>() -> Vec<T> {
    (0..POLY_LENGTH)
        .map(|index| T::try_from(index % PLAIN_MODULUS).unwrap())
        .collect()
}

// Replay noise independently and overwrite one ciphertext through all encodings.
fn assert_ntt_roundtrip<T>(cipher_modulus: T)
where
    T: FheUint,
{
    let modulus = BarrettModulus::new(cipher_modulus);
    let ntt = UintNttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let params = NtruParameters::new(
        PolyLength::new(POLY_LENGTH),
        T::try_from(PLAIN_MODULUS).unwrap(),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(42);
    let secret_key =
        NttNtruSecretKey::generate(params.encryption_parameters(), &ntt, &mut rng).unwrap();
    assert_eq!(secret_key.cipher_modulus(), cipher_modulus);
    let messages = messages::<T>();
    let message = Polynomial::new(messages.as_slice());

    let mut cipher = primus_ntru::NttNtruCiphertext::new(vec![T::ONE; POLY_LENGTH]);
    let mut raw = cipher.clone();
    let mut encoded = Polynomial::new(vec![T::ZERO; POLY_LENGTH]);
    let mut phase = Polynomial::new(vec![T::ZERO; POLY_LENGTH]);
    let mut noise = vec![T::ZERO; POLY_LENGTH];
    let mut expected_noise = vec![T::ZERO; POLY_LENGTH];
    for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
        let mut message_rng = StdRng::seed_from_u64(43);
        let mut raw_rng = StdRng::seed_from_u64(43);
        let mut noise_rng = StdRng::seed_from_u64(43);
        params
            .plaintext_codec()
            .encode_slice_to(&messages, encoded.as_mut(), embedding);
        secret_key.encrypt_message_to(
            &message,
            &mut cipher,
            &params,
            embedding,
            &ntt,
            &mut message_rng,
        );
        secret_key.encrypt_encoded_to(
            &encoded,
            &mut raw,
            params.encryption_parameters(),
            &ntt,
            &mut raw_rng,
        );
        assert_eq!(cipher.as_ref(), raw.as_ref());
        assert_eq!(message_rng.next_u64(), raw_rng.next_u64());
        assert_eq!(
            secret_key.decrypt_message(&cipher, &params, &ntt).as_ref(),
            messages
        );

        // Reference the original message and actual embedding, not a re-encoded
        // decoder output. The exact NTT phase error must match sampled noise.
        secret_key.decrypt_phase_to(&cipher, &mut phase, modulus, &ntt);
        phase_error_magnitude_slice_to(phase.as_ref(), encoded.as_ref(), &mut noise, modulus);
        sample_gaussian_values_to(
            &mut expected_noise,
            params.noise_distribution(),
            &mut noise_rng,
        );
        for value in &mut expected_noise {
            *value = (*value).min(cipher_modulus - *value);
        }
        assert_eq!(noise, expected_noise);
    }

    secret_key.encrypt_zeros_to(&mut cipher, params.encryption_parameters(), &ntt, &mut rng);
    assert_eq!(
        secret_key.decrypt_message(&cipher, &params, &ntt).as_ref(),
        vec![T::ZERO; POLY_LENGTH]
    );
}

#[test]
fn ntt_secret_key_encodings_reuse_ciphertext_storage() {
    assert_ntt_roundtrip(132_120_577u32);
    assert_ntt_roundtrip(1_125_899_906_826_241u64);
}

// Native torus encryption reuses both ciphertext and FFT workspaces.
fn assert_fourier_roundtrip<T, Table>(table: &Table)
where
    T: FheUint + TorusFftValue,
    Table: FftTable,
{
    let mut fft = FftEngine::new(table);
    let params = NtruParameters::new(
        PolyLength::new(POLY_LENGTH),
        T::try_from(PLAIN_MODULUS).unwrap(),
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(42);
    let secret_key =
        FourierNtruSecretKey::generate(params.encryption_parameters(), &mut fft, &mut rng).unwrap();
    let mut encrypt_workspace = FourierNtruEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    let mut decrypt_workspace = FourierNtruDecryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    let messages = messages::<T>();
    let message = Polynomial::new(messages.as_slice());

    let mut cipher = primus_ntru::FourierNtruCiphertext::<Vec<_>>::zero(table.fourier_length());
    let mut raw = cipher.clone();
    let mut encoded = Polynomial::new(vec![T::ZERO; POLY_LENGTH]);
    for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
        let mut message_rng = StdRng::seed_from_u64(43);
        let mut raw_rng = StdRng::seed_from_u64(43);
        params
            .plaintext_codec()
            .encode_slice_to(&messages, encoded.as_mut(), embedding);
        // Reuse dirty output and scratch for the second embedding. Both entry
        // points must produce identical Fourier values and consume the same RNG.
        secret_key.encrypt_message_to(
            &message,
            &mut cipher,
            &params,
            embedding,
            &mut fft,
            &mut message_rng,
            &mut encrypt_workspace,
        );
        secret_key.encrypt_encoded_to(
            &encoded,
            &mut raw,
            params.encryption_parameters(),
            &mut fft,
            &mut raw_rng,
            &mut encrypt_workspace,
        );
        assert_eq!(cipher.as_ref(), raw.as_ref());
        assert_eq!(message_rng.next_u64(), raw_rng.next_u64());
        assert_eq!(
            secret_key
                .decrypt_message(&cipher, &params, &mut fft, &mut decrypt_workspace)
                .as_ref(),
            messages
        );
    }

    secret_key.encrypt_zeros_to(
        &mut cipher,
        params.encryption_parameters(),
        &mut fft,
        &mut rng,
        &mut encrypt_workspace,
    );
    assert_eq!(
        secret_key
            .decrypt_message(&cipher, &params, &mut fft, &mut decrypt_workspace,)
            .as_ref(),
        vec![T::ZERO; POLY_LENGTH]
    );
}

#[test]
fn fourier_secret_key_encodings_reuse_ciphertext_storage() {
    let poly_length = PolyLength::new(POLY_LENGTH);
    let table = RustFftTable::new(poly_length);
    assert_fourier_roundtrip::<u32, _>(&table);
    assert_fourier_roundtrip::<u64, _>(&table);
    #[cfg(feature = "tfhe-fft")]
    {
        let table = primus_fft::TfheFftTable::new(poly_length);
        assert_fourier_roundtrip::<u32, _>(&table);
        assert_fourier_roundtrip::<u64, _>(&table);
    }
}

#[test]
fn transform_backends_reject_the_zero_key() {
    let zero_key = NtruSecretKey::<u32>::new(
        vec![i32::default(); POLY_LENGTH],
        SecretKeyDistr::SparseTernary,
    );

    let modulus = BarrettModulus::new(132_120_577u32);
    let ntt = UintNttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    assert!(matches!(
        NttNtruSecretKey::try_from_coeff_secret_key(&zero_key, modulus, &ntt),
        Err(NtruError::NonInvertibleSecretKey)
    ));

    let table = RustFftTable::new(PolyLength::new(POLY_LENGTH));
    let mut fft = FftEngine::new(&table);
    assert!(matches!(
        FourierNtruSecretKey::try_from_coeff_secret_key(&zero_key, &mut fft),
        Err(NtruError::NonInvertibleSecretKey)
    ));
}

fn assert_generated_fourier_pairs<Table: FftTable>(table: &Table) {
    let mut fft = FftEngine::new(table);
    let mut rng = StdRng::seed_from_u64(0xB701);
    let message = Polynomial::new((0..POLY_LENGTH as u64).map(|i| i % 16).collect::<Vec<_>>());
    let mut encrypt = FourierNtruEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    let mut decrypt = FourierNtruDecryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    for distribution in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::gaussian(3.2),
        SecretKeyDistr::Ternary {
            negative_one_probability: 0.125,
            one_probability: 0.375,
        },
        SecretKeyDistr::FixedHammingWeightTernary { hamming_weight: 7 },
        SecretKeyDistr::FixedCompositionTernary {
            negative_one_weight: 3,
            one_weight: 4,
        },
    ] {
        let params = NtruParameters::new(
            PolyLength::new(POLY_LENGTH),
            16,
            NativeModulus::new(),
            distribution,
            0.7,
        );
        let (coeff, key) =
            FourierNtruSecretKey::generate_pair(params.encryption_parameters(), &mut fft, &mut rng)
                .unwrap();
        assert_eq!(coeff.distr(), distribution);
        assert_eq!(coeff.as_slice().iter().sum::<i64>().rem_euclid(2), 1);
        // Reimport the returned signed key to check the pair's identity, rather
        // than decrypting with the same opaque key that encrypted the message.
        let check_key = FourierNtruSecretKey::try_from_coeff_secret_key(&coeff, &mut fft).unwrap();
        let cipher = key.encrypt_message(
            &message,
            &params,
            PlaintextEmbedding::Unsigned,
            &mut fft,
            &mut rng,
            &mut encrypt,
        );
        assert_eq!(
            check_key
                .decrypt_message(&cipher, &params, &mut fft, &mut decrypt)
                .as_ref(),
            message.as_ref(),
        );
    }
}

#[test]
fn generated_fourier_pairs_preserve_key_identity() {
    assert_generated_fourier_pairs(&RustFftTable::new(PolyLength::new(POLY_LENGTH)));
    assert_generated_fourier_pairs(&TfheFftTable::new(PolyLength::new(POLY_LENGTH)));
}

#[test]
fn native_fixed_even_weights_fail_without_sampling() {
    let table = RustFftTable::new(PolyLength::new(POLY_LENGTH));
    let mut fft = FftEngine::new(&table);
    for distribution in [
        SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 2 },
        SecretKeyDistr::FixedHammingWeightTernary { hamming_weight: 2 },
        SecretKeyDistr::FixedCompositionTernary {
            negative_one_weight: 1,
            one_weight: 1,
        },
        SecretKeyDistr::FixedCompositionTernary {
            negative_one_weight: 0,
            one_weight: 0,
        },
    ] {
        let params = NtruParameters::new(
            PolyLength::new(POLY_LENGTH),
            16u64,
            NativeModulus::new(),
            distribution,
            0.7,
        );
        let mut rng = StdRng::seed_from_u64(0xB701);
        let mut untouched = StdRng::seed_from_u64(0xB701);
        let result =
            FourierNtruSecretKey::generate_pair(params.encryption_parameters(), &mut fft, &mut rng);
        assert!(matches!(result, Err(NtruError::NonInvertibleSecretKey)));
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }
}

fn assert_unstable_inverse<Table: FftTable>(table: &Table, coeff: &NtruSecretKey<u64>) {
    assert!(matches!(
        FourierNtruSecretKey::try_from_coeff_secret_key(coeff, &mut FftEngine::new(table)),
        Err(NtruError::UnstableFourierInverse),
    ));
}

#[test]
fn native_invertibility_does_not_imply_fourier_stability() {
    const N: usize = 32;
    // f = (1-X+X^2)^8 has f(1)=1, hence is a native-ring unit. At the
    // negacyclic root exp(11*pi*i/32), |f| is about 1e-10. This imported
    // integer key isolates the numerical gate; it is not a ternary sample.
    let mut coefficients = vec![0i64; N];
    coefficients[0] = 1;
    for _ in 0..8 {
        let mut product = vec![0; N];
        for i in 0..N - 2 {
            product[i] += coefficients[i];
            product[i + 1] -= coefficients[i];
            product[i + 2] += coefficients[i];
        }
        coefficients = product;
    }
    assert_eq!(coefficients.iter().sum::<i64>(), 1);
    let coeff = NtruSecretKey::<u64>::new(coefficients, SecretKeyDistr::gaussian(3.2));
    assert_unstable_inverse(&RustFftTable::new(PolyLength::new(N)), &coeff);
    assert_unstable_inverse(&TfheFftTable::new(PolyLength::new(N)), &coeff);
}

#[test]
fn parameters_require_secret_support_below_explicit_modulus() {
    // The support endpoints 12 * sigma are exact integers here. Test both
    // Gaussian backends at the strict q boundary, independently of sampling.
    for (sigma, maximum_magnitude) in [(3.0, 36u32), (30.0, 360)] {
        let distribution = SecretKeyDistr::gaussian(sigma);
        for q in [maximum_magnitude - 1, maximum_magnitude] {
            assert_eq!(
                NtruParameters::try_new(
                    PolyLength::new(POLY_LENGTH),
                    2,
                    BarrettModulus::new(q),
                    distribution,
                    0.7
                )
                .err(),
                Some(primus_ntru::NtruParameterError::SecretKey(
                    primus_distr::SecretKeySamplerError::ModulusTooSmall {
                        maximum_magnitude: u128::from(maximum_magnitude),
                        modulus_minus_one: u128::from(q - 1),
                    },
                ))
            );
            assert!(
                std::panic::catch_unwind(|| NtruParameters::new(
                    PolyLength::new(POLY_LENGTH),
                    2,
                    BarrettModulus::new(q),
                    distribution,
                    0.7,
                ))
                .is_err()
            );
        }
        assert!(
            NtruParameters::try_new(
                PolyLength::new(POLY_LENGTH),
                2,
                BarrettModulus::new(maximum_magnitude + 1),
                distribution,
                0.7,
            )
            .is_ok()
        );
        assert!(
            NtruParameters::try_new(
                PolyLength::new(POLY_LENGTH),
                2,
                NativeModulus::<u32>::new(),
                distribution,
                0.7,
            )
            .is_ok()
        );
    }
}

#[test]
fn fallible_parameters_check_codec_and_samplers() {
    use primus_ntru::NtruParameterError as Error;
    let make = |n, t, distr, noise| {
        NtruParameters::try_new(
            PolyLength::new(n),
            t,
            NativeModulus::<u32>::new(),
            distr,
            noise,
        )
    };
    assert!(matches!(
        make(32, 1, SecretKeyDistr::UniformBinary, 0.7),
        Err(Error::Encoding(_))
    ));
    assert!(matches!(
        make(32, 4, SecretKeyDistr::UniformBinary, f64::INFINITY),
        Err(Error::Noise(_))
    ));
    assert!(matches!(
        make(
            32,
            4,
            SecretKeyDistr::FixedCompositionTernary {
                negative_one_weight: 16,
                one_weight: 17
            },
            0.7
        ),
        Err(Error::SecretKey(_))
    ));
    assert!(matches!(
        NtruParameters::try_new(
            PolyLength::new(32),
            12,
            BarrettModulus::new(17u32),
            SecretKeyDistr::UniformBinary,
            0.7
        ),
        Err(Error::Encoding(
            primus_encoding::CodecError::InsufficientScaleRecovery
        ))
    ));
}

#[test]
fn parameter_parts_bind_codec_and_basis_to_shared_sampling_state() {
    use primus_decompose::{
        DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount,
        primitive::ApproxSignedBasis,
    };
    use primus_encoding::ScaledCodec;
    use primus_ntru::{
        NlevParameterError, NlevParameters, NtruEncryptionParameters, NtruParameterError,
    };
    use std::sync::Arc;

    let modulus = BarrettModulus::new(257u32);
    let inner = Arc::new(NtruEncryptionParameters::new(
        PolyLength::new(32),
        modulus,
        SecretKeyDistr::gaussian(3.2),
        0.7,
    ));
    let basis = |q| ApproxSignedBasis::new(q, DecompositionBaseLog::new(3), None);

    // Native and other explicit bases must both be rejected before binding.
    for foreign_q in [None, Some(769)] {
        assert_eq!(
            NlevParameters::try_from_parts(Arc::clone(&inner), basis(foreign_q)).err(),
            Some(NlevParameterError::BasisModulusMismatch)
        );
    }
    assert_eq!(
        NtruParameters::try_from_parts(
            Arc::clone(&inner),
            ScaledCodec::new(4, BarrettModulus::new(769))
        )
        .err(),
        Some(NtruParameterError::CodecModulusMismatch)
    );

    let gadget = NlevParameters::try_from_parts(Arc::clone(&inner), basis(Some(257))).unwrap();
    let ordinary = NtruParameters::try_from_parts(inner, ScaledCodec::new(4, modulus)).unwrap();
    for level_count in [None, Some(DecompositionLevelCount::new(1))] {
        let decomposition = DecompositionConfig {
            log_basis: DecompositionBaseLog::new(4),
            level_count,
        };
        let derived = NlevParameters::try_with_ntru_params(&ordinary, decomposition).unwrap();
        // q=257 has nine value bits: two 4-bit levels, or one retained level.
        assert_eq!(
            derived.level_count().get(),
            level_count.map_or(2, DecompositionLevelCount::get)
        );
        assert_eq!(derived.basis().modulus(), Some(257));
        for parameters in [&gadget, &derived, &gadget.clone()] {
            assert!(std::ptr::eq(
                ordinary.encryption_parameters(),
                parameters.encryption_parameters()
            ));
            assert_eq!(parameters.nlev_len(), 32 * parameters.level_count().get());
        }
    }
    assert!(matches!(
        NlevParameters::try_with_ntru_params(
            &ordinary,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(2)),
            },
        ),
        Err(NlevParameterError::InvalidBasis(_))
    ));
    assert!(std::ptr::eq(
        ordinary.encryption_parameters(),
        ordinary.clone().encryption_parameters()
    ));
}

#[test]
fn ordinary_operations_validate_before_sampling_or_writing() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let mut rng = StdRng::seed_from_u64(73);
    let modulus = BarrettModulus::new(132_120_577u32);
    let ntt = UintNttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let params = NtruParameters::new(
        PolyLength::new(POLY_LENGTH),
        16,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let short_params = NtruParameters::new(
        PolyLength::new(POLY_LENGTH / 2),
        16,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let key = NttNtruSecretKey::generate(params.encryption_parameters(), &ntt, &mut rng).unwrap();
    let input = key.encrypt_zeros(params.encryption_parameters(), &ntt, &mut rng);
    let mut output = Polynomial::new(vec![7; POLY_LENGTH]);
    assert!(
        catch_unwind(AssertUnwindSafe(|| key.decrypt_message_to(
            &input,
            &mut output,
            &short_params,
            &ntt
        )))
        .is_err()
    );
    assert!(output.iter().all(|&value| value == 7));
    let mut wrong_output = primus_ntru::NttNtruCiphertext::new(vec![7; POLY_LENGTH / 2]);
    let mut rng = StdRng::seed_from_u64(91);
    let mut expected_rng = StdRng::seed_from_u64(91);
    assert!(
        catch_unwind(AssertUnwindSafe(|| key.encrypt_zeros_to(
            &mut wrong_output,
            params.encryption_parameters(),
            &ntt,
            &mut rng
        )))
        .is_err()
    );
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
    assert!(wrong_output.as_ref().iter().all(|&value| value == 7));

    // f = 1 and its inverse transform to all ones at either modulus. Only
    // construction metadata can distinguish these domains; the values cannot.
    let foreign_modulus = BarrettModulus::new(257u32);
    let foreign_table = UintNttTable::new(PolyLength::new(POLY_LENGTH), foreign_modulus).unwrap();
    let mut coefficients = vec![0i32; POLY_LENGTH];
    coefficients[0] = 1;
    let foreign_key = NttNtruSecretKey::try_from_coeff_secret_key(
        &NtruSecretKey::new(coefficients, SecretKeyDistr::UniformBinary),
        foreign_modulus,
        &foreign_table,
    )
    .unwrap();
    assert_eq!(foreign_key.cipher_modulus(), 257);
    let mut cipher = primus_ntru::NttNtruCiphertext::new(vec![7; POLY_LENGTH]);
    let mut rng = StdRng::seed_from_u64(93);
    let mut expected_rng = StdRng::seed_from_u64(93);
    assert!(
        catch_unwind(AssertUnwindSafe(|| foreign_key.encrypt_zeros_to(
            &mut cipher,
            params.encryption_parameters(),
            &ntt,
            &mut rng
        )))
        .is_err()
    );
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
    assert!(cipher.as_ref().iter().all(|&value| value == 7));
    assert!(
        catch_unwind(AssertUnwindSafe(|| foreign_key.decrypt_phase_to(
            &input,
            &mut output,
            modulus,
            &ntt
        )))
        .is_err()
    );
    assert!(output.iter().all(|&value| value == 7));

    let table = RustFftTable::new(PolyLength::new(POLY_LENGTH));
    let mut fft = FftEngine::new(&table);
    let params = NtruParameters::new(
        PolyLength::new(POLY_LENGTH),
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let short_params = NtruParameters::new(
        PolyLength::new(POLY_LENGTH / 2),
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let key =
        FourierNtruSecretKey::generate(params.encryption_parameters(), &mut fft, &mut rng).unwrap();
    let mut encrypt = FourierNtruEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    let mut decrypt = FourierNtruDecryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    let mut input = key.encrypt_zeros(
        params.encryption_parameters(),
        &mut fft,
        &mut rng,
        &mut encrypt,
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| key.decrypt_message_to(
            &input,
            &mut output,
            &short_params,
            &mut fft,
            &mut decrypt
        )))
        .is_err()
    );
    assert!(output.iter().all(|&value| value == 7));
    let before = input.as_ref().to_vec();
    let mut short_encrypt = FourierNtruEncryptWorkspace::new(PolyLength::new(POLY_LENGTH / 2));
    let mut rng = StdRng::seed_from_u64(91);
    let mut expected_rng = StdRng::seed_from_u64(91);
    assert!(
        catch_unwind(AssertUnwindSafe(|| key.encrypt_zeros_to(
            &mut input,
            params.encryption_parameters(),
            &mut fft,
            &mut rng,
            &mut short_encrypt
        )))
        .is_err()
    );
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
    assert_eq!(input.as_ref(), before);
}
