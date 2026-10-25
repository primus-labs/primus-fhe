//! Public encryption boundaries reject incompatible domains and storage before writes.

use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_encoding::{PlaintextEmbedding, ScaledCodec};
use primus_lattice::GlweDimension;
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGgswCiphertext, FourierGlevCiphertext, FourierGlweAutomorphismKey,
    FourierGlweCiphertext, FourierGlweEncryptWorkspace, FourierGlweGadgetEncryptWorkspace,
    FourierGlweKeySwitchingKey, FourierGlweSecretKey, FourierGlweTraceKey, GadgetSize,
    GlevParameters, GlweCiphertext, GlweEncryptionParameters, GlweKeySwitchingParameters,
    GlweParameters, GlweSecretKey, GlweSize, GlweSizeError, NttGgswCiphertext, NttGlevCiphertext,
    NttGlweCiphertext, NttGlweGadgetEncryptWorkspace, NttGlweKeySwitchingKey,
    NttGlweKeySwitchingWorkspace, NttGlwePublicEncryptWorkspace, NttGlwePublicKey,
    NttGlweSecretKey, SecretKeyDistr,
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use rand::{Rng, SeedableRng, rngs::StdRng};

const N: usize = 64;

#[test]
fn key_switch_parameters_check_input_layout_at_construction() {
    let glwe = GlweParameters::new(
        GlweDimension::new(1),
        PolyLength::new(N),
        4,
        NativeModulus::<u32>::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let output = GlevParameters::with_glwe_params(
        &glwe,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(4),
            level_count: None,
        },
    );
    // Parameters allocate no ciphertexts; address-space boundaries can be
    // checked without constructing a large key or buffer.
    for (dimension, error) in [
        (
            usize::MAX / output.glev_len() + 1,
            GlweSizeError::LengthOverflow("GLWE key-switching key"),
        ),
        (
            usize::MAX / N + 1,
            GlweSizeError::LengthOverflow("GLWE mask"),
        ),
        (
            usize::MAX / N,
            GlweSizeError::LengthOverflow("GLWE ciphertext"),
        ),
    ] {
        assert_eq!(
            GlweKeySwitchingParameters::try_new(GlweDimension::new(dimension), output.clone())
                .err(),
            Some(error)
        );
    }
    let parameters = GlweKeySwitchingParameters::try_new(GlweDimension::new(2), output).unwrap();
    assert_eq!(parameters.input_size().glwe_len(), 3 * N);
    assert_eq!(
        parameters.input_size().poly_length(),
        parameters.output_size().glwe_size().poly_length()
    );
}

#[test]
fn fallible_parameters_check_layout_codec_and_samplers() {
    use primus_glwe::GlweParameterError as Error;
    let make = |k, n, t, distr, noise| {
        GlweParameters::try_new(
            GlweDimension::new(k),
            PolyLength::new(n),
            t,
            NativeModulus::<u32>::new(),
            distr,
            noise,
        )
    };
    // Ring length is checked by PolyLength; this boundary owns composed overflow.
    assert!(matches!(
        make(usize::MAX - 1, 32, 4, SecretKeyDistr::UniformBinary, 0.7),
        Err(Error::Layout(_))
    ));
    assert!(matches!(
        make(1, 32, 1, SecretKeyDistr::UniformBinary, 0.7),
        Err(Error::Encoding(_))
    ));
    assert!(matches!(
        make(1, 32, 4, SecretKeyDistr::UniformBinary, f64::NAN),
        Err(Error::Noise(_))
    ));
    // A fixed weight applies to the complete kN key, not to each polynomial.
    let distr = SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 33 };
    assert!(make(2, 32, 4, distr, 0.7).is_ok());
    assert!(matches!(
        make(1, 32, 4, distr, 0.7),
        Err(Error::SecretKey(_))
    ));
    assert!(matches!(
        GlweParameters::try_new(
            GlweDimension::new(1),
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
fn independent_parameter_parts_check_secret_weight_and_codec_domain() {
    use primus_decompose::primitive::ApproxSignedBasis;
    use primus_glwe::{GlevParameterError, GlweEncryptionParameters, GlweParameterError, GlweSize};
    use std::sync::Arc;

    let modulus = BarrettModulus::new(257u32);
    let inner = Arc::new(GlweEncryptionParameters::new(
        modulus,
        SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 33 },
        0.7,
    ));
    let basis = ApproxSignedBasis::new(Some(257), DecompositionBaseLog::new(3), None);
    let codec = ScaledCodec::new(4, modulus);
    // The sampler alone has no layout: both compositions must check total kN.
    for k in [1, 2] {
        let size = GlweSize::new(GlweDimension::new(k), PolyLength::new(32));
        let gadget = GlevParameters::try_from_parts(size, Arc::clone(&inner), basis.clone());
        let fresh_gadget = GlevParameters::try_new(
            size,
            modulus,
            inner.secret_key_distr(),
            DecompositionConfig {
                log_basis: basis.log_basis(),
                level_count: None,
            },
            inner.noise_distribution().standard_deviation(),
        );
        let ordinary = GlweParameters::try_from_parts(size, Arc::clone(&inner), codec);
        if k == 1 {
            assert!(matches!(gadget, Err(GlevParameterError::SecretKey(_))));
            assert!(matches!(
                fresh_gadget,
                Err(GlevParameterError::SecretKey(_))
            ));
            assert!(matches!(ordinary, Err(GlweParameterError::SecretKey(_))));
        } else {
            let gadget = gadget.unwrap();
            let fresh_gadget = fresh_gadget.unwrap();
            let ordinary = ordinary.unwrap();
            assert_eq!(fresh_gadget.basis(), &basis);
            assert_eq!(fresh_gadget.glwe_size(), size);
            // Binding and cloning outer parameters retain the prepared samplers.
            assert!(std::ptr::eq(
                gadget.clone().encryption_parameters(),
                inner.as_ref()
            ));
            assert!(std::ptr::eq(
                ordinary.clone().encryption_parameters(),
                inner.as_ref()
            ));
            assert_eq!(gadget.basis(), &basis);
            assert_eq!(ordinary.plain_modulus_value(), 4);

            // Replacing the basis preserves the validated layout and sampler
            // pairing while recomputing the gadget lengths for the new levels.
            let new_basis = ApproxSignedBasis::new(
                Some(257),
                DecompositionBaseLog::new(4),
                Some(DecompositionLevelCount::new(2)),
            );
            let derived = gadget.try_with_new_basis(new_basis.clone()).unwrap();
            assert_eq!(derived.glwe_size(), size);
            assert_eq!(derived.basis(), &new_basis);
            assert_eq!(derived.glev_len(), size.glwe_len() * 2);
            assert!(std::ptr::eq(
                derived.encryption_parameters(),
                inner.as_ref(),
            ));
            for foreign_modulus in [None, Some(769)] {
                let foreign_basis = ApproxSignedBasis::new(
                    foreign_modulus,
                    DecompositionBaseLog::new(4),
                    Some(DecompositionLevelCount::new(2)),
                );
                assert!(matches!(
                    gadget.try_with_new_basis(foreign_basis),
                    Err(GlevParameterError::BasisModulusMismatch)
                ));
            }
        }
    }
    assert!(matches!(
        GlweParameters::try_from_parts(
            GlweSize::new(GlweDimension::new(2), PolyLength::new(32)),
            inner,
            ScaledCodec::new(4, BarrettModulus::new(769)),
        ),
        Err(GlweParameterError::CodecModulusMismatch)
    ));
}

#[test]
fn secret_generation_rejects_incompatible_tables_before_sampling() {
    let size = GlweSize::new(GlweDimension::new(1), PolyLength::new(N));
    let modulus = BarrettModulus::new(257u32);
    let params = GlweEncryptionParameters::new(modulus, SecretKeyDistr::UniformBinary, 0.7);
    for table in [
        UintNttTable::new(PolyLength::new(N), BarrettModulus::new(769u32)).unwrap(),
        UintNttTable::new(PolyLength::new(N * 2), modulus).unwrap(),
    ] {
        let mut rng = StdRng::seed_from_u64(42);
        let mut expected_rng = StdRng::seed_from_u64(42);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = NttGlweSecretKey::generate_pair(size, &params, &table, &mut rng);
            }))
            .is_err()
        );
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }

    let params = GlweEncryptionParameters::new(
        NativeModulus::<u32>::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let table = RustFftTable::new(PolyLength::new(N * 2));
    let mut fft = FftEngine::new(&table);
    let mut rng = StdRng::seed_from_u64(42);
    let mut expected_rng = StdRng::seed_from_u64(42);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = FourierGlweSecretKey::generate_pair(size, &params, &mut fft, &mut rng);
        }))
        .is_err()
    );
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
}

// KS may change dimension; automorphism and trace must return to the same layout.
// Every public constructor must reject its own incompatible resources before RNG use.
fn check_fourier_evaluation_key_generation_boundaries<Table: FftTable>() {
    let poly_length = PolyLength::new(32);
    let size = GlweSize::new(GlweDimension::new(2), poly_length);
    let small_size = GlweSize::new(GlweDimension::new(1), poly_length);
    let long_size = GlweSize::new(GlweDimension::new(2), PolyLength::new(64));
    let distr = SecretKeyDistr::UniformTernary;
    let params = GlevParameters::try_new(
        size,
        NativeModulus::<u32>::new(),
        distr,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
        0.7,
    )
    .unwrap();
    let key_switching = GlweKeySwitchingParameters::new(size.dimension(), params.clone());
    let long_gadget = GadgetSize::new(long_size, params.basis().level_count());
    let secret = |size: GlweSize| GlweSecretKey::new(vec![1; size.mask_len()], size, distr);
    let small_secret = secret(small_size);
    let long_secret = secret(long_size);
    let secret = secret(size);
    let table = Table::new(poly_length);
    let long_table = Table::new(long_size.poly_length());
    let mut fft = FftEngine::new(&table);
    let fourier_secret = FourierGlweSecretKey::from_coeff_secret_key(&secret, &mut fft);
    let small_fourier = FourierGlweSecretKey::from_coeff_secret_key(&small_secret, &mut fft);

    for (input, output, table, workspace_size) in [
        (&long_secret, &fourier_secret, &table, params.size()),
        (&secret, &small_fourier, &table, params.size()),
        (&secret, &fourier_secret, &long_table, params.size()),
        (&secret, &fourier_secret, &table, long_gadget),
        (&small_secret, &fourier_secret, &table, params.size()),
    ] {
        for operation in 0..3 {
            let mut fft = FftEngine::new(table);
            let mut workspace = FourierGlweGadgetEncryptWorkspace::new(workspace_size);
            let mut rng = StdRng::seed_from_u64(42);
            let mut expected_rng = StdRng::seed_from_u64(42);
            assert!(
                catch_unwind(AssertUnwindSafe(|| match operation {
                    0 => {
                        let _ = FourierGlweKeySwitchingKey::generate(
                            input,
                            output,
                            &key_switching,
                            &mut fft,
                            &mut rng,
                            &mut workspace,
                        );
                    }
                    1 => {
                        let _ = FourierGlweAutomorphismKey::generate(
                            3,
                            input,
                            output,
                            &params,
                            &mut fft,
                            &mut rng,
                            &mut workspace,
                        );
                    }
                    _ => {
                        let _ = FourierGlweTraceKey::generate(
                            input,
                            output,
                            &params,
                            &mut fft,
                            &mut rng,
                            &mut workspace,
                        );
                    }
                }))
                .is_err()
            );
            assert_eq!(rng.next_u64(), expected_rng.next_u64());
        }
    }
}

#[test]
fn fourier_evaluation_key_generation_rejects_before_sampling() {
    check_fourier_evaluation_key_generation_boundaries::<RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check_fourier_evaluation_key_generation_boundaries::<primus_fft::TfheFftTable>();
}

#[test]
fn secret_support_is_checked_at_parameter_construction() {
    for (sigma, valid) in [(1.0, true), (1.1, false)] {
        let result = catch_unwind(|| {
            GlweParameters::new(
                GlweDimension::new(1),
                PolyLength::new(N),
                2u32,
                BarrettModulus::new(13),
                SecretKeyDistr::gaussian(sigma),
                0.7,
            )
        });
        assert_eq!(result.is_ok(), valid);
    }
}

#[test]
fn fourier_encryption_rejects_incomplete_and_excess_masks_before_writes() {
    let params = GlweParameters::new(
        GlweDimension::new(1),
        PolyLength::new(N),
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let table = RustFftTable::new(PolyLength::new(N));
    let mut fft = FftEngine::new(&table);
    let mut rng = StdRng::seed_from_u64(42);
    let (_, key) = FourierGlweSecretKey::generate_pair(
        params.size(),
        params.encryption_parameters(),
        &mut fft,
        &mut rng,
    );
    let mut workspace = FourierGlweEncryptWorkspace::new(PolyLength::new(N));
    let message = Polynomial::new(vec![3u32; N]);
    let sentinel = Complex64::new(7.0, 9.0);

    // A body without a mask used to return recoverable plaintext; excess masks
    // used to be silently ignored by the secret/mask zip.
    for len in [N / 2, params.fourier_glwe_len() + N / 2] {
        let mut output = FourierGlweCiphertext::new(vec![sentinel; len]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.encrypt_message_to(
                    &message,
                    &mut output,
                    &params,
                    PlaintextEmbedding::Unsigned,
                    &mut fft,
                    &mut rng,
                    &mut workspace,
                );
            }))
            .is_err()
        );
        assert_eq!(output.as_ref(), vec![sentinel; len]);
    }
}

#[test]
fn ntt_operations_reject_incompatible_domains_and_workspace_before_writes() {
    let modulus = BarrettModulus::new(257u32);
    let params = GlweParameters::new(
        GlweDimension::new(1),
        PolyLength::new(N),
        16,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let table = UintNttTable::new(PolyLength::new(N), modulus).unwrap();
    let wrong_table = UintNttTable::new(PolyLength::new(N), BarrettModulus::new(769u32)).unwrap();
    let wrong_length_table = UintNttTable::new(PolyLength::new(N * 2), modulus).unwrap();
    let gadget = GlevParameters::with_glwe_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(4),
            level_count: None,
        },
    );
    let mut rng = StdRng::seed_from_u64(42);
    let (coeff_key, key) = NttGlweSecretKey::generate_pair(
        params.size(),
        params.encryption_parameters(),
        &table,
        &mut rng,
    );
    // Equal layouts and matching parameters/table do not establish the secret's domain.
    let foreign_key = NttGlweSecretKey::from_coeff_secret_key(&coeff_key, &wrong_table);
    let public_key =
        NttGlwePublicKey::generate(&key, params.encryption_parameters(), &table, &mut rng);
    let message = Polynomial::new(vec![3u32; N]);
    let mut workspace = NttGlwePublicEncryptWorkspace::new(PolyLength::new(N));

    let mut gadget_workspace = NttGlweGadgetEncryptWorkspace::new(gadget.size());
    for (key, wrong_ntt) in [
        (&key, &wrong_table),
        (&key, &wrong_length_table),
        (&foreign_key, &table),
    ] {
        for ggsw in [false, true] {
            let len = if ggsw {
                gadget.ggsw_len()
            } else {
                gadget.glev_len()
            };
            let mut output = vec![7u32; len];
            let mut rng = StdRng::seed_from_u64(43);
            let mut expected_rng = StdRng::seed_from_u64(43);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    if ggsw {
                        key.encrypt_ggsw_to(
                            &message,
                            &mut NttGgswCiphertext::new(output.as_mut_slice()),
                            &gadget,
                            wrong_ntt,
                            &mut rng,
                            &mut gadget_workspace,
                        );
                    } else {
                        key.encrypt_glev_to(
                            &message,
                            &mut NttGlevCiphertext::new(output.as_mut_slice()),
                            &gadget,
                            wrong_ntt,
                            &mut rng,
                            &mut gadget_workspace,
                        );
                    }
                }))
                .is_err()
            );
            assert_eq!(output, vec![7; len]);
            assert_eq!(rng.next_u64(), expected_rng.next_u64());
        }
    }
    let key_switching = GlweKeySwitchingParameters::new(params.dimension(), gadget);
    // The declared input layout binds both rank and polynomial length.
    for size in [
        GlweSize::new(GlweDimension::new(2), PolyLength::new(N)),
        GlweSize::new(GlweDimension::new(1), PolyLength::new(2 * N)),
    ] {
        let input = GlweSecretKey::new(
            vec![1; size.mask_len()],
            size,
            SecretKeyDistr::UniformBinary,
        );
        let mut rejected_rng = StdRng::seed_from_u64(43);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = NttGlweKeySwitchingKey::generate(
                    &input,
                    &key,
                    &key_switching,
                    &table,
                    &mut rejected_rng,
                    &mut gadget_workspace,
                );
            }))
            .is_err()
        );
        assert_eq!(
            rejected_rng.next_u64(),
            StdRng::seed_from_u64(43).next_u64()
        );
    }
    let switching_key = NttGlweKeySwitchingKey::generate(
        &coeff_key,
        &key,
        &key_switching,
        &table,
        &mut rng,
        &mut gadget_workspace,
    );
    let input = GlweCiphertext::new(vec![0u32; params.glwe_len()]);
    let mut switching_workspace = NttGlweKeySwitchingWorkspace::new(params.size());
    // Also reject a mutually compatible modulus/table pair belonging to a different key.
    for (modulus, ntt) in [
        (modulus, &wrong_table),
        (modulus, &wrong_length_table),
        (BarrettModulus::new(769), &wrong_table),
    ] {
        let mut output = GlweCiphertext::new(vec![7u32; params.glwe_len()]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                switching_key.key_switch_to(
                    &input,
                    &mut output,
                    modulus,
                    ntt,
                    &mut switching_workspace,
                );
            }))
            .is_err()
        );
        assert_eq!(output.as_ref(), vec![7u32; params.glwe_len()]);
    }

    for public in [false, true] {
        let mut output = NttGlweCiphertext::new(vec![7u32; params.glwe_len()]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                if public {
                    public_key.encrypt_message_to(
                        &message,
                        &mut output,
                        &params,
                        PlaintextEmbedding::Unsigned,
                        &wrong_table,
                        &mut rng,
                        &mut workspace,
                    );
                } else {
                    key.encrypt_message_to(
                        &message,
                        &mut output,
                        &params,
                        PlaintextEmbedding::Unsigned,
                        &wrong_table,
                        &mut rng,
                    );
                }
            }))
            .is_err()
        );
        assert_eq!(output.as_ref(), vec![7u32; params.glwe_len()]);
    }
    // Ordinary NTT encryption must reject a foreign owner before the first draw.
    let mut output = NttGlweCiphertext::new(vec![7u32; params.glwe_len()]);
    let mut rejected_rng = StdRng::seed_from_u64(43);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            foreign_key.encrypt_message_to(
                &message,
                &mut output,
                &params,
                PlaintextEmbedding::Unsigned,
                &table,
                &mut rejected_rng,
            );
        }))
        .is_err()
    );
    assert_eq!(output.as_ref(), vec![7u32; params.glwe_len()]);
    assert_eq!(
        rejected_rng.next_u64(),
        StdRng::seed_from_u64(43).next_u64()
    );

    for length in [N / 2, N * 2] {
        let mut wrong_workspace = NttGlwePublicEncryptWorkspace::new(PolyLength::new(length));
        let mut output = NttGlweCiphertext::new(vec![7u32; params.glwe_len()]);
        let mut rng = StdRng::seed_from_u64(43);
        let mut expected_rng = StdRng::seed_from_u64(43);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                public_key.encrypt_message_to(
                    &message,
                    &mut output,
                    &params,
                    PlaintextEmbedding::Unsigned,
                    &table,
                    &mut rng,
                    &mut wrong_workspace,
                );
            }))
            .is_err()
        );
        assert_eq!(output.as_ref(), vec![7u32; params.glwe_len()]);
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
    let input = NttGlweCiphertext::new(vec![0u32; params.glwe_len()]);
    let mut phase = Polynomial::new(vec![7u32; N]);
    for (key, ntt) in [(&key, &wrong_table), (&foreign_key, &table)] {
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.decrypt_phase_to(&input, &mut phase, modulus, ntt);
            }))
            .is_err()
        );
        assert_eq!(phase.as_ref(), vec![7u32; N]);
    }

    // Coefficient entry points share these checks; no RNG, output or scratch
    // change is allowed for a bad layout or transform domain.
    for (key, polynomial_len, ciphertext_len, scratch_len, ntt) in [
        (&key, N - 1, 2 * N, N, &table),
        (&key, N, 2 * N - 1, N, &table),
        (&key, N, 3 * N, N, &table),
        (&key, N, 2 * N, N - 1, &table),
        (&key, N, 2 * N, N + 1, &table),
        (&key, N, 2 * N, N, &wrong_table),
        (&key, N, 2 * N, N, &wrong_length_table),
        (&foreign_key, N, 2 * N, N, &table),
    ] {
        let mut polynomial = Polynomial::new(vec![7; polynomial_len]);
        let mut ciphertext = GlweCiphertext::new(vec![7; ciphertext_len]);
        let mut scratch = vec![7; scratch_len];
        let mut rng = StdRng::seed_from_u64(43);
        let mut expected_rng = StdRng::seed_from_u64(43);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.encrypt_message_coeff_to(
                    &polynomial,
                    &mut ciphertext,
                    &params,
                    PlaintextEmbedding::Unsigned,
                    ntt,
                    &mut rng,
                    &mut scratch,
                );
            }))
            .is_err()
        );
        assert_eq!(ciphertext.as_ref(), vec![7; ciphertext_len]);
        assert_eq!(scratch, vec![7; scratch_len]);
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.decrypt_message_coeff_to(
                    &ciphertext,
                    &mut polynomial,
                    &params,
                    ntt,
                    &mut scratch,
                );
            }))
            .is_err()
        );
        assert_eq!(polynomial.as_ref(), vec![7; polynomial_len]);
        assert_eq!(scratch, vec![7; scratch_len]);
    }
}

#[test]
fn only_ggsw_requires_matching_workspace_levels_in_both_domains() {
    let mut rng = StdRng::seed_from_u64(42);
    let modulus = BarrettModulus::new(132_120_577u32);
    let ntt_params = GlweParameters::new(
        GlweDimension::new(1),
        PolyLength::new(N),
        16,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let fourier_params = GlweParameters::new(
        GlweDimension::new(1),
        PolyLength::new(N),
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let ntt_gadget = GlevParameters::with_glwe_params(
        &ntt_params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    );
    let fourier_gadget = GlevParameters::with_glwe_params(
        &fourier_params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    );
    let ntt = UintNttTable::new(PolyLength::new(N), modulus).unwrap();
    let table = RustFftTable::new(PolyLength::new(N));
    let mut fft = FftEngine::new(&table);
    let (_, ntt_key) = NttGlweSecretKey::generate_pair(
        ntt_params.size(),
        ntt_params.encryption_parameters(),
        &ntt,
        &mut rng,
    );
    let (_, fourier_key) = FourierGlweSecretKey::generate_pair(
        fourier_params.size(),
        fourier_params.encryption_parameters(),
        &mut fft,
        &mut rng,
    );
    let message = Polynomial::new(vec![1u32; N]);

    for levels in [1, 4] {
        let size = GadgetSize::new(ntt_params.size(), DecompositionLevelCount::new(levels));
        let mut ntt_workspace = NttGlweGadgetEncryptWorkspace::new(size);
        let mut fourier_workspace = FourierGlweGadgetEncryptWorkspace::new(size);
        let mut ntt_glev = NttGlevCiphertext::<Vec<u32>>::zero(ntt_gadget.glev_len());
        let mut fourier_glev =
            FourierGlevCiphertext::<Vec<Complex64>>::zero(fourier_gadget.fourier_glev_len());
        ntt_key.encrypt_glev_to(
            &message,
            &mut ntt_glev,
            &ntt_gadget,
            &ntt,
            &mut rng,
            &mut ntt_workspace,
        );
        fourier_key.encrypt_glev_to(
            &message,
            &mut fourier_glev,
            &fourier_gadget,
            &mut fft,
            &mut rng,
            &mut fourier_workspace,
        );
        let mut ntt_output = NttGgswCiphertext::new(vec![7u32; ntt_gadget.ggsw_len()]);
        let sentinel = Complex64::new(7.0, 9.0);
        let mut fourier_output =
            FourierGgswCiphertext::new(vec![sentinel; fourier_gadget.fourier_ggsw_len()]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                ntt_key.encrypt_ggsw_to(
                    &message,
                    &mut ntt_output,
                    &ntt_gadget,
                    &ntt,
                    &mut rng,
                    &mut ntt_workspace,
                );
            }))
            .is_err()
        );
        assert_eq!(ntt_output.as_ref(), vec![7u32; ntt_gadget.ggsw_len()]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                fourier_key.encrypt_ggsw_to(
                    &message,
                    &mut fourier_output,
                    &fourier_gadget,
                    &mut fft,
                    &mut rng,
                    &mut fourier_workspace,
                );
            }))
            .is_err()
        );
        assert_eq!(
            fourier_output.as_ref(),
            vec![sentinel; fourier_gadget.fourier_ggsw_len()]
        );
    }
}

#[test]
fn glev_construction_reuses_basis_and_rejects_incompatible_domains_or_layouts() {
    use primus_decompose::primitive::ApproxSignedBasis;
    use primus_glwe::GlevParameterError;

    let native = GlweParameters::new(
        GlweDimension::new(2),
        PolyLength::new(N),
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let explicit = GlweParameters::new(
        GlweDimension::new(2),
        PolyLength::new(N),
        16u32,
        BarrettModulus::new(257),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    assert_eq!(native.cipher_modulus_value(), None);
    assert_eq!(explicit.cipher_modulus_value(), Some(257));
    let native_clone = native.clone();
    for levels in [None, Some(2)] {
        let basis = ApproxSignedBasis::new(
            None,
            DecompositionBaseLog::new(3),
            levels.map(DecompositionLevelCount::new),
        );
        let params = GlevParameters::try_with_basis(&native_clone, basis.clone()).unwrap();
        let from_config = GlevParameters::try_with_glwe_params(
            &native_clone,
            DecompositionConfig {
                log_basis: basis.log_basis(),
                level_count: levels.map(DecompositionLevelCount::new),
            },
        )
        .unwrap();
        assert_eq!(from_config.basis(), &basis);
        assert!(std::ptr::eq(
            from_config.encryption_parameters(),
            native.encryption_parameters()
        ));
        assert_eq!(params.basis(), &basis);
        assert_eq!(params.glwe_size(), native.size());
        // Derivation and both outer parameter clones retain the prepared samplers.
        assert!(std::ptr::eq(
            params.clone().encryption_parameters(),
            native.encryption_parameters()
        ));
        let basis = ApproxSignedBasis::new(
            Some(257),
            DecompositionBaseLog::new(3),
            levels.map(DecompositionLevelCount::new),
        );
        let params = GlevParameters::try_with_basis(&explicit, basis.clone()).unwrap();
        assert_eq!(params.basis(), &basis);
        assert_eq!(params.glwe_size(), explicit.size());
        assert!(std::ptr::eq(
            params.encryption_parameters(),
            explicit.encryption_parameters()
        ));
    }
    for modulus in [Some(257), Some(769)] {
        assert!(matches!(
            GlevParameters::try_with_basis(
                &native,
                ApproxSignedBasis::new(modulus, DecompositionBaseLog::new(3), None)
            ),
            Err(GlevParameterError::BasisModulusMismatch)
        ));
    }
    for modulus in [None, Some(769)] {
        assert!(matches!(
            GlevParameters::try_with_basis(
                &explicit,
                ApproxSignedBasis::new(modulus, DecompositionBaseLog::new(3), None)
            ),
            Err(GlevParameterError::BasisModulusMismatch)
        ));
    }
    // Each value is valid on its own, but two 8-bit levels cannot fit at q=257.
    assert!(matches!(
        GlevParameters::try_with_glwe_params(
            &explicit,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(2)),
            },
        ),
        Err(GlevParameterError::InvalidBasis(_))
    ));
    // GLWE lengths fit but the quadratic GGSW layout overflows, without allocating it.
    let huge = GlweParameters::new(
        GlweDimension::new(1usize << (usize::BITS / 2)),
        PolyLength::new(N),
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    assert!(matches!(
        GlevParameters::try_with_glwe_params(
            &huge,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(3),
                level_count: None
            }
        ),
        Err(GlevParameterError::InvalidSize(_))
    ));
}
