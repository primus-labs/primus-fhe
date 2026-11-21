//! Public encryption boundaries reject incompatible domains and storage before writes.

use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_encoding::{PlaintextEmbedding, ScaledCodec};
use primus_lattice::GlweDimension;
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    BlockOccupancy, FourierGlweAutomorphismKey, FourierGlweCiphertext, FourierGlweEncryptor,
    FourierGlweKeySwitchingKey, FourierGlweTraceKey, GadgetSize, GlevParameters, GlweCiphertext,
    GlweEncryptionParameters, GlweKeySwitchingParameters, GlweParameters, GlweSecretKey, GlweSize,
    GlweSizeError, NttGgswCiphertext, NttGlevCiphertext, NttGlweCiphertext,
    NttGlweGadgetEncryptWorkspace, NttGlweKeySwitchingKey, NttGlweKeySwitchingWorkspace,
    NttGlwePublicEncryptWorkspace, NttGlwePublicKey, NttGlweSecretKey, SecretKeyDistr,
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

    // At q=13 the Gaussian support can include magnitudes up to 12.
    let gaussian = |sigma| {
        GlweParameters::try_new(
            GlweDimension::new(1),
            PolyLength::new(N),
            2u32,
            BarrettModulus::new(13),
            SecretKeyDistr::gaussian(sigma),
            0.7,
        )
    };
    assert!(gaussian(1.0).is_ok());
    assert!(matches!(
        gaussian(1.1),
        Err(Error::SecretKey(
            primus_distr::SecretKeySamplerError::ModulusTooSmall {
                maximum_magnitude: 13,
                modulus_minus_one: 12,
            }
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
fn ntt_secret_generation_rejects_incompatible_tables_before_sampling() {
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
}

// KS may change dimension; automorphism and trace must return to the same layout.
// Every public constructor must reject its own incompatible resources before RNG use.
fn check_fourier_evaluation_key_generation_boundaries<Table: FftTable>() {
    let length = PolyLength::new(32);
    let size = GlweSize::new(GlweDimension::new(2), length);
    let small_size = GlweSize::new(GlweDimension::new(1), length);
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
    let ks = GlweKeySwitchingParameters::new(size.dimension(), params.clone());
    let make_secret = |size: GlweSize| GlweSecretKey::new(vec![1; size.mask_len()], size, distr);
    let secret = make_secret(size);
    let small = make_secret(small_size);
    let long = make_secret(long_size);
    let table = Table::new(length);
    let long_table = Table::new(long_size.poly_length());
    for operation in 0..3 {
        // Only KS has an independent source key. All three reject wrong target
        // layouts and FFT lengths before consuming any encryption randomness.
        for case in 0..if operation == 0 { 4 } else { 2 } {
            let target = if case == 0 { &small } else { &secret };
            let input = match case {
                2 => &long,
                3 => &small,
                _ => &secret,
            };
            let mut encryptor =
                FourierGlweEncryptor::try_new(target, params.encryption_parameters()).unwrap();
            let mut fft = FftEngine::new(if case == 1 { &long_table } else { &table });
            let mut rng = StdRng::seed_from_u64(42);
            let mut expected_rng = StdRng::seed_from_u64(42);
            assert!(
                catch_unwind(AssertUnwindSafe(|| match operation {
                    0 => {
                        let _ = FourierGlweKeySwitchingKey::generate(
                            input,
                            &mut encryptor,
                            &ks,
                            &mut fft,
                            &mut rng,
                        );
                    }
                    1 => {
                        let _ = FourierGlweAutomorphismKey::generate(
                            3,
                            &mut encryptor,
                            &params,
                            &mut fft,
                            &mut rng,
                        );
                    }
                    _ => {
                        let _ = FourierGlweTraceKey::generate(
                            &mut encryptor,
                            &params,
                            &mut fft,
                            &mut rng,
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
    let key_coefficients = primus_glwe::GlweSecretKey::generate(
        params.size(),
        (params.encryption_parameters()).secret_key_sampler(),
        &mut rng,
    );
    let mut key =
        FourierGlweEncryptor::try_new(&key_coefficients, params.encryption_parameters()).unwrap();

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
                );
            }))
            .is_err()
        );
        assert_eq!(output.as_ref(), vec![sentinel; len]);
    }
}

struct NttBoundaryKey {
    params: GlweParameters<u32, BarrettModulus<u32>>,
    table: UintNttTable<u32>,
    coefficient_key: GlweSecretKey<u32>,
    key: NttGlweSecretKey<u32>,
}

impl NttBoundaryKey {
    fn new() -> Self {
        let modulus = BarrettModulus::new(257);
        let params = GlweParameters::new(
            GlweDimension::new(1),
            PolyLength::new(N),
            16,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let table = UintNttTable::new(params.poly_length(), modulus).unwrap();
        let (coefficient_key, key) = NttGlweSecretKey::generate_pair(
            params.size(),
            params.encryption_parameters(),
            &table,
            &mut StdRng::seed_from_u64(42),
        );
        Self {
            params,
            table,
            coefficient_key,
            key,
        }
    }

    fn gadget(&self) -> GlevParameters<u32, BarrettModulus<u32>> {
        GlevParameters::with_glwe_params(
            &self.params,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(4),
                level_count: None,
            },
        )
    }
}

#[track_caller]
fn rejects_before_sampling(attempt: impl FnOnce(&mut StdRng)) {
    let mut rng = StdRng::seed_from_u64(43);
    let mut untouched = StdRng::seed_from_u64(43);
    assert!(catch_unwind(AssertUnwindSafe(|| attempt(&mut rng))).is_err());
    assert_eq!(rng.next_u64(), untouched.next_u64());
}

#[test]
fn ntt_gadget_encryption_rejects_incompatible_domains_before_sampling() {
    let fixture = NttBoundaryKey::new();
    let params = fixture.gadget();
    let wrong_modulus = BarrettModulus::new(769);
    let wrong_table = UintNttTable::new(PolyLength::new(N), wrong_modulus).unwrap();
    let longer_table =
        UintNttTable::new(PolyLength::new(2 * N), fixture.params.cipher_modulus()).unwrap();
    let foreign_key =
        NttGlweSecretKey::from_coeff_secret_key(&fixture.coefficient_key, &wrong_table);
    let message = Polynomial::new(vec![3u32; N]);
    let mut workspace = NttGlweGadgetEncryptWorkspace::new(params.size());

    for (key, table) in [
        (&fixture.key, &wrong_table),
        (&fixture.key, &longer_table),
        (&foreign_key, &fixture.table),
    ] {
        let mut output = NttGlevCiphertext::new(vec![7u32; params.glev_len()]);
        rejects_before_sampling(|rng| {
            key.encrypt_glev_to(&message, &mut output, &params, table, rng, &mut workspace);
        });
        assert!(output.as_ref().iter().all(|&value| value == 7));
    }

    // GGSW shares the domain checks. One case verifies the entry calls them.
    let mut output = NttGgswCiphertext::new(vec![7u32; params.ggsw_len()]);
    rejects_before_sampling(|rng| {
        fixture.key.encrypt_ggsw_to(
            &message,
            &mut output,
            &params,
            &wrong_table,
            rng,
            &mut workspace,
        );
    });
    assert!(output.as_ref().iter().all(|&value| value == 7));
}

#[test]
fn ntt_key_switch_rejects_wrong_input_layout_and_evaluation_domain() {
    let fixture = NttBoundaryKey::new();
    let params = &fixture.params;
    let key_switching = GlweKeySwitchingParameters::new(params.dimension(), fixture.gadget());
    let mut gadget_workspace = NttGlweGadgetEncryptWorkspace::new(key_switching.output().size());

    // The declared source layout binds rank and polynomial length independently.
    for size in [
        GlweSize::new(GlweDimension::new(2), PolyLength::new(N)),
        GlweSize::new(GlweDimension::new(1), PolyLength::new(2 * N)),
    ] {
        let input = GlweSecretKey::new(
            vec![1; size.mask_len()],
            size,
            SecretKeyDistr::UniformBinary,
        );
        rejects_before_sampling(|rng| {
            let _ = NttGlweKeySwitchingKey::generate(
                &input,
                &fixture.key,
                &key_switching,
                &fixture.table,
                rng,
                &mut gadget_workspace,
            );
        });
    }

    let switching_key = NttGlweKeySwitchingKey::generate(
        &fixture.coefficient_key,
        &fixture.key,
        &key_switching,
        &fixture.table,
        &mut StdRng::seed_from_u64(44),
        &mut gadget_workspace,
    );
    let input = GlweCiphertext::new(vec![0u32; params.glwe_len()]);
    let mut workspace = NttGlweKeySwitchingWorkspace::new(params.size());
    let modulus = params.cipher_modulus();
    let foreign_modulus = BarrettModulus::new(769);
    let wrong_table = UintNttTable::new(params.poly_length(), foreign_modulus).unwrap();
    let longer_table = UintNttTable::new(PolyLength::new(2 * N), modulus).unwrap();
    // Even a modulus and table that agree with one another can belong to the wrong key.
    for (modulus, table) in [
        (modulus, &wrong_table),
        (modulus, &longer_table),
        (foreign_modulus, &wrong_table),
    ] {
        let mut output = GlweCiphertext::new(vec![7u32; params.glwe_len()]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                switching_key.key_switch_to(&input, &mut output, modulus, table, &mut workspace);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 7));
    }
}

#[test]
fn ntt_public_encryption_rejects_incompatible_resources_before_writes() {
    let fixture = NttBoundaryKey::new();
    let params = &fixture.params;
    let public_key = NttGlwePublicKey::generate(
        &fixture.key,
        params.encryption_parameters(),
        &fixture.table,
        &mut StdRng::seed_from_u64(45),
    );
    let wrong_table = UintNttTable::new(params.poly_length(), BarrettModulus::new(769)).unwrap();
    let message = Polynomial::new(vec![3u32; N]);
    let ephemeral = params
        .try_ephemeral_sampler(Some(SecretKeyDistr::SparseTernary))
        .unwrap();

    // Extra workspace capacity must fail the same exact-size check as a short buffer.
    for (table, workspace_length) in [(&wrong_table, N), (&fixture.table, 2 * N)] {
        let mut workspace = NttGlwePublicEncryptWorkspace::new(PolyLength::new(workspace_length));
        let mut output = NttGlweCiphertext::new(vec![7u32; params.glwe_len()]);
        rejects_before_sampling(|rng| {
            public_key.encrypt_message_to(
                &message,
                &mut output,
                params,
                &ephemeral,
                PlaintextEmbedding::Unsigned,
                table,
                rng,
                &mut workspace,
            );
        });
        assert!(output.as_ref().iter().all(|&value| value == 7));
    }
}

#[test]
fn ntt_secret_operations_reject_incompatible_domains_before_writes() {
    let fixture = NttBoundaryKey::new();
    let params = &fixture.params;
    let wrong_table = UintNttTable::new(params.poly_length(), BarrettModulus::new(769)).unwrap();
    let foreign_key =
        NttGlweSecretKey::from_coeff_secret_key(&fixture.coefficient_key, &wrong_table);
    let message = Polynomial::new(vec![3u32; N]);
    let input = NttGlweCiphertext::new(vec![0u32; params.glwe_len()]);
    let mut phase = Polynomial::new(vec![7u32; N]);

    // Matching parameters and table do not establish the owning key's domain.
    for (key, table) in [(&fixture.key, &wrong_table), (&foreign_key, &fixture.table)] {
        let mut output = NttGlweCiphertext::new(vec![7u32; params.glwe_len()]);
        rejects_before_sampling(|rng| {
            key.encrypt_message_to(
                &message,
                &mut output,
                params,
                PlaintextEmbedding::Unsigned,
                table,
                rng,
            );
        });
        assert!(output.as_ref().iter().all(|&value| value == 7));

        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.decrypt_phase_to(&input, &mut phase, params.cipher_modulus(), table);
            }))
            .is_err()
        );
        assert!(phase.as_ref().iter().all(|&value| value == 7));
    }
}

#[test]
fn coefficient_secret_operations_reject_invalid_layouts_without_touching_scratch() {
    let fixture = NttBoundaryKey::new();
    let params = &fixture.params;
    let wrong_table = UintNttTable::new(params.poly_length(), BarrettModulus::new(769)).unwrap();
    let longer_table = UintNttTable::new(PolyLength::new(2 * N), params.cipher_modulus()).unwrap();
    let foreign_key =
        NttGlweSecretKey::from_coeff_secret_key(&fixture.coefficient_key, &wrong_table);

    // Each case changes one of the polynomial, ciphertext, scratch, table or key domains.
    for (key, polynomial_len, ciphertext_len, scratch_len, table) in [
        (&fixture.key, N - 1, 2 * N, N, &fixture.table),
        (&fixture.key, N, 2 * N - 1, N, &fixture.table),
        (&fixture.key, N, 3 * N, N, &fixture.table),
        (&fixture.key, N, 2 * N, N - 1, &fixture.table),
        (&fixture.key, N, 2 * N, N + 1, &fixture.table),
        (&fixture.key, N, 2 * N, N, &wrong_table),
        (&fixture.key, N, 2 * N, N, &longer_table),
        (&foreign_key, N, 2 * N, N, &fixture.table),
    ] {
        let mut polynomial = Polynomial::new(vec![7; polynomial_len]);
        let mut ciphertext = GlweCiphertext::new(vec![7; ciphertext_len]);
        let mut scratch = vec![7; scratch_len];
        rejects_before_sampling(|rng| {
            key.encrypt_message_coeff_to(
                &polynomial,
                &mut ciphertext,
                params,
                PlaintextEmbedding::Unsigned,
                table,
                rng,
                &mut scratch,
            );
        });
        assert!(ciphertext.as_ref().iter().all(|&value| value == 7));
        assert!(scratch.iter().all(|&value| value == 7));

        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.decrypt_message_coeff_to(
                    &ciphertext,
                    &mut polynomial,
                    params,
                    table,
                    &mut scratch,
                );
            }))
            .is_err()
        );
        assert!(polynomial.as_ref().iter().all(|&value| value == 7));
        assert!(scratch.iter().all(|&value| value == 7));
    }
}

#[test]
fn only_ntt_ggsw_requires_matching_workspace_levels() {
    let mut rng = StdRng::seed_from_u64(42);
    let modulus = BarrettModulus::new(132_120_577u32);
    let params = GlweParameters::new(
        GlweDimension::new(1),
        PolyLength::new(N),
        16,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let gadget = GlevParameters::with_glwe_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    );
    let ntt = UintNttTable::new(PolyLength::new(N), modulus).unwrap();
    let (_, key) = NttGlweSecretKey::generate_pair(
        params.size(),
        params.encryption_parameters(),
        &ntt,
        &mut rng,
    );
    let message = Polynomial::new(vec![1u32; N]);
    for levels in [1, 4] {
        let mut workspace = NttGlweGadgetEncryptWorkspace::new(GadgetSize::new(
            params.size(),
            DecompositionLevelCount::new(levels),
        ));
        let mut glev = NttGlevCiphertext::<Vec<u32>>::zero(gadget.glev_len());
        key.encrypt_glev_to(&message, &mut glev, &gadget, &ntt, &mut rng, &mut workspace);
        let mut output = NttGgswCiphertext::new(vec![7u32; gadget.ggsw_len()]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| key.encrypt_ggsw_to(
                &message,
                &mut output,
                &gadget,
                &ntt,
                &mut rng,
                &mut workspace
            )))
            .is_err()
        );
        assert_eq!(output.as_ref(), vec![7u32; gadget.ggsw_len()]);
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

/// A padded return key retains the logical block partition, not a new kN-sized sample.
#[test]
fn padded_lwe_gadget_parameters_validate_logical_prefix_and_full_layout() {
    use std::sync::Arc;

    use primus_decompose::primitive::ApproxSignedBasis;
    use primus_glwe::GlevParameterError;
    use primus_lattice::LweDimension;

    let size = GlweSize::new(GlweDimension::new(1), PolyLength::new(32));
    let inner = Arc::new(GlweEncryptionParameters::new(
        NativeModulus::<u32>::new(),
        SecretKeyDistr::BlockBinary {
            block_size: 3,
            occupancy: BlockOccupancy::AtMostOne,
        },
        0.7,
    ));
    let basis = ApproxSignedBasis::new(None, DecompositionBaseLog::new(3), None);
    let make = |size, dimension, basis| {
        GlevParameters::try_from_padded_lwe_parts(
            size,
            LweDimension::new(dimension),
            Arc::clone(&inner),
            basis,
        )
    };

    // n=6 consists of two width-three blocks; the 26 public zeros add no blocks.
    let padded = make(size, 6, basis.clone()).unwrap();
    assert_eq!(padded.glwe_size(), size);
    assert_eq!(padded.basis(), &basis);
    assert!(std::ptr::eq(padded.encryption_parameters(), inner.as_ref()));
    // Ordinary construction still requires the complete 32 coefficients to
    // form valid blocks. The padded constructor must not weaken this boundary.
    assert!(matches!(
        GlevParameters::try_from_parts(size, Arc::clone(&inner), basis.clone()),
        Err(GlevParameterError::SecretKey(
            primus_distr::SecretKeySamplerError::InvalidBlockLength {
                length: 32,
                block_size: 3
            }
        ))
    ));
    assert!(matches!(
        make(size, 5, basis.clone()),
        Err(GlevParameterError::SecretKey(
            primus_distr::SecretKeySamplerError::InvalidBlockLength {
                length: 5,
                block_size: 3
            }
        ))
    ));
    assert!(matches!(
        make(size, 33, basis.clone()),
        Err(GlevParameterError::PaddedSecretDimensionExceedsCapacity {
            logical_dimension: 33,
            capacity: 32
        })
    ));
    let explicit_basis = ApproxSignedBasis::new(Some(257), DecompositionBaseLog::new(3), None);
    assert!(matches!(
        make(size, 6, explicit_basis),
        Err(GlevParameterError::BasisModulusMismatch)
    ));

    // Prefix validation cannot bypass overflow of the physical GGSW layout.
    let huge = GlweSize::new(
        GlweDimension::new(1usize << (usize::BITS / 2)),
        PolyLength::new(32),
    );
    assert!(matches!(
        make(huge, 6, basis),
        Err(GlevParameterError::InvalidSize(_))
    ));
}
