//! Separate q/Q domains, return-key binding and packed one-hot geometry; no transforms.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_lwe::{LweDimension, LweSecretKey};
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::{NtruSecretKey, SecretKeyDistr};
use primus_shape::PolyLength;
use primus_tfhe::{BlindRotationMethod, DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_ntru::{
    CbsConfig, CbsGadgetConfig, CbsGadgetParameters, CbsParameters, CircuitBootstrapParameterError,
    ClientKey, DecompositionConfig, GadgetEncryptionConfig, KeyGenerationError, LookupTableError,
    LweConfig, ModulusConfig, OneHotBootstrapError, OneHotLookupTable, PbsConfig, PbsMessageConfig,
    PbsParameters, TfheKeyError,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn decomposition(base: u32) -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(base),
        level_count: None,
    }
}

fn config() -> PbsConfig<u32, BarrettModulus<u32>, PowOf2Modulus<u32>> {
    PbsConfig {
        external_lwe: LweConfig {
            dimension: LweDimension::new(8),
            cipher_modulus: ModulusConfig::Explicit(1024),
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 1.0,
        },
        ring_modulus: ModulusConfig::Explicit(12289),
        bsk_poly_length: PolyLength::new(64),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: decomposition(2),
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: decomposition(2),
            noise_standard_deviation: 3.2,
        },
        method: BlindRotationMethod::Classic,
        messages: PbsMessageConfig::new(8).with_output_modulus(4),
    }
}

fn gadget() -> CbsGadgetConfig {
    CbsGadgetConfig {
        trace: decomposition(2),
        scheme_switch: decomposition(2),
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(2),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    }
}

// A simple invertible f and independent binary s isolate return composition
// checks without generating BR keys or preparing a transform table.
fn return_client(
    parameters: &PbsParameters<u32, BarrettModulus<u32>, PowOf2Modulus<u32>>,
) -> ClientKey<u32> {
    let external = parameters.external_lwe();
    let mut f = vec![0; parameters.poly_length().get()];
    f[0] = 1;
    ClientKey::new(
        LweSecretKey::new(
            vec![1; external.dimension().get()],
            external.secret_key_distr(),
            external.cipher_modulus(),
        ),
        NtruSecretKey::new(f, parameters.accumulator_ntru().secret_key_distr()),
    )
}

#[test]
fn return_binding_checks_imported_parameters_and_actual_key_rows() {
    let parameters = PbsParameters::try_from_config(config()).unwrap();
    let client = return_client(&parameters);
    let mut rng = StdRng::seed_from_u64(73);
    let key = parameters
        .try_generate_lwe_return_key(&client, &mut rng)
        .unwrap();
    parameters.check_lwe_return_key(&key).unwrap();

    // An independent component may use different decomposition and row noise,
    // but must still target the configured external secret domain.
    let mut changed = config();
    changed.key_switching.decomposition = decomposition(3);
    changed.key_switching.noise_standard_deviation = 4.0;
    let alternative = PbsParameters::try_from_config(changed).unwrap();
    let alternative_key = parameters
        .try_generate_lwe_return_key_with_parameters(alternative.key_switching(), &client, &mut rng)
        .unwrap();
    parameters
        .check_lwe_return_key_with_parameters(alternative.key_switching(), &alternative_key)
        .unwrap();
    assert!(parameters.check_lwe_return_key(&alternative_key).is_err());

    for case in 0..3 {
        let mut changed = config();
        match case {
            0 => changed.external_lwe.dimension = LweDimension::new(9),
            1 => changed.external_lwe.cipher_modulus = ModulusConfig::Explicit(2048),
            _ => changed.external_lwe.secret_key_distr = SecretKeyDistr::UniformTernary,
        }
        let other = PbsParameters::try_from_config(changed).unwrap();
        let mut rng = StdRng::seed_from_u64(75);
        let mut untouched = StdRng::seed_from_u64(75);
        assert!(matches!(
            parameters.try_generate_lwe_return_key_with_parameters(
                other.key_switching(),
                &client,
                &mut rng
            ),
            Err(KeyGenerationError::IncompatibleKeySwitchingParameters)
        ));
        assert_eq!(rng.next_u64(), untouched.next_u64());
        assert!(matches!(
            parameters.check_lwe_return_key_with_parameters(other.key_switching(), &key),
            Err(primus_tfhe::TfheEvaluationError::IncompatibleLweReturnKey)
        ));
    }

    // Actual rows must match N, Q, target dimension, q and the complete basis.
    // Checking supplied parameter labels alone would miss these mismatches.
    for case in 0..6 {
        let mut changed = config();
        match case {
            0 => changed.bsk_poly_length = PolyLength::new(32),
            1 => changed.ring_modulus = ModulusConfig::Explicit(65537),
            2 => changed.external_lwe.dimension = LweDimension::new(9),
            3 => changed.external_lwe.cipher_modulus = ModulusConfig::Explicit(2048),
            4 => changed.key_switching.decomposition = decomposition(3),
            _ => {
                changed.key_switching.decomposition.level_count =
                    Some(DecompositionLevelCount::new(4))
            }
        }
        let other = PbsParameters::try_from_config(changed).unwrap();
        let other_key = other
            .try_generate_lwe_return_key(&return_client(&other), &mut rng)
            .unwrap();
        assert!(matches!(
            parameters.check_lwe_return_key(&other_key),
            Err(primus_tfhe::TfheEvaluationError::IncompatibleLweReturnKey)
        ));
        assert!(matches!(
            parameters.check_lwe_return_key_with_parameters(parameters.key_switching(), &other_key),
            Err(primus_tfhe::TfheEvaluationError::IncompatibleLweReturnKey)
        ));
    }
}

#[test]
fn return_generation_rejects_incompatible_secrets_before_sampling() {
    let parameters = PbsParameters::try_from_config(config()).unwrap();
    for expected in [
        TfheKeyError::LweSecretKeyModulusMismatch,
        TfheKeyError::ExternalLweDimensionMismatch,
        TfheKeyError::ClientSecretKeyDistributionMismatch,
        TfheKeyError::InvalidClientSecretKeyCoefficient,
        TfheKeyError::PolynomialLengthMismatch,
        TfheKeyError::AccumulatorSecretKeyDistributionMismatch,
        TfheKeyError::AccumulatorSecretOutsideLweModulus,
    ] {
        let mut s = vec![1; 8];
        let mut q = 1024;
        let mut s_distr = SecretKeyDistr::UniformBinary;
        let mut f = vec![0; 64];
        f[0] = 1;
        let mut f_distr = SecretKeyDistr::SparseTernary;
        match expected {
            TfheKeyError::LweSecretKeyModulusMismatch => q = 2048,
            TfheKeyError::ExternalLweDimensionMismatch => s.truncate(7),
            TfheKeyError::ClientSecretKeyDistributionMismatch => {
                s_distr = SecretKeyDistr::UniformTernary
            }
            TfheKeyError::InvalidClientSecretKeyCoefficient => s[0] = 2,
            TfheKeyError::PolynomialLengthMismatch => f.truncate(32),
            TfheKeyError::AccumulatorSecretKeyDistributionMismatch => {
                f_distr = SecretKeyDistr::UniformTernary
            }
            TfheKeyError::AccumulatorSecretOutsideLweModulus => f[0] = 1024,
        }
        let client = ClientKey::new(
            LweSecretKey::new(s, s_distr, PowOf2Modulus::new(q)),
            NtruSecretKey::new(f, f_distr),
        );
        // Both the configured and independent-component entry points must check
        // imported secrets before the lower-level key generator consumes RNG.
        for independent in [false, true] {
            let mut rng = StdRng::seed_from_u64(74);
            let mut untouched = StdRng::seed_from_u64(74);
            let result = if independent {
                parameters.try_generate_lwe_return_key_with_parameters(
                    parameters.key_switching(),
                    &client,
                    &mut rng,
                )
            } else {
                parameters.try_generate_lwe_return_key(&client, &mut rng)
            };
            assert!(
                matches!(result, Err(KeyGenerationError::ClientKey(error)) if error == expected)
            );
            assert_eq!(rng.next_u64(), untouched.next_u64());
        }
    }
}

#[test]
fn return_and_codecs_use_external_q_while_lut_uses_ring_q() {
    let parameters = PbsParameters::try_from_config(config()).unwrap();
    // A message override keeps q=1024, the external secret and its sampler;
    // no NTRU/return material is needed to bind either encryption client.
    let client = return_client(&parameters);
    let secret = client.external_lwe_secret_key();
    let mut rng = StdRng::seed_from_u64(76);
    let public_key = parameters
        .try_generate_public_key(secret, &mut rng)
        .unwrap();
    let private = parameters
        .encryptor_with_message_modulus(secret, 16)
        .unwrap();
    let public = parameters
        .public_encryptor_with_message_modulus(&public_key, 16)
        .unwrap();
    let decryptor = parameters
        .pbs_decryptor_with_message_modulus(secret, 16)
        .unwrap();
    for ciphertext in [
        private.encrypt(15, &mut rng).unwrap(),
        public.encrypt(15, &mut rng).unwrap(),
    ] {
        assert_eq!(decryptor.decrypt(ciphertext.as_view()).unwrap(), 15);
    }

    let codecs = parameters.pbs_codecs(parameters.messages()).unwrap();
    let table = parameters
        .lookup_table_compiler(&codecs)
        .unwrap()
        .compile_fn(|x| (x % 4) as u32)
        .unwrap();
    // Plateau boundaries at t_in=8, encoded at t_out=4 and Q=12289.
    // Checking midpoints also catches accidentally using t_out for input centers.
    for (index, expected) in [(0, 0), (8, 3072), (24, 6145), (40, 9217), (56, 0)] {
        assert_eq!(table.polynomial().as_ref()[index], expected);
    }
    assert_eq!(codecs.output_codec().decode_value(256), 1);
    assert_eq!(parameters.key_switching().basis().modulus(), Some(1024));
    assert_eq!(
        parameters
            .key_switching()
            .output()
            .noise_standard_deviation(),
        3.2
    );
    for (q, big_q, expected) in [
        (2048, 12289, LookupTableError::InputModulusMismatch),
        (1024, 65537, LookupTableError::OutputModulusMismatch),
    ] {
        let wrong = parameters
            .messages()
            .try_rounded_codecs(PowOf2Modulus::new(q), BarrettModulus::new(big_q))
            .unwrap();
        assert!(
            matches!(parameters.lookup_table_compiler(&wrong), Err(error) if error == expected)
        );
    }
}

#[test]
fn independent_cbs_material_must_match_ring_and_trace_modulus() {
    let pbs = PbsParameters::try_from_config(config()).unwrap();
    let cbs = CbsGadgetParameters::try_from_config(&pbs, gadget()).unwrap();
    let foreign_basis = ApproxSignedBasis::new(Some(65537), DecompositionBaseLog::new(2), None);
    assert!(matches!(
        CbsGadgetParameters::try_new(
            &pbs,
            foreign_basis,
            cbs.trace().clone(),
            cbs.scheme_switch().clone()
        ),
        Err(CircuitBootstrapParameterError::OutputBasisModulusMismatch)
    ));
    let mut changed = config();
    changed.bsk_poly_length = PolyLength::new(32);
    let other = PbsParameters::try_from_config(changed).unwrap();
    assert!(matches!(
        CbsGadgetParameters::try_new(
            &pbs,
            cbs.output_basis().clone(),
            other.blind_rotation().clone(),
            cbs.scheme_switch().clone()
        ),
        Err(CircuitBootstrapParameterError::PolynomialLengthMismatch { role: "trace" })
    ));
    changed = config();
    changed.ring_modulus = ModulusConfig::Explicit(65537);
    let other = PbsParameters::try_from_config(changed).unwrap();
    assert!(matches!(
        CbsGadgetParameters::try_new(
            &pbs,
            cbs.output_basis().clone(),
            cbs.trace().clone(),
            other.blind_rotation().clone()
        ),
        Err(CircuitBootstrapParameterError::CipherModulusMismatch {
            role: "scheme-switch"
        })
    ));
    changed.ring_modulus = ModulusConfig::Explicit(12288); // Valid even Barrett ring; modular trace cannot halve it.
    let even = PbsParameters::try_from_config(changed).unwrap();
    assert!(matches!(
        CbsGadgetParameters::try_from_config(&even, gadget()),
        Err(CircuitBootstrapParameterError::UnsupportedTraceModulus)
    ));
}

#[test]
fn one_hot_negative_rotation_has_left_closed_guard_and_zero_padding() {
    let cbs = CbsParameters::try_from_config(CbsConfig {
        projection: primus_tfhe_ntru::NtruProjectionMethod::Separate,
        pbs: config(),
        gadget: gadget(),
    })
    .unwrap();
    let pbs = cbs.pbs_parameters();
    let table = OneHotLookupTable::try_new(pbs, cbs.gadget(), cbs.input_codec()).unwrap();
    let coefficients = table.polynomial().as_ref();
    let n = 64i32;
    let weights: Vec<_> = cbs.gadget().output_basis().scalar_iter().collect();
    // Read the constant term of X^power*T using signed negacyclic indexing.
    let constant = |power: i32| {
        let index = (-power).rem_euclid(2 * n) as usize;
        let value = coefficients[index % n as usize];
        if index < n as usize {
            value
        } else {
            (12289 - value) % 12289
        }
    };
    let w = 4;
    let stride = 16;
    let a = 2;
    for message in 0..4 {
        for error in -a..a {
            let phase = message * stride + w * error;
            for selector in 0..4 {
                for level in 0..w {
                    let expected = if selector == message && level < 3 {
                        weights[level as usize]
                    } else {
                        0
                    };
                    assert_eq!(constant(selector * stride - level - phase), expected);
                }
            }
        }
    }
    // The excluded right endpoint of m=0 belongs to m=1, including r=0's zero result.
    assert_eq!(constant(-w * a), 0);
    assert_eq!(constant(stride - w * a), weights[0]);
    let too_wide = RoundedCodec::new(32, pbs.external_lwe().cipher_modulus());
    assert!(matches!(
        OneHotLookupTable::try_new(pbs, cbs.gadget(), &too_wide),
        Err(OneHotBootstrapError::InsufficientCapacity)
    ));
}
