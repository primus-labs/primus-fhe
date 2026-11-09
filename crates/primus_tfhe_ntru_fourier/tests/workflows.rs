//! Small deterministic consumers of the recommended public workflow.
//! n=8/N=128 are arithmetic regression parameters, not security profiles.
#![cfg(any(feature = "rustfft", feature = "tfhe-fft"))]

use primus_encoding::phase_error_magnitude;
use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_integer::AsFrom;
use primus_lattice::nlev::{NlevIter, NlevIterMut};
use primus_modulus::PowOf2Modulus;
use primus_ntru::{BlockOccupancy, LweDimension, SecretKeyDistr};
use primus_poly::{Polynomial, PolynomialIter};
use primus_shape::PolyLength;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_ntru_fourier::{
    BlindRotationMethod, CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig, LweConfig,
    ModulusConfig, PbsConfig, PbsMessageConfig, TfheContext, TfheContextError,
};
use rand::{SeedableRng, rngs::StdRng};

const SPARSE: BlindRotationMethod = BlindRotationMethod::Sparse {
    copy_count: 3,
    bucket_count: 8,
};

fn decomposition() -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: None,
    }
}

/// Keep rounding and transform error far below the test message spacing.
/// Sparse needs fixed-weight binary secrets; classic/block cases select their distributions below.
fn config<T: TorusFftValue>(method: BlindRotationMethod) -> PbsConfig<T, PowOf2Modulus<T>> {
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

/// Two message programs share a context, key and evaluator. Rounded output
/// at t=8 feeds padded input at t=8; the final full-domain t=16 result may not
/// feed a padded t=16 program. Ciphertexts carry no encoding metadata.
fn chained_pbs<T: TorusFftValue, Table: FftTable>(config: PbsConfig<T, PowOf2Modulus<T>>) {
    let context = TfheContext::<T, Table, _>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(101);
    // Client: only encrypted inputs and the evaluation key leave this side.
    let mut generator = primus_tfhe_ntru_fourier::KeyGenerator::new(&context);
    let client = generator.try_generate_client_key(&mut rng).unwrap();
    // Independent BR generation does not construct any return material.
    let blind_rotation = generator
        .try_generate_blind_rotation_key(&client, &mut rng)
        .unwrap();
    assert_eq!(
        blind_rotation.sparse_bootstrapping_key().is_some(),
        matches!(config.method, BlindRotationMethod::Sparse { .. }),
    );
    assert_eq!(
        blind_rotation.block_bootstrapping_key().is_some(),
        config.method == BlindRotationMethod::Block,
    );
    if let SecretKeyDistr::BlockBinary {
        block_size,
        occupancy,
    } = config.external_lwe.secret_key_distr
        && config.method == BlindRotationMethod::Block
    {
        assert_eq!(
            blind_rotation
                .block_bootstrapping_key()
                .unwrap()
                .occupancy(),
            occupancy
        );
        let mut other = config;
        other.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
            block_size,
            occupancy: if occupancy == BlockOccupancy::AtMostOne {
                BlockOccupancy::ExactlyOne
            } else {
                BlockOccupancy::AtMostOne
            },
        };
        let other = TfheContext::<T, Table, _>::try_from_pbs_config(other).unwrap();
        assert!(matches!(
            primus_tfhe_ntru_fourier::bootstrap::BootstrapResources::try_new(
                &other,
                &blind_rotation
            ),
            Err(primus_tfhe_ntru_fourier::TfheEvaluationError::IncompatibleBlindRotationKey)
        ));
    }
    let key_switching = context
        .parameters()
        .try_generate_lwe_return_key(&client, &mut rng)
        .unwrap();
    let server = primus_tfhe_ntru_fourier::ServerKey::new(blind_rotation, key_switching);
    let secret = client.external_lwe_secret_key();
    let first_messages = PbsMessageConfig::new(T::as_from(16)).with_output_modulus(T::as_from(8));
    let second_messages = PbsMessageConfig::new(T::as_from(8)).with_output_modulus(T::as_from(16));
    let encryptor = context
        .encryptor_with_message_modulus(secret, first_messages.input_modulus)
        .unwrap();
    let decryptor = context
        .pbs_decryptor_with_message_modulus(secret, second_messages.output_modulus)
        .unwrap();
    let default_decoder = context.pbs_decryptor(secret).unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: 16→8 then 8→16. Only the intermediate must stay in padded 0..4.
    let first = context
        .pbs_lookup_table_compiler_with_messages(first_messages)
        .unwrap()
        .compile_fn(|x| T::as_from((x + 1) % 4))
        .unwrap();
    let second = context
        .pbs_lookup_table_compiler_with_messages(second_messages)
        .unwrap()
        .compile_fn(|x| T::as_from(3 * x + 1))
        .unwrap();
    let mut evaluator = context.evaluator(&server).unwrap();
    let mut middle = context.allocate_lwe_ciphertext();
    let mut output = context.allocate_lwe_ciphertext();
    for x in [0, 7, 1, 2, 0] {
        encryptor
            .encrypt_padded_to(T::as_from(x), input.as_mut_view(), &mut rng)
            .unwrap();
        evaluator.apply_lookup_table_to(input.as_view(), &first, middle.as_mut_view());
        // The override leaves the default t=8 output decoder unchanged.
        assert_eq!(
            default_decoder.decrypt(middle.as_view()).unwrap(),
            T::as_from((x + 1) % 4)
        );
        evaluator.apply_lookup_table_to(middle.as_view(), &second, output.as_mut_view());
        assert_eq!(
            decryptor.decrypt(output.as_view()).unwrap(),
            T::as_from(3 * ((x + 1) % 4) + 1),
            "input {x}"
        );
    }
    // A returned 10 is valid at full t=16 but not in padded 0..8. Fresh input
    // rejects that value; a server cannot infer this violation from raw ciphertext.
    assert!(encryptor.encrypt_padded(T::as_from(10), &mut rng).is_err());
}

/// Three ManyLUT output lanes require a fourth padding lane. MVB uses one
/// integer output scale, consumed through the Scaled client factory. Nine MVB
/// outputs exercise a complete eight-output return tile and its trailing output.
fn many_lut_and_mvb<T: TorusFftValue, Table: FftTable>(mut config: PbsConfig<T, PowOf2Modulus<T>>) {
    // Keep the established small-parameter ManyLUT noise margin at t_in=8;
    // use different defaults to detect accidental fallback to config messages.
    config.messages = PbsMessageConfig::new(T::as_from(16));
    let context = TfheContext::<T, Table, _>::try_from_pbs_config(config).unwrap();
    check_many_lut_and_mvb(&context);
}

/// Consume the same public programs from PBS-only and split-CBS contexts.
/// This checks that the BR precision selected for CBS also owns strided PBS/MVB.
fn check_many_lut_and_mvb<T: TorusFftValue, Table: FftTable>(
    context: &TfheContext<T, Table, PowOf2Modulus<T>>,
) {
    let mut rng = StdRng::seed_from_u64(102);
    // Client: programs explicitly use 8→4; outputs use different encodings.
    let (client, server) = context.try_generate_keys(&mut rng).unwrap();
    let secret = client.external_lwe_secret_key();
    let messages = PbsMessageConfig::new(T::as_from(8)).with_output_modulus(T::as_from(4));
    let encryptor = context
        .encryptor_with_message_modulus(secret, messages.input_modulus)
        .unwrap();
    let rounded = context
        .pbs_decryptor_with_message_modulus(secret, messages.output_modulus)
        .unwrap();
    let scaled = context
        .ring_return_decryptor(secret, messages.output_modulus)
        .unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: input-dependent outputs, deliberately different in adjacent lanes.
    let function = |x: usize, lane: usize| T::as_from((x * (lane + 1) + lane + lane / 4) % 4);
    let lut = context
        .pbs_lookup_table_compiler_with_messages(messages)
        .unwrap()
        .compile_interleaved_fn(3, function)
        .unwrap();
    let program = context
        .compile_mvb_fn_with_messages(messages, 4, 9, function)
        .unwrap();
    let mut pbs = context.evaluator(&server).unwrap();
    let mut mvb = context.mvb_evaluator(&server).unwrap();
    let mut lanes = vec![context.allocate_lwe_ciphertext(); 3];
    let mut factors = vec![context.allocate_lwe_ciphertext(); 9];

    // Equal parameters do not make a separately prepared transform program reusable.
    // Reject its binding before writing any of the caller's outputs.
    let other =
        TfheContext::<T, Table, _>::try_from_parameters(context.parameters().clone()).unwrap();
    let foreign = other
        .compile_mvb_fn_with_messages(messages, 4, 9, function)
        .unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mvb.apply_lookup_table_to(input.as_view(), &foreign, &mut factors);
        }))
        .is_err()
    );
    assert!(
        factors
            .iter()
            .all(|ct| ct.as_ref().iter().all(|&v| v == T::ZERO))
    );

    for x in [0, 3, 1, 2] {
        encryptor
            .encrypt_padded_to(T::as_from(x), input.as_mut_view(), &mut rng)
            .unwrap();
        pbs.apply_interleaved_lookup_table_to(input.as_view(), &lut, &mut lanes);
        mvb.apply_lookup_table_to(input.as_view(), &program, &mut factors);
        for (i, output) in lanes.iter().enumerate() {
            assert_eq!(
                rounded.decrypt(output.as_view()).unwrap(),
                function(x, i),
                "ManyLUT input {x}, lane {i}"
            );
        }
        for (i, output) in factors.iter().enumerate() {
            assert_eq!(
                scaled.decrypt(output.as_view()).unwrap(),
                function(x, i),
                "MVB input {x}, factor {i}"
            );
        }
    }
}

/// NGSW phase is bit*g_l*f, including every secret coefficient (unlike NLEV).
/// scalar/16 is only a regression tolerance for these fixed small fixtures.
fn assert_ngsw_phase<T: primus_integer::FheUint, M: primus_reduce::RingContext<T>>(
    phase: &[T],
    secret: &[T::SignedInteger],
    bit: T,
    scalar: T,
    modulus: M,
) {
    let weight = modulus.reduce_mul(bit, scalar);
    for (&actual, &coefficient) in phase.iter().zip(secret) {
        let expected = modulus.reduce_mul(weight, modulus.encode_signed(coefficient));
        assert!(
            phase_error_magnitude(actual, expected, modulus) <= scalar >> 4u32,
            "actual {actual:?}, expected {expected:?}, scalar {scalar:?}"
        );
    }
}

/// Consume the bootstrapped predicate in CMux, then check every coefficient.
fn circuit_selection<T: TorusFftValue, Table: FftTable>(pbs: PbsConfig<T, PowOf2Modulus<T>>) {
    let context = TfheContext::<T, Table, _>::try_from_pbs_config(pbs).unwrap();
    let mut rng = StdRng::seed_from_u64(if pbs.method == BlindRotationMethod::Block {
        106
    } else {
        103
    });
    // PBS-only setup rejects CBS key generation until the gadgets are added.
    assert!(matches!(
        context.try_generate_circuit_bootstrap_keys(&mut rng),
        Err(primus_tfhe_ntru::KeyGenerationError::MissingCircuitBootstrapParameters)
    ));
    let context = context
        .try_with_circuit_bootstrap(CbsGadgetConfig {
            trace: decomposition(),
            scheme_switch: decomposition(),
            output: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(4),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
        })
        .unwrap();
    // Client: encrypt nonconstant candidate polynomials under the ring secret.
    let (client, server) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    if let SecretKeyDistr::BlockBinary {
        block_size,
        occupancy: BlockOccupancy::AtMostOne,
    } = pbs.external_lwe.secret_key_distr
    {
        assert!(
            client.external_lwe_secret_key().as_ref()[..block_size]
                .iter()
                .all(|&s| s == T::ZERO)
        );
    }
    let encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
    let mut ring_client = context
        .accumulator_client(client.accumulator_ntru_secret_key(), T::as_from(8))
        .unwrap();
    // Avoid a short periodic pattern that could hide an incorrect coefficient rotation.
    let messages: Vec<Vec<T>> = (0..4)
        .map(|r| {
            (0..128)
                .map(|i| T::as_from(((i >> r) + i / 7 + r) % 4))
                .collect()
        })
        .collect();
    let candidates: Vec<_> = messages
        .iter()
        .map(|m| ring_client.encrypt(m, &mut rng))
        .collect();
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![T::ZERO; 128];

    // Server: custom F=[m>=2], then choose the encrypted branch.
    let program = context
        .compile_cbs_fn(|m| T::as_from(usize::from(m >= 2)))
        .unwrap();
    let mut cbs = context
        .circuit_bootstrap_evaluator_with_lookup_table(&server, program)
        .unwrap();
    let mut control = cbs.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();
    let n = context.parameters().poly_length().get();
    let modulus = context.parameters().accumulator_ntru().cipher_modulus();
    let secret = client.accumulator_ntru_secret_key();
    let basis = context.cbs_parameters().unwrap().gadget().output_basis();
    // GLWE MSB programs carry a post-trace correction that NTRU does not
    // implement. Reject even at the advanced binding boundary, with matching
    // q/Q, shape and output basis (independently of the context's message t).
    let input_codec = primus_encoding::RoundedCodec::new(
        T::TWO,
        context.parameters().external_lwe().cipher_modulus(),
    );
    let msb = primus_tfhe::CircuitBootstrapLookupTable::try_from_fn(
        context.parameters().poly_length(),
        &input_codec,
        primus_tfhe::CbsInputEncoding::MsbBoolean,
        basis,
        modulus,
        T::as_from,
    )
    .unwrap();
    assert!(matches!(
        primus_tfhe_ntru_fourier::circuit_bootstrap::CircuitBootstrapEvaluator::try_with_lookup_table(
            &context,
            server.circuit_bootstrap_key(), msb,
        ),
        Err(primus_tfhe::TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable)
    ));
    let mut phase = Polynomial::new(vec![T::ZERO; n]);
    let mut probe = context.allocate_accumulator_ciphertext();
    let mut fft = context.new_fft_engine();
    let transformed =
        primus_ntru::FourierNtruSecretKey::try_from_coeff_secret_key(secret, &mut fft).unwrap();
    let mut decrypt_workspace =
        primus_ntru::FourierNtruDecryptWorkspace::new(context.parameters().poly_length());
    let mut transformed_probe =
        primus_lattice::ntru::FourierNtru::new(vec![primus_fft::Complex64::default(); n / 2]);
    for m in [0, 3, 1, 2] {
        encryptor
            .encrypt_padded_to(T::as_from(m), input.as_mut_view(), &mut rng)
            .unwrap();
        cbs.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
        let bit = T::as_from(usize::from(m >= 2));
        for (row, scalar) in control.iter_ntru(n / 2).zip(basis.scalar_iter()) {
            transformed.decrypt_phase_to(&row, &mut phase, &mut fft, &mut decrypt_workspace);
            assert_ngsw_phase(phase.as_ref(), secret.as_slice(), bit, scalar, modulus);
            // Consume each level independently before the encrypted t8 CMux.
            probe.as_mut().fill(T::ZERO);
            probe.as_mut()[0] = scalar;
            cbs.external_product_to(control.as_view(), probe.as_view(), selected.as_mut_view());
            selected.write_fourier_form(&mut transformed_probe, &mut fft);
            transformed.decrypt_phase_to(
                &transformed_probe,
                &mut phase,
                &mut fft,
                &mut decrypt_workspace,
            );
            assert_ngsw_phase(phase.as_ref(), secret.as_slice(), bit, scalar, modulus);
        }
        cbs.cmux_to(
            control.as_view(),
            candidates[0].as_view(),
            candidates[1].as_view(),
            selected.as_mut_view(),
        );
        ring_client.decrypt_to(&selected, &mut decoded);
        assert_eq!(decoded, messages[usize::from(m >= 2)], "CBS input {m}");
    }

    // Equal numeric domains do not establish the operation/resource identity.
    // Reject before writing, then transfer the original CBS resources to PBS.
    let other =
        TfheContext::<T, Table, _>::try_from_parameters(context.parameters().clone()).unwrap();
    let mut foreign = server.bootstrap_resources(&other).unwrap();
    let (mut operation, resources) = cbs.into_parts();
    control.as_mut().fill(Default::default());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        operation.circuit_bootstrap_to(input.as_view(), &mut control, &mut foreign);
    }));
    assert!(result.is_err());
    assert!(control.as_ref().iter().all(|v| *v == Default::default()));
    assert!(matches!(
        primus_tfhe_ntru_fourier::Evaluator::try_from_resources(
            &context,
            foreign,
            server.server_key(),
        ),
        Err(primus_tfhe::TfheEvaluationError::IncompatibleLweReturnKey)
    ));
    let mut pbs = primus_tfhe_ntru_fourier::Evaluator::try_from_resources(
        &context,
        resources,
        server.server_key(),
    )
    .unwrap();
    // Consume the last real CBS→CMux result at both extraction endpoints.
    let mut returned_ring = context.allocate_lwe_ciphertext();
    let ring_decryptor = context
        .ring_return_decryptor(client.external_lwe_secret_key(), T::as_from(8))
        .unwrap();
    for index in [0, 1, n - 1] {
        pbs.return_ring_at_to(selected.as_view(), index, returned_ring.as_mut_view());
        assert_eq!(
            ring_decryptor.decrypt(returned_ring.as_view()).unwrap(),
            messages[1][index]
        );
    }
    let identity = context
        .pbs_lookup_table_compiler()
        .unwrap()
        .compile_fn(T::as_from)
        .unwrap();
    let returned = pbs.apply_lookup_table(input.as_view(), &identity);
    let decryptor = context
        .pbs_decryptor(client.external_lwe_secret_key())
        .unwrap();
    assert_eq!(
        decryptor.decrypt(returned.as_view()).unwrap(),
        T::as_from(2)
    );

    // Reuse the same key for four-way selection; m=0 exercises the default branch.
    let mut one_hot = context.one_hot_evaluator(&server).unwrap();
    let mut selectors = one_hot.allocate_nonzero_ngsw_output();
    for m in [0, 3, 1, 2, 0] {
        encryptor
            .encrypt_padded_to(T::as_from(m), input.as_mut_view(), &mut rng)
            .unwrap();
        one_hot.one_hot_nonzero_ngsw_to(input.as_view(), &mut selectors);
        one_hot.cmux_k_to(
            one_hot.nonzero_ngsw_selectors(&selectors),
            candidates[0].as_view(),
            &candidates[1..],
            selected.as_mut_view(),
        );
        ring_client.decrypt_to(&selected, &mut decoded);
        assert_eq!(decoded, messages[m], "one-hot input {m}");
        if context.parameters().blind_rotation_method() == BlindRotationMethod::Block && m == 3 {
            // Both dual entry points retain the same coefficient NLEV controls.
            // Consume them as a public-polynomial lift instead of only comparing bytes.
            let mut standalone = one_hot.allocate_nlev_output();
            let mut nlev = one_hot.allocate_nlev_output();
            let mut full = one_hot.allocate_ngsw_output();
            one_hot.one_hot_nlev_to(input.as_view(), &mut standalone);
            one_hot.one_hot_nlev_and_nonzero_ngsw_to(input.as_view(), &mut nlev, &mut selectors);
            assert_eq!(nlev, standalone);
            one_hot.one_hot_to(input.as_view(), &mut nlev, &mut full);
            assert_eq!(nlev, standalone);
            assert_eq!(&full[one_hot.ngsw_selector_len()..], selectors);
            let scalar = basis.scalar_iter().next().unwrap();
            let polynomial = Polynomial::new(
                (0..n)
                    .map(|i| if i % 3 == 0 { scalar } else { T::ZERO })
                    .collect::<Vec<_>>(),
            );
            let mut product = primus_ntru::FourierNtruExternalProductWorkspace::new(
                context.parameters().poly_length(),
            );
            let mut transformed_control = primus_lattice::nlev::FourierNlev::new(vec![
                primus_fft::Complex64::default();
                basis.level_count().get() * n / 2
            ]);
            for selector in [0, m] {
                let control = one_hot.nlev_selectors(&nlev).selector(selector).unwrap();
                control.write_fourier_form(&mut transformed_control, &mut fft);
                transformed_control.external_product_to(
                    &polynomial,
                    &mut selected,
                    basis,
                    &mut fft,
                    &mut product,
                );
                selected.write_fourier_form(&mut transformed_probe, &mut fft);
                transformed.decrypt_phase_to(
                    &transformed_probe,
                    &mut phase,
                    &mut fft,
                    &mut decrypt_workspace,
                );
                for (&actual, &value) in phase.as_ref().iter().zip(polynomial.as_ref()) {
                    let expected = if selector == m { value } else { T::ZERO };
                    assert!(phase_error_magnitude(actual, expected, modulus) <= scalar >> 4u32);
                }
            }
            // Consume the dual NGSW result after the NLEV lift dirtied all scratch.
            one_hot.cmux_k_to(
                one_hot.nonzero_ngsw_selectors(&selectors),
                candidates[0].as_view(),
                &candidates[1..],
                selected.as_mut_view(),
            );
            ring_client.decrypt_to(&selected, &mut decoded);
            assert_eq!(decoded, messages[m], "dual one-hot input {m}");
        }
    }
    let mut inputs = [input.clone(), input.clone(), input];
    for (message, input) in [0, 3, 1].into_iter().zip(&mut inputs) {
        encryptor
            .encrypt_padded_to(T::as_from(message), input.as_mut_view(), &mut rng)
            .unwrap();
    }
    assert_pair_matches_single(
        one_hot,
        inputs.each_ref().map(|input| input.as_view()),
        context.parameters().blind_rotation_method() != BlindRotationMethod::Classic,
    );
}

/// Pair callbacks and odd single tails preserve projection strategy and dirty-buffer reuse.
fn assert_pair_matches_single<T: TorusFftValue, Table: FftTable>(
    one_hot: primus_tfhe_ntru_fourier::OneHotEvaluator<'_, T, Table>,
    inputs: [primus_tfhe_ntru_fourier::Lwe<&[T]>; 3],
    has_pair: bool,
) {
    let (mut operation, mut resources) = one_hot.into_parts();
    let mut pair = operation.new_pair_workspace(&resources);
    assert_eq!(pair.is_some(), has_pair);
    let mut nlev = operation.allocate_nlev_output();
    let mut ngsw = operation.allocate_nonzero_ngsw_output();
    let mut expected_nlev = [nlev.clone(), nlev.clone(), nlev.clone()];
    let mut expected_ngsw = [ngsw.clone(), ngsw.clone(), ngsw.clone()];
    // An unwinding consumer must not leave the borrowed accumulator swapped out.
    if let Some(pair) = &mut pair {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            operation.with_pair(
                [inputs[0].as_view(), inputs[1].as_view()],
                pair,
                &mut resources,
                |_, projection| {
                    projection.project_to(None, Some(ngsw.as_mut_slice()));
                    panic!("intentional projection consumer failure");
                },
            );
        }));
        assert!(result.is_err());
    }
    for (with_nlev, with_ngsw) in [(false, true), (true, false), (true, true)] {
        for (i, input) in inputs.iter().enumerate() {
            match (with_nlev, with_ngsw) {
                (true, true) => operation.one_hot_nlev_and_nonzero_ngsw_to(
                    input.as_view(),
                    &mut expected_nlev[i],
                    &mut expected_ngsw[i],
                    &mut resources,
                ),
                (true, false) => operation.one_hot_nlev_to(
                    input.as_view(),
                    &mut expected_nlev[i],
                    &mut resources,
                ),
                _ => operation.one_hot_nonzero_ngsw_to(
                    input.as_view(),
                    &mut expected_ngsw[i],
                    &mut resources,
                ),
            }
        }
        let first_single = if let Some(pair) = &mut pair {
            let mut visited = 0;
            operation.with_pair(
                [inputs[0].as_view(), inputs[1].as_view()],
                pair,
                &mut resources,
                |i, projection| {
                    assert_eq!(i, visited);
                    visited += 1;
                    projection.project_to(
                        with_nlev.then_some(nlev.as_mut_slice()),
                        with_ngsw.then_some(ngsw.as_mut_slice()),
                    );
                    if with_nlev {
                        assert_eq!(nlev, expected_nlev[i]);
                    }
                    if with_ngsw {
                        assert_eq!(ngsw, expected_ngsw[i]);
                    }
                },
            );
            assert_eq!(visited, 2);
            2
        } else {
            0
        };
        for (i, input) in inputs.iter().enumerate().skip(first_single) {
            match (with_nlev, with_ngsw) {
                (true, true) => operation.one_hot_nlev_and_nonzero_ngsw_to(
                    input.as_view(),
                    &mut nlev,
                    &mut ngsw,
                    &mut resources,
                ),
                (true, false) => {
                    operation.one_hot_nlev_to(input.as_view(), &mut nlev, &mut resources)
                }
                _ => operation.one_hot_nonzero_ngsw_to(input.as_view(), &mut ngsw, &mut resources),
            }
            if with_nlev {
                assert_eq!(nlev, expected_nlev[i]);
            }
            if with_ngsw {
                assert_eq!(ngsw, expected_ngsw[i]);
            }
        }
    }
}

#[test]
fn u32_classic_chain() {
    let mut config = config(BlindRotationMethod::Classic);
    config.external_lwe.secret_key_distr = SecretKeyDistr::UniformBinary;
    #[cfg(feature = "rustfft")]
    chained_pbs::<u32, primus_fft::RustFftTable>(config);
    #[cfg(feature = "tfhe-fft")]
    chained_pbs::<u32, primus_fft::TfheFftTable>(config);

    // Classic controls also consume correlated block-binary secrets unchanged.
    config.external_lwe.dimension = LweDimension::new(6);
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        config.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
            block_size: 3,
            occupancy,
        };
        #[cfg(feature = "rustfft")]
        chained_pbs::<u32, primus_fft::RustFftTable>(config);
        #[cfg(feature = "tfhe-fft")]
        chained_pbs::<u32, primus_fft::TfheFftTable>(config);
    }
}

#[cfg(feature = "rustfft")]
#[test]
fn rustfft_u32_ternary_batches() {
    let mut config = config(BlindRotationMethod::Classic);
    config.external_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    many_lut_and_mvb::<u32, primus_fft::RustFftTable>(config);
}

#[cfg(feature = "rustfft")]
#[test]
fn rustfft_u32_classic_cbs() {
    let mut config = config(BlindRotationMethod::Classic);
    config.external_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    circuit_selection::<u32, primus_fft::RustFftTable>(config);
}

#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_u64_sparse_chain() {
    let config = config(SPARSE);
    chained_pbs::<u64, primus_fft::TfheFftTable>(config);
}

#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_u64_sparse_batches() {
    let config = config(SPARSE);
    many_lut_and_mvb::<u64, primus_fft::TfheFftTable>(config);
}

#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_u64_sparse_cbs() {
    let config = config(SPARSE);
    circuit_selection::<u64, primus_fft::TfheFftTable>(config);
}

/// The direct-block ordinary path consumes independent q/Q, unequal message
/// spaces, interleaved lanes, and CBS controls all the way back to LWE.
#[test]
fn u64_block_workflows() {
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        let mut pbs = config(BlindRotationMethod::Block);
        pbs.external_lwe.dimension = LweDimension::new(10);
        pbs.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
            block_size: 5,
            occupancy,
        };
        #[cfg(feature = "rustfft")]
        {
            chained_pbs::<u64, primus_fft::RustFftTable>(pbs);
            many_lut_and_mvb::<u64, primus_fft::RustFftTable>(pbs);
            circuit_selection::<u64, primus_fft::RustFftTable>(pbs);
        }
        #[cfg(feature = "tfhe-fft")]
        {
            chained_pbs::<u64, primus_fft::TfheFftTable>(pbs);
            many_lut_and_mvb::<u64, primus_fft::TfheFftTable>(pbs);
            circuit_selection::<u64, primus_fft::TfheFftTable>(pbs);
        }
    }
}

/// Exact schoolbook native phase of a stored coefficient row. This oracle
/// deliberately avoids FFT inversion so a rounded reconstruction cannot hide here.
fn native_phase<T: TorusFftValue>(ciphertext: &[T], secret: &[T::SignedInteger]) -> Vec<T> {
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

const NATIVE_TEST_N: usize = 64;
const NATIVE_TEST_SUPPORT: [usize; 2] = [0, 4];

fn native_control_fixture<T: TorusFftValue, Table: FftTable>(
    method: BlindRotationMethod,
) -> (
    TfheContext<T, Table, PowOf2Modulus<T>>,
    primus_tfhe_ntru_fourier::ClientKey<T>,
) {
    let mut config = config::<T>(method);
    config.bsk_poly_length = PolyLength::new(NATIVE_TEST_N);
    config.bsk_secret_distr = SecretKeyDistr::Gaussian {
        standard_deviation: 1.0,
    };
    let context = TfheContext::try_from_pbs_config(config).unwrap();
    let external = context.parameters().external_lwe();
    let mut input = vec![T::ZERO; external.dimension().get()];
    for index in NATIVE_TEST_SUPPORT {
        input[index] = T::ONE;
    }
    let mut ring = vec![T::SignedInteger::as_from(0i32); NATIVE_TEST_N];
    ring[0] = T::SignedInteger::as_from(1i32);
    ring[1] = T::SignedInteger::as_from(2i32);
    let client = primus_tfhe_ntru_fourier::ClientKey::new(
        primus_lwe::LweSecretKey::new(
            input,
            external.secret_key_distr(),
            external.cipher_modulus(),
        ),
        primus_ntru::NtruSecretKey::new(ring, config.bsk_secret_distr),
    );
    (context, client)
}

fn check_public_native_control_spectra<T: TorusFftValue, Table: FftTable>() {
    let (context, client) = native_control_fixture::<T, Table>(BlindRotationMethod::Classic);
    let parameters = context.parameters().blind_rotation();
    let n = NATIVE_TEST_N;
    let mut fft = context.new_fft_engine();
    let mut generator = primus_tfhe_ntru_fourier::KeyGenerator::new(&context);

    // (1+2X) * sum((-2X)^k, k=0..N) = 1+2^N in the negacyclic ring.
    // N >= T::BITS, so the finite geometric series is the native inverse.
    let inverse = (0..n)
        .scan(T::ONE, |power, _| {
            let coefficient = power.cast_to_signed();
            *power = power.wrapping_mul(T::as_from(-2i32));
            Some(coefficient)
        })
        .collect::<Vec<_>>();
    let f = client.accumulator_ntru_secret_key().as_slice();
    let inverse_words = inverse
        .iter()
        .map(|&value| T::cast_from_signed(value))
        .collect::<Vec<_>>();
    let mut unit = vec![T::ZERO; n];
    unit[0] = T::ONE;
    assert_eq!(native_phase(&inverse_words, f), unit);

    let row_len = fft.fourier_length();
    let mut expected_spectrum = vec![Complex64::default(); row_len];
    let mut assert_spectra = |label: &str, values: &[Complex64], bit, lift, rng: &mut StdRng| {
        assert_eq!(values.len(), parameters.fourier_nlev_len());
        for (level, (actual, scalar)) in values
            .chunks_exact(row_len)
            .zip(parameters.basis().scalar_iter())
            .enumerate()
        {
            let mut noise = parameters
                .encryption_parameters()
                .noise_distribution()
                .sample_vec(n, rng);
            if lift && bit {
                noise[0] = noise[0].wrapping_add(scalar);
            }
            let mut coefficients = native_phase(&noise, &inverse);
            if !lift && bit {
                coefficients[0] = coefficients[0].wrapping_add(scalar);
            }
            fft.forward_as_torus(&coefficients, &mut expected_spectrum);
            assert_eq!(actual, expected_spectrum, "{label}, level {level}");
        }
    };

    let mut rng = StdRng::seed_from_u64(0x50C);
    let mut reference_rng = StdRng::seed_from_u64(0x50C);
    let key = generator
        .try_generate_blind_rotation_key(&client, &mut rng)
        .unwrap();
    let controls = key.classic_controls().unwrap();
    assert_spectra(
        "initializer",
        controls.initializer().as_ref(),
        true,
        true,
        &mut reference_rng,
    );
    let (first, negative) = controls.first_controls();
    assert!(negative.is_none());
    assert_spectra(
        "first control",
        first.as_ref(),
        true,
        true,
        &mut reference_rng,
    );
    let remaining = controls.remaining_controls();
    assert_eq!(remaining.len(), client.external_lwe_dimension() - 1);
    for (i, control) in remaining.enumerate() {
        assert_spectra(
            "NGSW control",
            control.as_ref(),
            NATIVE_TEST_SUPPORT.contains(&(i + 1)),
            false,
            &mut reference_rng,
        );
    }

    let mut rng = StdRng::seed_from_u64(0x11F7);
    let mut reference_rng = StdRng::seed_from_u64(0x11F7);
    let lift = generator
        .try_generate_public_lift_key(client.accumulator_ntru_secret_key(), parameters, &mut rng)
        .unwrap();
    assert_spectra("public lift", lift.as_ref(), true, true, &mut reference_rng);
}

fn check_sparse_native_control_phases<T: TorusFftValue, Table: FftTable>() {
    use primus_tfhe::sparse::BucketMap;

    let (context, client) = native_control_fixture::<T, Table>(SPARSE);
    let parameters = context.parameters().blind_rotation();
    let mut generator = primus_tfhe_ntru_fourier::KeyGenerator::new(&context);
    let mut rng = StdRng::seed_from_u64(0x5A2);
    let mut reference_rng = StdRng::seed_from_u64(0x5A2);
    let key = generator
        .try_generate_blind_rotation_key(&client, &mut rng)
        .unwrap();
    let sparse = key.sparse_bootstrapping_key().unwrap();
    let (map, selected) = BucketMap::try_generate(
        client.external_lwe_dimension(),
        sparse.copy_count(),
        sparse.bucket_count(),
        &NATIVE_TEST_SUPPORT,
        &mut reference_rng,
    )
    .unwrap();
    let f = client.accumulator_ntru_secret_key().as_slice();
    for (bucket, &chosen) in selected.iter().enumerate() {
        let (indices, controls) = sparse.bucket_data(bucket);
        assert_eq!(
            indices,
            &map.input_indices()[map.bucket_offsets()[bucket]..map.bucket_offsets()[bucket + 1]]
        );
        assert_eq!(controls.len(), (indices.len() + 1) * parameters.nlev_len());
        for (control, index) in controls
            .chunks_exact(parameters.nlev_len())
            .zip(indices.iter().copied().chain([BucketMap::UNASSIGNED]))
        {
            let (rows, tail) = control.as_chunks::<NATIVE_TEST_N>();
            assert!(tail.is_empty());
            for (row, scalar) in rows.iter().zip(parameters.basis().scalar_iter()) {
                let mut expected = parameters
                    .encryption_parameters()
                    .noise_distribution()
                    .sample_vec(NATIVE_TEST_N, &mut reference_rng);
                if index == chosen {
                    if bucket == 0 {
                        expected[0] = expected[0].wrapping_add(scalar);
                    } else {
                        for (phase, &coefficient) in expected.iter_mut().zip(f) {
                            *phase = phase.wrapping_add(
                                scalar.wrapping_mul(T::cast_from_signed(coefficient)),
                            );
                        }
                    }
                }
                assert_eq!(
                    native_phase(row, f),
                    expected,
                    "bucket {bucket}, input {index}"
                );
            }
        }
    }
}

#[test]
fn public_native_control_spectra() {
    #[cfg(feature = "rustfft")]
    {
        check_public_native_control_spectra::<u32, primus_fft::RustFftTable>();
        check_public_native_control_spectra::<u64, primus_fft::RustFftTable>();
    }
    #[cfg(feature = "tfhe-fft")]
    {
        check_public_native_control_spectra::<u32, primus_fft::TfheFftTable>();
        check_public_native_control_spectra::<u64, primus_fft::TfheFftTable>();
    }
}

#[test]
fn sparse_native_control_phases() {
    #[cfg(feature = "rustfft")]
    {
        check_sparse_native_control_phases::<u32, primus_fft::RustFftTable>();
        check_sparse_native_control_phases::<u64, primus_fft::RustFftTable>();
    }
    #[cfg(feature = "tfhe-fft")]
    {
        check_sparse_native_control_phases::<u32, primus_fft::TfheFftTable>();
        check_sparse_native_control_phases::<u64, primus_fft::TfheFftTable>();
    }
}

/// Empty first blocks still carry NLEV lift rows; later blocks carry NGSW.
/// Check exact coefficient phases and reject malformed imported support pre-RNG.
fn check_block_coefficients<Table: FftTable>(occupancy: BlockOccupancy) {
    use primus_tfhe_ntru_fourier::{ClientKey, KeyGenerationError, KeyGenerator, TfheKeyError};
    use rand::Rng;

    let mut pbs = config::<u64>(BlindRotationMethod::Block);
    pbs.external_lwe.dimension = LweDimension::new(6);
    pbs.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
        block_size: 3,
        occupancy,
    };
    pbs.bsk_poly_length = PolyLength::new(32);
    let gadget = CbsGadgetConfig {
        trace: decomposition(),
        scheme_switch: decomposition(),
        output: decomposition(),
    };
    let context = TfheContext::<u64, Table, _>::try_from_pbs_config(pbs)
        .unwrap()
        .try_with_circuit_bootstrap(gadget)
        .unwrap();
    let mut generator = KeyGenerator::new(&context);
    let mut f = vec![0i64; 32];
    f[..3].fill(1);
    let client = |support| {
        ClientKey::new(
            primus_lwe::LweSecretKey::new(
                support,
                pbs.external_lwe.secret_key_distr,
                context.parameters().external_lwe().cipher_modulus(),
            ),
            primus_ntru::NtruSecretKey::new(f.clone(), pbs.bsk_secret_distr),
        )
    };
    let mut rng = StdRng::seed_from_u64(0xB30);
    let mut untouched = StdRng::seed_from_u64(0xB30);
    let invalid = client(vec![1, 1, 0, 0, 0, 0]);
    let expected = Some(KeyGenerationError::ClientKey(
        TfheKeyError::InvalidClientSecretKeyBlock,
    ));
    assert_eq!(
        generator
            .try_generate_blind_rotation_key(&invalid, &mut rng)
            .err(),
        expected
    );
    assert_eq!(
        generator.try_generate_server_key(&invalid, &mut rng).err(),
        expected
    );
    assert_eq!(
        generator
            .try_generate_circuit_bootstrap_server_key(&invalid, &mut rng)
            .err(),
        expected
    );
    assert_eq!(rng.next_u64(), untouched.next_u64());

    let control_len = context.parameters().blind_rotation().nlev_len();
    let has_dummy = occupancy == BlockOccupancy::AtMostOne;
    let supports = if has_dummy {
        [vec![0, 0, 0, 0, 1, 0], vec![0; 6]]
    } else {
        [vec![1, 0, 0, 0, 1, 0], vec![0, 0, 1, 0, 0, 1]]
    };
    for support in supports {
        let client = client(support.clone());
        let key = generator
            .try_generate_blind_rotation_key(&client, &mut rng)
            .unwrap();
        let block = key.block_bootstrapping_key().unwrap();
        assert!(key.sparse_bootstrapping_key().is_none());
        assert_eq!(block.block_count(), 2);
        for block_index in 0..2 {
            let (range, coefficients) = block.block_data(block_index);
            let occupied = support[range.clone()].iter().copied().sum::<u64>();
            for (row, bit) in NlevIter::new(coefficients, control_len).zip(
                support[range]
                    .iter()
                    .copied()
                    .chain(has_dummy.then_some(1 - occupied)),
            ) {
                for (polynomial, scalar) in PolynomialIter::new(row.as_ref(), 32)
                    .zip(context.parameters().blind_rotation().basis().scalar_iter())
                {
                    let phase = native_phase(polynomial.as_ref(), &f);
                    for (i, actual) in phase.into_iter().enumerate() {
                        let message = if block_index == 0 {
                            u64::from(i == 0)
                        } else {
                            f[i] as u64
                        };
                        let expected = scalar.wrapping_mul(bit).wrapping_mul(message);
                        // sigma=0.7 has truncated support below this fixed margin.
                        // A Fourier ciphertext round trip has far larger phase error.
                        assert!(
                            actual
                                .wrapping_sub(expected)
                                .min(expected.wrapping_sub(actual))
                                <= 16
                        );
                    }
                }
            }
        }
    }

    // Precision changes only the online transform, not the exact coefficient
    // material or fresh encryption coins. Equality here is a representation
    // regression check; it does not certify Fourier error or a parameter DFR.
    let split_br = primus_tfhe_ntru_fourier::CbsConfig {
        pbs,
        gadget,
        projection: primus_tfhe_ntru_fourier::NtruProjectionMethod::Separate,
        fourier_precision: primus_tfhe_ntru_fourier::FourierCbsPrecision {
            blind_rotation: primus_tfhe_ntru_fourier::FourierPrecision::Split { low_bits: 40 },
            trace: primus_tfhe_ntru_fourier::FourierPrecision::Ordinary,
            scheme_switch: primus_tfhe_ntru_fourier::FourierPrecision::Ordinary,
        },
    };
    let split_context = TfheContext::<u64, Table, _>::try_from_cbs_config(split_br).unwrap();
    let mut split_generator = KeyGenerator::new(&split_context);
    let client = client(vec![1, 0, 0, 0, 1, 0]);
    let mut ordinary_rng = StdRng::seed_from_u64(0xB3C);
    let mut split_rng = StdRng::seed_from_u64(0xB3C);
    let ordinary_key = generator
        .try_generate_blind_rotation_key(&client, &mut ordinary_rng)
        .unwrap();
    let split_key = split_generator
        .try_generate_blind_rotation_key(&client, &mut split_rng)
        .unwrap();
    assert_eq!(
        ordinary_key
            .block_bootstrapping_key()
            .unwrap()
            .controls()
            .as_slice(),
        split_key
            .block_bootstrapping_key()
            .unwrap()
            .controls()
            .as_slice(),
    );
    let next_ordinary = ordinary_rng.next_u64();
    assert_eq!(next_ordinary, split_rng.next_u64());
    if occupancy == BlockOccupancy::ExactlyOne {
        let exact = primus_ntru::split::NativeNtruGadgetGenerator::try_new(
            client.accumulator_ntru_secret_key(),
        )
        .unwrap();
        let mut reference = vec![0; 6 * control_len];
        let mut replay = StdRng::seed_from_u64(0xB3C);
        for (i, (&bit, coefficients)) in client
            .external_lwe_secret_key()
            .as_ref()
            .iter()
            .zip(NlevIterMut::new(&mut reference, control_len))
            .enumerate()
        {
            exact.encrypt_bit_coeff_to(
                bit == 1,
                i < 3,
                coefficients,
                context.parameters().blind_rotation(),
                &mut replay,
            );
        }
        assert_eq!(
            ordinary_key
                .block_bootstrapping_key()
                .unwrap()
                .controls()
                .as_slice(),
            reference
        );
        assert_eq!(replay.next_u64(), next_ordinary);
    }

    // Identical coefficient payloads still bind to distinct online precision.
    // Bootstrap resources validate that binding before allocating any buffers.
    use primus_tfhe_ntru_fourier::{
        FourierPrecision, TfheEvaluationError, bootstrap::BootstrapResources,
    };
    assert_eq!(ordinary_key.precision(), FourierPrecision::Ordinary);
    assert_eq!(
        split_key.precision(),
        FourierPrecision::Split { low_bits: 40 }
    );
    assert!(BootstrapResources::try_new(&context, &ordinary_key).is_ok());
    assert!(BootstrapResources::try_new(&split_context, &split_key).is_ok());
    assert!(matches!(
        BootstrapResources::try_new(&context, &split_key),
        Err(TfheEvaluationError::IncompatibleBlindRotationKey)
    ));
    assert!(matches!(
        BootstrapResources::try_new(&split_context, &ordinary_key),
        Err(TfheEvaluationError::IncompatibleBlindRotationKey)
    ));
    let mut other_split = split_br;
    other_split.fourier_precision.blind_rotation = FourierPrecision::Split { low_bits: 35 };
    let other_split = TfheContext::<u64, Table, _>::try_from_cbs_config(other_split).unwrap();
    assert!(matches!(
        BootstrapResources::try_new(&other_split, &split_key),
        Err(TfheEvaluationError::IncompatibleBlindRotationKey)
    ));

    // Supporting direct binary blocks does not broaden the unrelated sparse
    // and classic ternary algorithms' split capabilities.
    for (method, secret_key_distr) in [
        (
            SPARSE,
            SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 2 },
        ),
        (BlindRotationMethod::Classic, SecretKeyDistr::UniformTernary),
    ] {
        let mut unsupported = split_br;
        unsupported.pbs.method = method;
        unsupported.pbs.external_lwe.secret_key_distr = secret_key_distr;
        assert!(matches!(
            TfheContext::<u64, Table, _>::try_from_cbs_config(unsupported),
            Err(primus_tfhe_ntru_fourier::TfheContextError::UnsupportedSplitBlindRotation)
        ));
    }
}

#[test]
fn block_coefficient_phases_and_key_boundaries() {
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        #[cfg(feature = "rustfft")]
        check_block_coefficients::<primus_fft::RustFftTable>(occupancy);
        #[cfg(feature = "tfhe-fft")]
        check_block_coefficients::<primus_fft::TfheFftTable>(occupancy);
    }
}

/// The shared Fourier binding must reject another ring before allocating an evaluator.
#[test]
fn default_cbs_rejects_mixed_ring_material() {
    use primus_tfhe_ntru_fourier::{CircuitBootstrapServerKey, TfheEvaluationError};
    // Engine selection does not change the binding check; exercise it once.
    #[cfg(feature = "rustfft")]
    type Table = primus_fft::RustFftTable;
    #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
    type Table = primus_fft::TfheFftTable;
    type Context = TfheContext<u32, Table, PowOf2Modulus<u32>>;
    let pbs = config(BlindRotationMethod::Classic);
    let gadget = CbsGadgetConfig {
        trace: decomposition(),
        scheme_switch: decomposition(),
        output: decomposition(),
    };
    let context = Context::try_from_pbs_config(pbs)
        .unwrap()
        .try_with_circuit_bootstrap(gadget)
        .unwrap();
    let mut other_pbs = pbs;
    other_pbs.bsk_poly_length = PolyLength::new(64);
    let other = Context::try_from_pbs_config(other_pbs)
        .unwrap()
        .try_with_circuit_bootstrap(gadget)
        .unwrap();
    let mut rng = StdRng::seed_from_u64(108);
    let (_, server) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    let (_, other_server) = other.try_generate_circuit_bootstrap_keys(&mut rng).unwrap();

    // Keep q, native Q, precision and gadgets identical; change only trace/SS N.
    let (server, _) = server.into_parts();
    let (_, circuit) = other_server.into_parts();
    let mixed = CircuitBootstrapServerKey::new(server, circuit);
    assert!(matches!(
        context.circuit_bootstrap_evaluator_with_lookup_table(
            &mixed,
            context.compile_cbs_identity().unwrap(),
        ),
        Err(TfheEvaluationError::IncompatibleCircuitBootstrapParameters)
    ));
}

/// Keygen rejects incompatible imports before sampling, including f that cannot
/// be represented at return q or inverted at Q. Error paths leave scratch reusable.
fn check_key_generation_boundaries<Table: FftTable>() {
    use primus_ntru::{NtruError, NtruSecretKey};
    use primus_tfhe_ntru_fourier::{ClientKey, KeyGenerationError, KeyGenerator, TfheKeyError};
    use rand::Rng;

    let mut config = config::<u32>(SPARSE);
    config.bsk_poly_length = PolyLength::new(64);
    let context = TfheContext::<u32, Table, _>::try_from_pbs_config(config)
        .unwrap()
        .try_with_circuit_bootstrap(CbsGadgetConfig {
            trace: decomposition(),
            scheme_switch: decomposition(),
            output: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(4),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
        })
        .unwrap();
    let mut generator = KeyGenerator::new(&context);
    let mut rng = StdRng::seed_from_u64(115);
    let mut untouched = StdRng::seed_from_u64(115);
    let external = context.parameters().external_lwe();
    let imported = |dimension, constant| {
        let mut s = vec![0; dimension];
        s[..2].fill(1);
        let mut f = vec![0; 64];
        f[0] = constant;
        ClientKey::new(
            primus_lwe::LweSecretKey::new(
                s,
                external.secret_key_distr(),
                external.cipher_modulus(),
            ),
            NtruSecretKey::new(f, config.bsk_secret_distr),
        )
    };
    for (dimension, constant, expected) in [
        (
            7,
            1,
            KeyGenerationError::ClientKey(TfheKeyError::ExternalLweDimensionMismatch),
        ),
        (
            8,
            1 << 24,
            KeyGenerationError::ClientKey(TfheKeyError::AccumulatorSecretOutsideLweModulus),
        ),
        (
            8,
            0,
            KeyGenerationError::Ntru(NtruError::NonInvertibleSecretKey),
        ),
    ] {
        let client = imported(dimension, constant);
        if constant != 1 << 24 {
            assert_eq!(
                generator
                    .try_generate_blind_rotation_key(&client, &mut rng)
                    .err(),
                Some(expected.clone())
            );
        }
        assert_eq!(
            generator.try_generate_server_key(&client, &mut rng).err(),
            Some(expected.clone())
        );
        assert_eq!(
            generator
                .try_generate_circuit_bootstrap_server_key(&client, &mut rng)
                .err(),
            Some(expected)
        );
    }

    // A foreign lift is rejected before the joint path samples either client secret.
    let mut other_config = config;
    other_config.bsk_poly_length = PolyLength::new(32);
    let other = primus_tfhe_ntru_fourier::PbsParameters::try_from_config(other_config).unwrap();
    assert!(matches!(
        generator.try_generate_circuit_bootstrap_keys_with_public_lift(
            Some(other.blind_rotation()),
            &mut rng
        ),
        Err(KeyGenerationError::IncompatiblePublicLiftParameters)
    ));

    // Direct Block BR requires u64. Reject unsupported modes at context
    // construction, before allocating an FFT table or generating keys.
    let mut block_config = config;
    block_config.method = BlindRotationMethod::Block;
    block_config.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
        block_size: 2,
        occupancy: BlockOccupancy::AtMostOne,
    };
    let gadget = CbsGadgetConfig {
        trace: decomposition(),
        scheme_switch: decomposition(),
        output: decomposition(),
    };
    let block_cbs = primus_tfhe_ntru_fourier::CbsConfig {
        projection: primus_tfhe_ntru::NtruProjectionMethod::Separate,
        fourier_precision: primus_tfhe_ntru::FourierCbsPrecision::ORDINARY,
        pbs: block_config,
        gadget,
    };
    assert!(matches!(
        TfheContext::<u32, Table, _>::try_from_pbs_config(block_config),
        Err(TfheContextError::Block(
            primus_tfhe_ntru::BlockBootstrappingKeyError::UnsupportedFourierWordSize { bits: 32 },
        ))
    ));
    assert!(matches!(
        TfheContext::<u32, Table, _>::try_from_cbs_config(block_cbs),
        Err(TfheContextError::Block(
            primus_tfhe_ntru::BlockBootstrappingKeyError::UnsupportedFourierWordSize { bits: 32 },
        ))
    ));

    // Sparse preflight must also precede client generation in both complete paths.
    let mut invalid_config = config;
    invalid_config.method = BlindRotationMethod::Sparse {
        copy_count: 0,
        bucket_count: 8,
    };
    let invalid =
        TfheContext::<u32, Table, _>::try_from_cbs_config(primus_tfhe_ntru_fourier::CbsConfig {
            projection: primus_tfhe_ntru::NtruProjectionMethod::Separate,
            fourier_precision: primus_tfhe_ntru::FourierCbsPrecision::ORDINARY,
            pbs: invalid_config,
            gadget: CbsGadgetConfig {
                trace: decomposition(),
                scheme_switch: decomposition(),
                output: decomposition(),
            },
        })
        .unwrap();
    let mut invalid_generator = KeyGenerator::new(&invalid);
    assert!(matches!(
        invalid_generator.try_generate_blind_rotation_key(&imported(8, 1), &mut rng),
        Err(KeyGenerationError::SparseBootstrapping(_))
    ));
    assert!(matches!(
        invalid_generator.try_generate(&mut rng),
        Err(KeyGenerationError::SparseBootstrapping(_))
    ));
    assert!(matches!(
        invalid_generator.try_generate_circuit_bootstrap_keys(&mut rng),
        Err(KeyGenerationError::SparseBootstrapping(_))
    ));
    assert_eq!(rng.next_u64(), untouched.next_u64());

    // An invertible f outside return q is still valid for standalone BR.
    // Odd q+1 is a unit for the native torus as well as the NTT prime field.
    generator
        .try_generate_blind_rotation_key(&imported(8, (1 << 24) + 1), &mut rng)
        .unwrap();

    // Reuse the same generator with a unit f=1 and the declared binary weight.
    let client = imported(8, 1);
    let server = generator
        .try_generate_circuit_bootstrap_server_key(&client, &mut rng)
        .unwrap();
    context.evaluator(server.server_key()).unwrap();
    context.circuit_bootstrap_evaluator(&server).unwrap();
    context.one_hot_evaluator(&server).unwrap();
}

#[test]
fn key_generation_boundaries() {
    #[cfg(feature = "rustfft")]
    check_key_generation_boundaries::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check_key_generation_boundaries::<primus_fft::TfheFftTable>();
}

/// Shared parameter preparation is representation-independent; only the backend
/// rejects fusion, for both raw configuration and independently prepared parameters.
fn reject_unsupported_projection<Table: FftTable>() {
    use NtruProjectionMethod::*;
    use primus_tfhe_ntru_fourier::{
        CbsConfig, CbsParameters, NtruProjectionMethod, TfheContextError,
    };
    let gadget = CbsGadgetConfig {
        trace: decomposition(),
        scheme_switch: decomposition(),
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(4),
            level_count: Some(DecompositionLevelCount::new(2)),
        },
    };
    for projection in [Separate, FusedLastStage, FusedLastThreeStages, PairedTrace] {
        let config = CbsConfig {
            pbs: config::<u32>(BlindRotationMethod::Classic),
            gadget,
            projection,
            fourier_precision: primus_tfhe_ntru::FourierCbsPrecision::ORDINARY,
        };
        let parameters = CbsParameters::try_from_config(config).unwrap();
        assert_eq!(parameters.projection(), projection);
        let results = [
            TfheContext::<u32, Table, _>::try_from_cbs_parameters(parameters),
            TfheContext::<u32, Table, _>::try_from_cbs_config(config),
        ];
        for result in results {
            if projection == Separate {
                assert_eq!(
                    result.unwrap().cbs_parameters().unwrap().projection(),
                    Separate
                );
            } else {
                assert!(
                    matches!(result, Err(TfheContextError::UnsupportedProjectionMethod(found)) if found == projection)
                );
            }
        }
    }
    for preset in [
        primus_tfhe_ntru_fourier::experimental::CLASSIC_CBS_U64,
        primus_tfhe_ntru_fourier::experimental::CLASSIC_ONE_HOT_U64,
    ] {
        assert_eq!(preset.projection, Separate);
    }
}

#[test]
fn fourier_rejects_unsupported_projection() {
    #[cfg(feature = "rustfft")]
    reject_unsupported_projection::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    reject_unsupported_projection::<primus_fft::TfheFftTable>();
}

/// A CBS context's split BSK also serves ordinary PBS. Trace-only and all-split
/// outputs are consumed as ordinary Fourier controls over nonconstant ring data.
/// Fused trace/SS use different limb widths and still return ordinary controls.
/// The separately sampled ordinary NLEV[1] lifts public polynomials even when
/// the selected BR uses split spectra and its first block's secret is all zero.
fn assert_public_lift<Table: FftTable>(
    context: &TfheContext<u64, Table, PowOf2Modulus<u64>>,
    secret: &primus_ntru::NtruSecretKey<u64>,
    lift: &primus_lattice::nlev::FourierNlev<Vec<primus_fft::Complex64>>,
) {
    let n = context.parameters().poly_length().get();
    let scalar = context
        .cbs_parameters()
        .unwrap()
        .gadget()
        .output_basis()
        .scalar_iter()
        .next()
        .unwrap();
    let polynomial = Polynomial::new(
        (0..n)
            .map(|i| if i % 3 == 0 { scalar } else { 0 })
            .collect::<Vec<_>>(),
    );
    let mut fft = context.new_fft_engine();
    let mut product =
        primus_ntru::FourierNtruExternalProductWorkspace::new(context.parameters().poly_length());
    let mut output = context.allocate_accumulator_ciphertext();
    lift.external_product_to(
        &polynomial,
        &mut output,
        context.parameters().blind_rotation().basis(),
        &mut fft,
        &mut product,
    );
    let phase = native_phase(output.as_ref(), secret.as_slice());
    for (&actual, &expected) in phase.iter().zip(polynomial.as_ref()) {
        assert!(
            actual
                .wrapping_sub(expected)
                .min(expected.wrapping_sub(actual))
                <= scalar >> 4u32
        );
    }
}

fn split_cbs_and_pbs<Table: FftTable>() {
    use NtruProjectionMethod::{FusedLastStage, PairedTrace, Separate};
    use primus_tfhe_ntru_fourier::{
        CbsConfig, FourierCbsPrecision, FourierPrecision as P, NtruProjectionMethod,
    };
    // Both logN parities, multirow output and unequal trace/SS limb widths.
    for (all, projection, n, message_modulus, levels, occupancy) in [
        (false, Separate, 128, 8, 3, None),
        (true, Separate, 128, 8, 3, None),
        (false, FusedLastStage, 128, 8, 3, None),
        (true, FusedLastStage, 128, 8, 3, None),
        (false, PairedTrace, 64, 8, 3, None),
        (true, PairedTrace, 128, 8, 3, None),
        // M=2, L=1: nonzero output has one target and must retain its old route.
        (true, PairedTrace, 64, 4, 1, None),
        // Block BR owns its precision independently of trace/SS. The split
        // cases consume both the simple and shared projection schedules.
        (
            false,
            PairedTrace,
            128,
            8,
            3,
            Some(BlockOccupancy::AtMostOne),
        ),
        (true, Separate, 128, 8, 3, Some(BlockOccupancy::AtMostOne)),
        (
            true,
            PairedTrace,
            128,
            8,
            3,
            Some(BlockOccupancy::AtMostOne),
        ),
        (
            false,
            PairedTrace,
            128,
            8,
            3,
            Some(BlockOccupancy::ExactlyOne),
        ),
        (true, Separate, 128, 8, 3, Some(BlockOccupancy::ExactlyOne)),
        (
            true,
            PairedTrace,
            128,
            8,
            3,
            Some(BlockOccupancy::ExactlyOne),
        ),
    ] {
        let method = if occupancy.is_some() {
            BlindRotationMethod::Block
        } else {
            BlindRotationMethod::Classic
        };
        let mut pbs_config = config::<u64>(method);
        if let Some(occupancy) = occupancy {
            pbs_config.external_lwe.dimension = LweDimension::new(10);
            pbs_config.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
                block_size: 5,
                occupancy,
            };
        }
        pbs_config.bsk_poly_length = PolyLength::new(n);
        pbs_config.messages = primus_tfhe_ntru_fourier::PbsMessageConfig::new(message_modulus);
        let last_message = message_modulus / 2 - 1;
        let c = CbsConfig {
            pbs: pbs_config,
            gadget: CbsGadgetConfig {
                trace: decomposition(),
                scheme_switch: decomposition(),
                output: DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(if levels == 1 { 12 } else { 4 }),
                    level_count: Some(DecompositionLevelCount::new(levels)),
                },
            },
            projection,
            fourier_precision: FourierCbsPrecision {
                blind_rotation: if all {
                    P::Split { low_bits: 40 }
                } else {
                    P::Ordinary
                },
                trace: P::Split { low_bits: 40 },
                scheme_switch: if all || projection != Separate {
                    P::Split { low_bits: 35 }
                } else {
                    P::Ordinary
                },
            },
        };
        let context = TfheContext::<u64, Table, _>::try_from_cbs_config(c).unwrap();
        if all && method == BlindRotationMethod::Block && projection == Separate {
            // This path uses q != native Q and the same split BR with an
            // interleaved stride of four and the MVB factor-lift schedule.
            check_many_lut_and_mvb(&context);
        }
        let mut rng = StdRng::seed_from_u64(if method == BlindRotationMethod::Block {
            106
        } else {
            414
        });
        let public_lift_requested =
            method == BlindRotationMethod::Block && (!all || projection == Separate);
        let (client, server, public_lift) = primus_tfhe_ntru_fourier::KeyGenerator::new(&context)
            .try_generate_circuit_bootstrap_keys_with_public_lift(
                public_lift_requested.then_some(context.parameters().blind_rotation()),
                &mut rng,
            )
            .unwrap();
        if occupancy == Some(BlockOccupancy::AtMostOne) {
            assert!(
                client.external_lwe_secret_key().as_ref()[..5]
                    .iter()
                    .all(|&s| s == 0)
            );
        }
        if let Some(lift) = public_lift {
            assert!(
                server
                    .server_key()
                    .blind_rotation_key()
                    .classic_controls()
                    .is_none()
            );
            assert_public_lift(&context, client.accumulator_ntru_secret_key(), &lift);
        }
        let encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
        let mut ring = context
            .accumulator_client(client.accumulator_ntru_secret_key(), 8)
            .unwrap();
        let messages: Vec<Vec<u64>> = (0..2)
            .map(|r| (0..n).map(|i| ((i / 7 + i + r) % 4) as u64).collect())
            .collect();
        let candidates: Vec<_> = messages.iter().map(|m| ring.encrypt(m, &mut rng)).collect();
        let mut selected = context.allocate_accumulator_ciphertext();
        let mut decoded = vec![0; n];
        let mut cbs = context
            .circuit_bootstrap_evaluator_with_lookup_table(
                &server,
                context.compile_cbs_fn(|m| u64::from(m >= 2)).unwrap(),
            )
            .unwrap();
        let mut control = cbs.allocate_output();
        let mut input = context.allocate_lwe_ciphertext();
        let mut pbs = context.evaluator(server.server_key()).unwrap();
        let lut = context
            .pbs_lookup_table_compiler()
            .unwrap()
            .compile_fn(|x| x as u64)
            .unwrap();
        let decoder = context
            .pbs_decryptor(client.external_lwe_secret_key())
            .unwrap();
        for m in [0, last_message] {
            encryptor
                .encrypt_padded_to(m, input.as_mut_view(), &mut rng)
                .unwrap();
            let output = pbs.apply_lookup_table(input.as_view(), &lut);
            assert_eq!(decoder.decrypt(output.as_view()).unwrap(), m);
            cbs.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
            cbs.cmux_to(
                control.as_view(),
                candidates[0].as_view(),
                candidates[1].as_view(),
                selected.as_mut_view(),
            );
            ring.decrypt_to(&selected, &mut decoded);
            assert_eq!(decoded, messages[usize::from(m >= 2)]);
        }
        if projection == PairedTrace {
            // Cross-selector and cross-level sharing, both logN parities. Reuse
            // dirty buffers across inputs and consume every ordinary FFT control.
            let mut one_hot = context.one_hot_evaluator(&server).unwrap();
            let mut full = one_hot.allocate_ngsw_output();
            let mut nonzero = one_hot.allocate_nonzero_ngsw_output();
            let mut nlev = one_hot.allocate_nlev_output();
            for m in [last_message, 0, 1] {
                encryptor
                    .encrypt_padded_to(m, input.as_mut_view(), &mut rng)
                    .unwrap();
                one_hot.one_hot_ngsw_to(input.as_view(), &mut full);
                one_hot.one_hot_nonzero_ngsw_to(input.as_view(), &mut nonzero);
                let len = one_hot.ngsw_selector_len();
                if message_modulus > 4 || levels > 1 {
                    assert_eq!(&full[len..], &nonzero);
                } else {
                    // Only the single-target fallback needs separate consumption:
                    // its rounding differs from the shared full output below.
                    for (r, control) in one_hot.nonzero_ngsw_selectors(&nonzero).iter() {
                        one_hot.cmux_to(
                            control,
                            candidates[0].as_view(),
                            candidates[1].as_view(),
                            selected.as_mut_view(),
                        );
                        ring.decrypt_to(&selected, &mut decoded);
                        assert_eq!(decoded, messages[usize::from(r as u64 == m)]);
                    }
                }
                for (r, control) in one_hot.ngsw_selectors(&full).iter() {
                    one_hot.cmux_to(
                        control,
                        candidates[0].as_view(),
                        candidates[1].as_view(),
                        selected.as_mut_view(),
                    );
                    ring.decrypt_to(&selected, &mut decoded);
                    assert_eq!(decoded, messages[usize::from(r as u64 == m)]);
                }
                // Switching to dual must bypass the shared path. Its NGSW
                // controls still select correctly, though their noise differs.
                one_hot.one_hot_nlev_and_nonzero_ngsw_to(input.as_view(), &mut nlev, &mut nonzero);
                if method == BlindRotationMethod::Block {
                    // NLEV remains coefficient-form even when BR is split.
                    // Schoolbook decryption checks every level/selector without
                    // using an FFT round trip as its own numerical oracle.
                    let mut standalone = one_hot.allocate_nlev_output();
                    one_hot.one_hot_nlev_to(input.as_view(), &mut standalone);
                    assert_eq!(standalone, nlev);
                    let basis = context.cbs_parameters().unwrap().gadget().output_basis();
                    for (selector, control) in one_hot.nlev_selectors(&nlev).iter() {
                        for (row, scalar) in control.iter_ntru(n).zip(basis.scalar_iter()) {
                            let phase = native_phase(
                                row.as_ref(),
                                client.accumulator_ntru_secret_key().as_slice(),
                            );
                            for (i, actual) in phase.into_iter().enumerate() {
                                let expected = if selector as u64 == m && i == 0 {
                                    scalar
                                } else {
                                    0
                                };
                                assert!(
                                    actual
                                        .wrapping_sub(expected)
                                        .min(expected.wrapping_sub(actual))
                                        <= scalar >> 4u32
                                );
                            }
                        }
                    }
                    // The all-selector dual entry point preserves the same
                    // coefficient controls and its NGSW outputs remain usable.
                    one_hot.one_hot_to(input.as_view(), &mut nlev, &mut full);
                    assert_eq!(standalone, nlev);
                    for (r, control) in one_hot.ngsw_selectors(&full).iter() {
                        one_hot.cmux_to(
                            control,
                            candidates[0].as_view(),
                            candidates[1].as_view(),
                            selected.as_mut_view(),
                        );
                        ring.decrypt_to(&selected, &mut decoded);
                        assert_eq!(decoded, messages[usize::from(r as u64 == m)]);
                    }
                }
                for (r, control) in one_hot.nonzero_ngsw_selectors(&nonzero).iter() {
                    one_hot.cmux_to(
                        control,
                        candidates[0].as_view(),
                        candidates[1].as_view(),
                        selected.as_mut_view(),
                    );
                    ring.decrypt_to(&selected, &mut decoded);
                    assert_eq!(decoded, messages[usize::from(r as u64 == m)]);
                }
            }
        }
        let mut inputs = [input.clone(), input.clone(), input];
        for (m, input) in [0, last_message, 1].into_iter().zip(&mut inputs) {
            encryptor
                .encrypt_padded_to(m, input.as_mut_view(), &mut rng)
                .unwrap();
        }
        assert_pair_matches_single(
            context.one_hot_evaluator(&server).unwrap(),
            inputs.each_ref().map(|input| input.as_view()),
            method != BlindRotationMethod::Classic,
        );
    }
}
#[cfg(feature = "rustfft")]
#[test]
fn rustfft_split_cbs_and_pbs() {
    split_cbs_and_pbs::<primus_fft::RustFftTable>();
}
#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_split_cbs_and_pbs() {
    split_cbs_and_pbs::<primus_fft::TfheFftTable>();
}
