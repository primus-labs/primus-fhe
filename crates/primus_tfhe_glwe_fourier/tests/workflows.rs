//! Small deterministic consumers of the recommended public workflow.
//! n=8/N=128 are arithmetic regression parameters, not security profiles.
#![cfg(any(feature = "rustfft", feature = "tfhe-fft"))]

use primus_encoding::phase_error_magnitude;
use primus_fft::{FftTable, TorusFftValue};
use primus_glwe::{
    BlockOccupancy, FourierGlweDecryptWorkspace, FourierGlweSecretKey, GlweDimension,
    SecretKeyDistr,
};
use primus_lattice::glwe::FourierGlwe;
use primus_lwe::LweDimension;
use primus_modulus::NativeModulus;
use primus_modulus::PowOf2Modulus;
use primus_poly::Polynomial;
use primus_reduce::RingContext;
use primus_reduce::{EncodeSigned, ReduceMul, ReduceNeg};
use primus_shape::PolyLength;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_glwe_fourier::circuit_bootstrap::{CbsGadgetParameters, CircuitBootstrapEvaluator};
use primus_tfhe_glwe_fourier::{
    BlindRotationMethod, CbsConfig, CbsGadgetConfig, CbsInputEncoding, DecompositionConfig,
    GadgetEncryptionConfig, LweConfig, ModulusConfig, PbsConfig, PbsMessageConfig, PbsOrder,
    TfheContext,
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
/// Sparse uses fixed weight; Block uses two non-power-of-two blocks.
/// Classic cases select binary/ternary below.
fn config<T: TorusFftValue>(method: BlindRotationMethod) -> PbsConfig<T> {
    let modulus = ModulusConfig::Native;
    let secret = if method == BlindRotationMethod::Block {
        SecretKeyDistr::BlockBinary {
            block_size: 3,
            occupancy: BlockOccupancy::AtMostOne,
        }
    } else {
        SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 3 }
    };
    PbsConfig {
        small_lwe: LweConfig {
            dimension: LweDimension::new(if method == BlindRotationMethod::Block {
                6
            } else {
                8
            }),
            cipher_modulus: modulus,
            secret_key_distr: secret,
            noise_standard_deviation: 1.0,
        },
        ring_modulus: modulus,
        bsk_dimension: GlweDimension::new(2),
        bsk_secret_distr: SecretKeyDistr::UniformTernary,
        method,
        order: PbsOrder::BootstrapKeyswitch,
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
fn chained_pbs<T: TorusFftValue, Table: FftTable, LM>(config: PbsConfig<T, LM>)
where
    LM: RingContext<T> + TryFrom<ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
{
    let context = TfheContext::<T, Table, LM>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(101);
    // Client: only encrypted inputs and the evaluation key leave this side.
    let client = primus_tfhe_glwe_fourier::ClientKey::generate(context.parameters(), &mut rng);
    // Independently generated components retain the same client and context.
    let mut generator = primus_tfhe_glwe_fourier::KeyGenerator::new(&context);
    let blind_rotation = generator
        .try_generate_blind_rotation_key(&client, &mut rng)
        .unwrap();
    assert_eq!(
        matches!(
            blind_rotation,
            primus_tfhe_glwe_fourier::key::BlindRotationKey::Sparse(_)
        ),
        matches!(config.method, BlindRotationMethod::Sparse { .. }),
    );
    assert_eq!(
        matches!(
            blind_rotation,
            primus_tfhe_glwe_fourier::key::BlindRotationKey::Block(_)
        ),
        config.method == BlindRotationMethod::Block,
    );
    let key_switching = generator
        .try_generate_glwe_key_switching_key(
            context.parameters().glwe_key_switching(),
            &client,
            &mut rng,
        )
        .unwrap();
    let server = primus_tfhe_glwe_fourier::ServerKey::new(blind_rotation, key_switching);
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
/// integer output scale, consumed through the Scaled client factory.
fn many_lut_and_mvb<T: TorusFftValue, Table: FftTable, LM>(mut config: PbsConfig<T, LM>)
where
    LM: RingContext<T> + TryFrom<ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
{
    // Keep the established small-parameter ManyLUT noise margin at t_in=8;
    // use different defaults to detect accidental fallback to config messages.
    config.messages = PbsMessageConfig::new(T::as_from(16));
    let context = TfheContext::<T, Table, LM>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(102);
    // Client: override the default 16→16 with 8→4; outputs use different encodings.
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
    let compiler = context
        .pbs_lookup_table_compiler_with_messages(messages)
        .unwrap();
    let ordinary = compiler.compile_fn(|x| function(x, 0)).unwrap();
    let pair = compiler.compile_interleaved_fn(2, function).unwrap();
    let program = context
        .compile_mvb_fn_with_messages(messages, 4, 9, function)
        .unwrap();
    let mut pbs = context.evaluator(&server).unwrap();
    let mut mvb = context.mvb_evaluator(&server).unwrap();
    let mut lanes = vec![context.allocate_lwe_ciphertext(); 3];
    let mut factors = vec![context.allocate_lwe_ciphertext(); 9];
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
        // Rebind the same PBS resources from step 4 to 1 to 2; the next
        // input returns to step 4. A cached previous-LUT quantizer would fail.
        pbs.apply_lookup_table_to(input.as_view(), &ordinary, lanes[0].as_mut_view());
        assert_eq!(rounded.decrypt(lanes[0].as_view()).unwrap(), function(x, 0));
        pbs.apply_interleaved_lookup_table_to(input.as_view(), &pair, &mut lanes[..2]);
        for (i, output) in lanes[..2].iter().enumerate() {
            assert_eq!(rounded.decrypt(output.as_view()).unwrap(), function(x, i));
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

/// Check every coefficient against the canonical GGSW phase: -F(m)*g*s_r
/// for a mask row, or F(m)*g at coefficient zero for the body row.
/// The scalar/16 allowance belongs only to this fixed small fixture, whose
/// BR/trace/SS use all decomposition levels. It detects missing/scaled/sign-flipped
/// rows; it is neither a general gadget-noise budget nor a DFR bound.
fn assert_gadget_phase<T: TorusFftValue>(
    phase: &[T],
    secret: Option<&[T::SignedInteger]>,
    bit: T,
    scalar: T,
    modulus: NativeModulus<T>,
) {
    let weight = modulus.reduce_mul(bit, scalar);
    for (i, &actual) in phase.iter().enumerate() {
        let expected = if let Some(secret) = secret {
            modulus.reduce_neg(modulus.reduce_mul(weight, modulus.encode_signed(secret[i])))
        } else if i == 0 {
            weight
        } else {
            T::ZERO
        };
        assert!(
            phase_error_magnitude(actual, expected, modulus) <= scalar >> 4u32,
            "coefficient {i}, scalar {scalar:?}, actual {actual:?}, expected {expected:?}"
        );
    }
}

fn circuit_selection<T: TorusFftValue, Table: FftTable, LM>(pbs: PbsConfig<T, LM>)
where
    LM: RingContext<T> + TryFrom<ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
{
    circuit_selection_with_trace::<T, Table, LM>(
        pbs,
        CbsInputEncoding::Padded,
        primus_tfhe_glwe_fourier::FourierTracePrecision::Ordinary,
    );
}

/// Inspect and consume every gadget row/level before the ordinary encrypted CMux.
/// All BR algorithms and PBS orders retain the same output sign/scale contract.
fn circuit_selection_with_trace<T: TorusFftValue, Table: FftTable, LM>(
    pbs: PbsConfig<T, LM>,
    input_encoding: CbsInputEncoding,
    precision: primus_tfhe_glwe_fourier::FourierTracePrecision,
) where
    LM: RingContext<T> + TryFrom<ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
{
    let config = CbsConfig {
        fourier_trace_precision: precision,
        input_encoding,
        pbs,
        gadget: CbsGadgetConfig {
            trace: decomposition(),
            scheme_switch: decomposition(),
            output: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(4),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
        },
    };
    let context = TfheContext::<T, Table, LM>::try_from_cbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(103);
    // Client: encrypt nonconstant candidate polynomials under the ring secret.
    let (client, server) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    // The prepared choice determines generated material; workspace follows this key.
    match server.circuit_bootstrap_key().trace_key() {
        primus_tfhe_glwe_fourier::circuit_bootstrap::CbsTraceKey::Ordinary(_) => {
            assert_eq!(
                precision,
                primus_tfhe_glwe_fourier::FourierTracePrecision::Ordinary
            );
        }
        #[cfg(feature = "split-trace")]
        primus_tfhe_glwe_fourier::circuit_bootstrap::CbsTraceKey::Split35(_) => {
            assert_eq!(
                precision,
                primus_tfhe_glwe_fourier::FourierTracePrecision::Split35
            );
        }
    }
    let encryptor = context
        .cbs_encryptor(client.external_lwe_secret_key())
        .unwrap();
    let mut ring_client = context
        .accumulator_client(client.glwe_secret_key(), T::as_from(8))
        .unwrap();
    // Avoid a short periodic pattern that could hide an incorrect coefficient rotation.
    let messages: Vec<Vec<T>> = (0..2)
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

    // MSB tests use NOT, whose negative slope also exercises the post-trace offset.
    let selector = |m| match input_encoding {
        CbsInputEncoding::Padded => usize::from(m >= 2),
        CbsInputEncoding::MsbBoolean => 1 - m,
    };
    let inputs = match input_encoding {
        CbsInputEncoding::Padded => [0, 3, 1, 2],
        CbsInputEncoding::MsbBoolean => [0, 1, 1, 0],
    };
    if input_encoding == CbsInputEncoding::MsbBoolean {
        let parameters = context.cbs_parameters().unwrap();
        // Same t=2, q/Q and basis, but padded t=2 has a different domain/geometry.
        let wrong = parameters
            .gadget()
            .compile_lookup_table(parameters.br_control_codec(), CbsInputEncoding::Padded)
            .unwrap();
        assert!(
            context
                .circuit_bootstrap_evaluator_with_lookup_table(&server, wrong)
                .is_err()
        );
        input.as_mut().fill(T::ONE);
        assert!(
            encryptor
                .encrypt_to(T::as_from(2), input.as_mut_view(), &mut rng)
                .is_err()
        );
        assert!(input.as_ref().iter().all(|v| *v == T::ONE));
    }

    // Server: compile the predicate, then choose the encrypted branch.
    let program = context.compile_cbs_fn(|m| T::as_from(selector(m))).unwrap();
    // A valid gadget program compiled at the wrong BR input q must fail binding.
    let wrong_input = primus_encoding::RoundedCodec::new(
        T::as_from(8),
        primus_modulus::PowOf2Modulus::new(T::as_from(512)),
    );
    let wrong_program = context
        .cbs_parameters()
        .unwrap()
        .gadget()
        .compile_lookup_table(&wrong_input, primus_tfhe::CbsInputEncoding::Padded)
        .unwrap();
    assert!(matches!(
        context.circuit_bootstrap_evaluator_with_lookup_table(&server, wrong_program),
        Err(primus_tfhe::TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable)
    ));
    let mut cbs = context
        .circuit_bootstrap_evaluator_with_lookup_table(&server, program)
        .unwrap();
    let mut control = cbs.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();
    let gadget = context.cbs_parameters().unwrap().gadget();
    let size = gadget.output_size();
    let n = size.glwe_size().poly_length().get();
    let modulus = NativeModulus::new();
    let mut fft = context.new_fft_engine();
    let transformed_secret =
        FourierGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), &mut fft);
    let mut phase = Polynomial::new(vec![T::ZERO; n]);
    let mut decrypt = FourierGlweDecryptWorkspace::new(size.glwe_size().poly_length());
    let mut returned = FourierGlwe::<Vec<_>>::zero(size.glwe_size().fourier_glwe_len());
    let mut probe = context.allocate_accumulator_ciphertext();
    let public_key = (input_encoding == CbsInputEncoding::MsbBoolean).then(|| {
        context
            .parameters()
            .try_generate_public_key(client.external_lwe_secret_key(), &mut rng)
            .unwrap()
    });
    for m in inputs {
        if let Some(public_key) = public_key.as_ref().filter(|_| m == 1) {
            context
                .cbs_public_encryptor(public_key)
                .unwrap()
                .encrypt_to(T::as_from(m), input.as_mut_view(), &mut rng)
                .unwrap();
        } else {
            encryptor
                .encrypt_to(T::as_from(m), input.as_mut_view(), &mut rng)
                .unwrap();
        }
        cbs.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
        assert!(
            control
                .as_ref()
                .iter()
                .all(|value| value.re.is_finite() && value.im.is_finite())
        );
        let bit = T::as_from(selector(m));
        for (row, glev) in control.iter_glev(size.fourier_glev_len()).enumerate() {
            let secret = client.glwe_secret_key().iter().nth(row);
            for (ciphertext, scalar) in glev
                .iter_glwe(size.glwe_size().fourier_glwe_len())
                .zip(gadget.output_basis().scalar_iter())
            {
                // Diagnose the final Fourier row; do not substitute the
                // coefficient intermediate from trace/scheme switching.
                transformed_secret.decrypt_phase_to(
                    &ciphertext,
                    &mut phase,
                    &mut fft,
                    &mut decrypt,
                );
                assert_gadget_phase(phase.as_ref(), secret, bit, scalar, modulus);

                // Exactly one +1 digit selects this row/level, so the final
                // Fourier control must contribute at every output weight.
                probe.as_mut().fill(T::ZERO);
                probe.as_mut()[row * n] = scalar;
                cbs.external_product_to(control.as_view(), probe.as_view(), selected.as_mut_view());
                selected.write_fourier_form(&mut returned, &mut fft);
                transformed_secret.decrypt_phase_to(&returned, &mut phase, &mut fft, &mut decrypt);
                assert_gadget_phase(phase.as_ref(), secret, bit, scalar, modulus);
            }
        }
        cbs.cmux_to(
            control.as_view(),
            candidates[0].as_view(),
            candidates[1].as_view(),
            selected.as_mut_view(),
        );
        ring_client.decrypt_to(&selected, &mut decoded);
        assert_eq!(decoded, messages[selector(m)], "CBS input {m}");
    }

    // Move standalone CBS resources into PBS; then lend them back to CBS and
    // consume a control at a different gadget layout. Subsequent BR must see
    // its original scratch layout. This also exercises both KS placements.
    let (_, resources) = cbs.into_parts();
    // Reuse the circuit material with another output basis of the same layout.
    // An old program cannot silently inherit the newly selected gadget scales.
    let mut alternate_config = config.gadget;
    alternate_config.output.log_basis = DecompositionBaseLog::new(3);
    let alternate =
        CbsGadgetParameters::try_from_config(context.parameters(), alternate_config).unwrap();
    let original_program = context.compile_cbs_identity().unwrap();
    assert!(matches!(
        CircuitBootstrapEvaluator::try_new(
            &resources,
            &alternate,
            server.circuit_bootstrap_key(),
            original_program,
        ),
        Err(primus_tfhe::TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable)
    ));
    let program = alternate
        .compile_lookup_table_fn(
            context.cbs_parameters().unwrap().br_control_codec(),
            input_encoding,
            |m| T::as_from(selector(m)),
        )
        .unwrap();
    let mut operation = CircuitBootstrapEvaluator::try_new(
        &resources,
        &alternate,
        server.circuit_bootstrap_key(),
        program,
    )
    .unwrap();

    // Recover the configured return from the complete bundle. Independently
    // supplied KS material remains supported through the explicit binding boundary.
    let mut ks_config = config.pbs.key_switching;
    ks_config.decomposition.log_basis = DecompositionBaseLog::new(3);
    let ks_parameters = context
        .parameters()
        .try_key_switching_parameters(ks_config)
        .unwrap();
    assert!(matches!(
        primus_tfhe_glwe_fourier::Evaluator::try_from_parts(
            &context,
            &ks_parameters,
            server.server_key().blind_rotation_key(),
            server.server_key().glwe_key_switching_key(),
        ),
        Err(primus_tfhe_glwe_fourier::TfheEvaluationError::IncompatibleGlweKeySwitchingKey)
    ));
    let key = primus_tfhe_glwe_fourier::KeyGenerator::new(&context)
        .try_generate_glwe_key_switching_key(&ks_parameters, &client, &mut rng)
        .unwrap();
    let mut pbs =
        primus_tfhe_glwe_fourier::Evaluator::try_from_resources(resources, server.server_key())
            .unwrap();
    let mut independent = primus_tfhe_glwe_fourier::Evaluator::try_from_parts(
        &context,
        &ks_parameters,
        server.server_key().blind_rotation_key(),
        &key,
    )
    .unwrap();
    let mut independent_output = context.allocate_lwe_ciphertext();
    let identity = context
        .pbs_lookup_table_compiler()
        .unwrap()
        .compile_fn(T::as_from)
        .unwrap();
    let decryptor = context
        .pbs_decryptor(client.external_lwe_secret_key())
        .unwrap();
    // Sharing a context never changes ordinary PBS input encoding. Re-encrypt
    // through its own client before handing the same message to the PBS identity.
    let pbs_encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
    let mut returned_lwe = context.allocate_lwe_ciphertext();
    let ring_decryptor = context
        .ring_return_decryptor(client.external_lwe_secret_key(), T::as_from(8))
        .unwrap();
    for m in inputs[..2].iter().copied() {
        encryptor
            .encrypt_to(T::as_from(m), input.as_mut_view(), &mut rng)
            .unwrap();
        operation.circuit_bootstrap_to(
            input.as_view(),
            &mut control,
            pbs.bootstrap_resources_mut(),
        );
        operation.cmux_to(
            &control,
            &candidates[0],
            &candidates[1],
            &mut selected,
            pbs.bootstrap_resources_mut(),
        );
        ring_client.decrypt_to(&selected, &mut decoded);
        assert_eq!(decoded, messages[selector(m)]);
        for index in [0, 1, n - 1] {
            pbs.return_ring_at_to(selected.as_view(), index, returned_lwe.as_mut_view());
            assert_eq!(
                ring_decryptor.decrypt(returned_lwe.as_view()).unwrap(),
                messages[selector(m)][index]
            );
        }
        pbs_encryptor
            .encrypt_padded_to(T::as_from(m), input.as_mut_view(), &mut rng)
            .unwrap();
        pbs.apply_lookup_table_to(input.as_view(), &identity, returned_lwe.as_mut_view());
        independent.apply_lookup_table_to(
            input.as_view(),
            &identity,
            independent_output.as_mut_view(),
        );
        assert_eq!(
            decryptor.decrypt(independent_output.as_view()).unwrap(),
            T::as_from(m)
        );
        assert_eq!(
            decryptor.decrypt(returned_lwe.as_view()).unwrap(),
            T::as_from(m)
        );
    }
    // A numerically equal but separately owned context cannot replace the
    // operation's bound resources, even when importing the same key material.
    let other = TfheContext::<T, Table, LM>::try_from_cbs_parameters(
        context.cbs_parameters().unwrap().clone(),
    )
    .unwrap();
    let mut other_resources = server.bootstrap_resources(&other).unwrap();
    control.as_mut().fill(Default::default());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        operation.circuit_bootstrap_to(input.as_view(), &mut control, &mut other_resources);
    }));
    assert!(result.is_err());
    assert!(control.as_ref().iter().all(|v| *v == Default::default()));
}

#[test]
fn u32_binary_classic_chain() {
    let mut config = config(BlindRotationMethod::Classic);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformBinary;
    #[cfg(feature = "rustfft")]
    chained_pbs::<u32, primus_fft::RustFftTable, _>(config);
    #[cfg(feature = "tfhe-fft")]
    chained_pbs::<u32, primus_fft::TfheFftTable, _>(config);

    // The logical block width need not divide the padded ring-KS target length.
    config.small_lwe.dimension = LweDimension::new(6);
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        config.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
            block_size: 3,
            occupancy,
        };
        for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
            config.order = order;
            #[cfg(feature = "rustfft")]
            chained_pbs::<u32, primus_fft::RustFftTable, _>(config);
            #[cfg(feature = "tfhe-fft")]
            chained_pbs::<u32, primus_fft::TfheFftTable, _>(config);
        }
    }
}

#[cfg(feature = "rustfft")]
#[test]
fn rustfft_u32_ternary_batches() {
    let mut config = config(BlindRotationMethod::Classic);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    config.order = PbsOrder::KeyswitchBootstrap;
    many_lut_and_mvb::<u32, primus_fft::RustFftTable, _>(config);
}

/// Both engines use the same fixed seed and u32 classic/KS-before-BR config.
/// Each engine checks every decoded coefficient against the expected plaintext.
#[test]
fn u32_classic_cbs_rows_and_consumption() {
    let mut config = config(BlindRotationMethod::Classic);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    config.order = PbsOrder::KeyswitchBootstrap;
    #[cfg(feature = "rustfft")]
    circuit_selection::<u32, primus_fft::RustFftTable, _>(config);
    #[cfg(feature = "tfhe-fft")]
    circuit_selection::<u32, primus_fft::TfheFftTable, _>(config);
}

#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_u64_sparse_chain() {
    let mut config = config(SPARSE);
    config.order = PbsOrder::KeyswitchBootstrap;
    chained_pbs::<u64, primus_fft::TfheFftTable, _>(config);
}

#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_u64_sparse_batches() {
    let config = config(SPARSE);
    many_lut_and_mvb::<u64, primus_fft::TfheFftTable, _>(config);
}

#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_u64_sparse_cbs() {
    let config = config(SPARSE);
    circuit_selection::<u64, primus_fft::TfheFftTable, _>(config);
}

/// q uses a power-of-two reducer independently of the accumulator representation.
/// Keep ring secret ternary/rank two to exercise signed padding and extraction.
fn two_domain_config<T: TorusFftValue>(
    method: BlindRotationMethod,
    order: PbsOrder,
) -> PbsConfig<T, PowOf2Modulus<T>> {
    let base = config::<T>(method);
    PbsConfig {
        small_lwe: LweConfig {
            cipher_modulus: ModulusConfig::Explicit(T::as_from(1024)),
            dimension: base.small_lwe.dimension,
            secret_key_distr: if method == BlindRotationMethod::Classic {
                SecretKeyDistr::UniformTernary
            } else {
                base.small_lwe.secret_key_distr
            },
            noise_standard_deviation: base.small_lwe.noise_standard_deviation,
        },
        ring_modulus: base.ring_modulus,
        bsk_dimension: base.bsk_dimension,
        bsk_poly_length: base.bsk_poly_length,
        bsk_secret_distr: base.bsk_secret_distr,
        bsk_gadget: base.bsk_gadget,
        method,
        key_switching: base.key_switching,
        messages: base.messages,
        order,
    }
}

#[test]
fn q1024_classic_returns_and_cbs() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let config = two_domain_config(BlindRotationMethod::Classic, order);
        #[cfg(feature = "rustfft")]
        chained_pbs::<u64, primus_fft::RustFftTable, _>(config);
        #[cfg(feature = "tfhe-fft")]
        chained_pbs::<u64, primus_fft::TfheFftTable, _>(config);
        #[cfg(feature = "rustfft")]
        many_lut_and_mvb::<u64, primus_fft::RustFftTable, _>(config);
        #[cfg(feature = "tfhe-fft")]
        many_lut_and_mvb::<u64, primus_fft::TfheFftTable, _>(config);
        #[cfg(feature = "rustfft")]
        circuit_selection::<u64, primus_fft::RustFftTable, _>(config);
        #[cfg(feature = "tfhe-fft")]
        circuit_selection::<u64, primus_fft::TfheFftTable, _>(config);
    }
}

#[test]
fn q1024_sparse_returns_and_cbs() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let config = two_domain_config(SPARSE, order);
        #[cfg(feature = "rustfft")]
        chained_pbs::<u32, primus_fft::RustFftTable, _>(config);
        #[cfg(feature = "tfhe-fft")]
        chained_pbs::<u32, primus_fft::TfheFftTable, _>(config);
        #[cfg(feature = "rustfft")]
        many_lut_and_mvb::<u32, primus_fft::RustFftTable, _>(config);
        #[cfg(feature = "tfhe-fft")]
        many_lut_and_mvb::<u32, primus_fft::TfheFftTable, _>(config);
        #[cfg(feature = "rustfft")]
        circuit_selection::<u32, primus_fft::RustFftTable, _>(config);
        #[cfg(feature = "tfhe-fft")]
        circuit_selection::<u32, primus_fft::TfheFftTable, _>(config);
    }
}

/// Direct blocks use the same changing ManyLUT strides and factorized MVB
/// program as the other methods; q differs from the native ring modulus.
#[test]
fn u32_block_pbs_and_batches() {
    let config = two_domain_config(BlindRotationMethod::Block, PbsOrder::BootstrapKeyswitch);
    #[cfg(feature = "rustfft")]
    chained_pbs::<u32, primus_fft::RustFftTable, _>(config);
    #[cfg(feature = "tfhe-fft")]
    chained_pbs::<u32, primus_fft::TfheFftTable, _>(config);
    #[cfg(feature = "rustfft")]
    many_lut_and_mvb::<u32, primus_fft::RustFftTable, _>(config);
    #[cfg(feature = "tfhe-fft")]
    many_lut_and_mvb::<u32, primus_fft::TfheFftTable, _>(config);
}

/// KS-before-BR prepares the direct-block input, then CBS controls encrypted
/// CMux and coefficient-indexed LWE returns. The logical width need not divide
/// the public zero-padded ring-KS target length.
#[test]
fn u64_block_cbs_and_returns() {
    let mut config = two_domain_config(BlindRotationMethod::Block, PbsOrder::KeyswitchBootstrap);
    config.small_lwe.dimension = LweDimension::new(10);
    config.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
        block_size: 5,
        occupancy: BlockOccupancy::AtMostOne,
    };
    #[cfg(feature = "rustfft")]
    circuit_selection::<u64, primus_fft::RustFftTable, _>(config);
    #[cfg(feature = "tfhe-fft")]
    circuit_selection::<u64, primus_fft::TfheFftTable, _>(config);
}

/// Imported keys and raw quantizers must agree with the declared input domain.
fn input_domain_binding<Table: FftTable>() {
    use primus_tfhe::TfheEvaluationError;
    use primus_tfhe::rotation::RotationModulusSwitch;
    use primus_tfhe_glwe_fourier::key::BlindRotationKey;

    for method in [
        BlindRotationMethod::Classic,
        SPARSE,
        BlindRotationMethod::Block,
    ] {
        let config = two_domain_config::<u32>(method, PbsOrder::BootstrapKeyswitch);
        let context = TfheContext::<u32, Table, _>::try_from_pbs_config(config).unwrap();
        let mut rng = StdRng::seed_from_u64(114);
        let (_, server) = context.try_generate_keys(&mut rng).unwrap();
        // The shape, gadgets and ring modulus agree; only input q differs.
        let mut wrong_config = config;
        wrong_config.small_lwe.cipher_modulus = ModulusConfig::Explicit(512);
        let wrong_context =
            TfheContext::<u32, Table, _>::try_from_pbs_config(wrong_config).unwrap();
        assert!(matches!(
            wrong_context.evaluator(&server),
            Err(TfheEvaluationError::IncompatibleBlindRotationKey)
        ));

        let input = context.allocate_lwe_ciphertext();
        let lut = Polynomial::new(vec![0u32; 128]);
        let mut output = context.allocate_accumulator_ciphertext();
        // Wrong q, wrong 2N, and a nonordinary step must fail before writes.
        for (q, two_n, step) in [(512, 256, 1), (1024, 128, 1), (1024, 256, 4)] {
            let rotation = RotationModulusSwitch::new(PowOf2Modulus::new(q), two_n, step);
            output.as_mut().fill(7);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match server.blind_rotation_key() {
                    BlindRotationKey::Classic(key) => {
                        let mut workspace = primus_tfhe_glwe_fourier::blind_rotation::FourierGlweBlindRotationWorkspace::new(key);
                        key.fourier_blind_rotate_lookup_table_to(
                            &input,
                            &lut,
                            &rotation,
                            &mut output,
                            &mut context.new_fft_engine(),
                            &mut workspace,
                        );
                    }
                    BlindRotationKey::Block(key) => {
                        let mut workspace =
                            primus_tfhe_glwe_fourier::block::BlockGlweBlindRotationWorkspace::new(
                                key,
                            );
                        workspace.blind_rotate_lookup_table_to(
                            key,
                            &input,
                            &lut,
                            &rotation,
                            &mut output,
                            &mut context.new_fft_engine(),
                        );
                    }
                    BlindRotationKey::Sparse(key) => {
                        let mut workspace =
                            primus_tfhe_glwe_fourier::sparse::SparseGlweBlindRotationWorkspace::new(
                                key.controls(),
                            );
                        workspace.blind_rotate_lookup_table_to(
                            key,
                            &input,
                            &lut,
                            &rotation,
                            &mut output,
                            &mut context.new_fft_engine(),
                        );
                    }
                }
            }));
            assert!(result.is_err());
            assert!(output.as_ref().iter().all(|&x| x == 7));
        }
    }
}

#[test]
fn input_domain_binding_precedes_output_writes() {
    #[cfg(feature = "rustfft")]
    input_domain_binding::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    input_domain_binding::<primus_fft::TfheFftTable>();
}

/// Split changes trace alone: preserve both PBS orders, classic/sparse BR and
/// a ternary ring key. The same consumer checks all rows and gadget levels.
#[test]
#[cfg(feature = "split-trace")]
fn split_trace_cbs_workflows() {
    for method in [BlindRotationMethod::Classic, SPARSE] {
        for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
            let mut config = config::<u64>(method);
            config.bsk_dimension = GlweDimension::new(1);
            config.order = order;
            #[cfg(feature = "rustfft")]
            circuit_selection_with_trace::<u64, primus_fft::RustFftTable, _>(
                config,
                CbsInputEncoding::Padded,
                primus_tfhe_glwe_fourier::FourierTracePrecision::Split35,
            );
            #[cfg(feature = "tfhe-fft")]
            circuit_selection_with_trace::<u64, primus_fft::TfheFftTable, _>(
                config,
                CbsInputEncoding::Padded,
                primus_tfhe_glwe_fourier::FourierTracePrecision::Split35,
            );
        }
    }
}

/// A valid split choice must not silently become Ordinary when the feature is off.
#[test]
#[cfg(not(feature = "split-trace"))]
fn split_trace_requires_backend_feature() {
    fn check<Table: FftTable>() {
        use primus_tfhe_glwe_fourier::{
            CbsParameters, FourierTracePrecision, PbsParameters, TfheContextError,
        };
        let mut pbs = config::<u64>(BlindRotationMethod::Classic);
        pbs.bsk_dimension = GlweDimension::new(1);
        let gadget = CbsGadgetConfig {
            trace: decomposition(),
            scheme_switch: decomposition(),
            output: decomposition(),
        };
        let parameters = CbsParameters::try_with_config(
            PbsParameters::try_from_config(pbs).unwrap(),
            gadget,
            CbsInputEncoding::Padded,
            FourierTracePrecision::Split35,
        )
        .unwrap();
        assert!(matches!(
            TfheContext::<u64, Table>::try_from_cbs_parameters(parameters),
            Err(TfheContextError::SplitTraceUnavailable)
        ));
        // Extending an existing PBS Context keeps its table and has the same gate.
        let context = TfheContext::<u64, Table>::try_from_pbs_config(pbs).unwrap();
        assert!(matches!(
            context.try_with_circuit_bootstrap(
                gadget,
                CbsInputEncoding::Padded,
                FourierTracePrecision::Split35,
            ),
            Err(TfheContextError::SplitTraceUnavailable)
        ));
    }
    #[cfg(feature = "rustfft")]
    check::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check::<primus_fft::TfheFftTable>();
}

/// MSB offsets work with either full-trace implementation and both KS placements.
#[test]
fn msb_boolean_cbs() {
    use primus_tfhe_glwe_fourier::FourierTracePrecision;
    // Native32 and same q=Q remain supported by ordinary trace.
    #[cfg(feature = "rustfft")]
    circuit_selection_with_trace::<u32, primus_fft::RustFftTable, _>(
        config(SPARSE),
        CbsInputEncoding::MsbBoolean,
        FourierTracePrecision::Ordinary,
    );
    #[cfg(feature = "tfhe-fft")]
    circuit_selection_with_trace::<u32, primus_fft::TfheFftTable, _>(
        config(SPARSE),
        CbsInputEncoding::MsbBoolean,
        FourierTracePrecision::Ordinary,
    );
    for (method, precision) in [
        (
            BlindRotationMethod::Classic,
            FourierTracePrecision::Ordinary,
        ),
        #[cfg(feature = "split-trace")]
        (SPARSE, FourierTracePrecision::Split35),
    ] {
        for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
            let mut config = two_domain_config::<u64>(method, order);
            config.bsk_dimension = GlweDimension::new(1);
            #[cfg(feature = "rustfft")]
            circuit_selection_with_trace::<u64, primus_fft::RustFftTable, _>(
                config,
                CbsInputEncoding::MsbBoolean,
                precision,
            );
            #[cfg(feature = "tfhe-fft")]
            circuit_selection_with_trace::<u64, primus_fft::TfheFftTable, _>(
                config,
                CbsInputEncoding::MsbBoolean,
                precision,
            );
        }
    }
}

/// Missing operation state, invalid sparse geometry and imported secrets are
/// rejected before key sampling. A rejected call must leave the generator reusable.
fn check_key_generation_boundaries<Table: FftTable>() {
    use primus_tfhe_glwe_fourier::{
        ClientKey, KeyGenerationError, KeyGenerator, SparseBootstrappingKeyError,
    };
    use rand::Rng;

    let gadget = CbsGadgetConfig {
        trace: decomposition(),
        scheme_switch: decomposition(),
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(4),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    };
    let mut config = config::<u32>(SPARSE);
    config.bsk_dimension = GlweDimension::new(1);
    config.bsk_poly_length = PolyLength::new(64);
    let context = TfheContext::<u32, Table>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(115);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let mut key_rng = StdRng::seed_from_u64(116);
    let mut untouched_rng = StdRng::seed_from_u64(116);

    // No CBS configuration: fail before sampling even when the client is compatible.
    let mut generator = KeyGenerator::new(&context);
    assert!(matches!(
        generator.try_generate_circuit_bootstrap_keys(&mut key_rng),
        Err(KeyGenerationError::MissingCircuitBootstrapParameters)
    ));
    assert!(matches!(
        generator.try_generate_circuit_bootstrap_server_key(&client, &mut key_rng),
        Err(KeyGenerationError::MissingCircuitBootstrapParameters)
    ));
    drop(generator);

    // Imported block coefficients must be checked before sampling key rows.
    let mut block_config = config;
    block_config.method = BlindRotationMethod::Block;
    block_config.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
        block_size: 2,
        occupancy: BlockOccupancy::AtMostOne,
    };
    let block_context = TfheContext::<u32, Table>::try_from_cbs_config(CbsConfig {
        fourier_trace_precision: primus_tfhe_glwe::FourierTracePrecision::Ordinary,
        pbs: block_config,
        gadget,
        input_encoding: CbsInputEncoding::Padded,
    })
    .unwrap();
    let mut block_generator = KeyGenerator::new(&block_context);
    let mut invalid_coefficients = vec![0; block_config.small_lwe.dimension.get()];
    invalid_coefficients[..2].fill(1);
    let invalid_block = ClientKey::new(
        primus_lwe::LweSecretKey::new(
            invalid_coefficients,
            block_config.small_lwe.secret_key_distr,
            block_context.parameters().small_lwe().cipher_modulus(),
        ),
        client.glwe_secret_key().clone(),
        block_config.order,
    );
    assert!(matches!(
        block_generator.try_generate_server_key(&invalid_block, &mut key_rng),
        Err(KeyGenerationError::ClientKey(_))
    ));
    assert!(matches!(
        block_generator.try_generate_circuit_bootstrap_server_key(&invalid_block, &mut key_rng),
        Err(KeyGenerationError::ClientKey(_))
    ));

    // Public sparse geometry must be checked before either PBS or CBS samples a client.
    let mut invalid_config = config;
    invalid_config.method = BlindRotationMethod::Sparse {
        copy_count: 0,
        bucket_count: 8,
    };
    let invalid_context = TfheContext::<u32, Table>::try_from_cbs_config(CbsConfig {
        fourier_trace_precision: primus_tfhe_glwe::FourierTracePrecision::Ordinary,
        pbs: invalid_config,
        gadget,
        input_encoding: CbsInputEncoding::Padded,
    })
    .unwrap();
    let mut generator = KeyGenerator::new(&invalid_context);
    assert!(matches!(
        generator.try_generate_blind_rotation_key(&client, &mut key_rng),
        Err(KeyGenerationError::SparseBootstrapping(_))
    ));
    assert!(matches!(
        generator.try_generate(&mut key_rng),
        Err(KeyGenerationError::SparseBootstrapping(_))
    ));
    assert!(matches!(
        generator.try_generate_circuit_bootstrap_keys(&mut key_rng),
        Err(KeyGenerationError::SparseBootstrapping(_))
    ));

    let context = context
        .try_with_circuit_bootstrap(
            gadget,
            CbsInputEncoding::Padded,
            primus_tfhe_glwe::FourierTracePrecision::Ordinary,
        )
        .unwrap();
    let mut generator = KeyGenerator::new(&context);
    let (small, ring, order) = client.clone().into_parts();
    let wrong_order = ClientKey::new(small, ring, PbsOrder::KeyswitchBootstrap);
    assert!(matches!(
        generator.try_generate_blind_rotation_key(&wrong_order, &mut key_rng),
        Err(KeyGenerationError::ClientKey(_))
    ));
    assert!(matches!(
        generator.try_generate_server_key(&wrong_order, &mut key_rng),
        Err(KeyGenerationError::ClientKey(_))
    ));
    assert!(matches!(
        generator.try_generate_circuit_bootstrap_server_key(&wrong_order, &mut key_rng),
        Err(KeyGenerationError::ClientKey(_))
    ));

    // Binary coefficients alone do not prove the declared sparse weight.
    let zero_secret = primus_lwe::LweSecretKey::new(
        vec![0; config.small_lwe.dimension.get()],
        config.small_lwe.secret_key_distr,
        context.parameters().small_lwe().cipher_modulus(),
    );
    let wrong_weight = ClientKey::new(zero_secret, client.glwe_secret_key().clone(), order);
    assert!(matches!(
        generator.try_generate_blind_rotation_key(&wrong_weight, &mut key_rng),
        Err(KeyGenerationError::SparseBootstrapping(
            SparseBootstrappingKeyError::InvalidSecretCoefficients
        ))
    ));
    assert!(matches!(
        generator.try_generate_server_key(&wrong_weight, &mut key_rng),
        Err(KeyGenerationError::SparseBootstrapping(
            SparseBootstrappingKeyError::InvalidSecretCoefficients
        ))
    ));
    assert!(matches!(
        generator.try_generate_circuit_bootstrap_server_key(&wrong_weight, &mut key_rng),
        Err(KeyGenerationError::SparseBootstrapping(
            SparseBootstrappingKeyError::InvalidSecretCoefficients
        ))
    ));
    assert_eq!(key_rng.next_u64(), untouched_rng.next_u64());

    // A valid import still produces the complete BR/KS/trace/SS bundle after errors.
    let server = generator
        .try_generate_circuit_bootstrap_server_key(&client, &mut key_rng)
        .unwrap();
    context.evaluator(server.server_key()).unwrap();
    context.circuit_bootstrap_evaluator(&server).unwrap();
}

#[test]
fn key_generation_boundaries() {
    #[cfg(feature = "rustfft")]
    check_key_generation_boundaries::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check_key_generation_boundaries::<primus_fft::TfheFftTable>();
}

/// Build a noiseless ring phase by schoolbook negacyclic convolution, independently
/// of encryption/extraction kernels. Nonconstant masks and two secret polynomials
/// expose signs, coefficient endpoints and a KS target with a partial last polynomial.
fn ring_return_phase<Table: FftTable, LM>(mut config: PbsConfig<u64, LM>, small_dimension: usize)
where
    LM: RingContext<u64> + TryFrom<ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
{
    use primus_encoding::{PlaintextEmbedding, ScaledCodec};
    use primus_reduce::{Reduce, ReduceAdd, ReduceSub};

    config.small_lwe.dimension = LweDimension::new(small_dimension);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    config.bsk_poly_length = PolyLength::new(64);
    let context = TfheContext::<u64, Table, LM>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(812);
    let (client, server) = context.try_generate_keys(&mut rng).unwrap();
    let mut evaluator = context.evaluator(&server).unwrap();
    let ring = context.parameters().ring_modulus();
    let q = context.parameters().small_lwe().cipher_modulus();
    let ring_codec = ScaledCodec::new(16, ring);
    let small_codec = ScaledCodec::new(16, q);
    let decoder = context
        .ring_return_decryptor(client.external_lwe_secret_key(), 16)
        .unwrap();
    let mut input = context.allocate_accumulator_ciphertext();
    let n = config.bsk_poly_length.get();
    let (mask, body) = input.a_b_mut_slices(n);
    for (j, value) in mask.iter_mut().enumerate() {
        *value = ring.reduce(0x9e37_79b9_7f4a_7c15u64.wrapping_mul(j as u64 + 1));
    }
    for (i, value) in body.iter_mut().enumerate() {
        *value = ring_codec.encode_value((i * 7 % 16) as u64, PlaintextEmbedding::Unsigned);
        for (a, secret) in
            primus_poly::PolynomialIter::new(mask, n).zip(client.glwe_secret_key().iter())
        {
            for (j, &s) in secret.iter().enumerate() {
                let term =
                    ring.reduce_mul(a.as_ref()[(i + n - j) & (n - 1)], ring.encode_signed(s));
                *value = if j <= i {
                    ring.reduce_add(*value, term)
                } else {
                    ring.reduce_sub(*value, term)
                };
            }
        }
    }
    let mut output = context.allocate_lwe_ciphertext();
    for index in [0, n / 2 + 3, n - 1] {
        evaluator.return_ring_at_to(input.as_view(), index, output.as_mut_view());
        let message = (index * 7 % 16) as u64;
        let phase = decoder.decrypt_phase(output.as_view()).unwrap();
        if config.order == PbsOrder::KeyswitchBootstrap {
            // Direct extraction is exact: it must not apply a small-secret KS.
            assert_eq!(
                phase,
                ring_codec.encode_value(message, PlaintextEmbedding::Unsigned)
            );
        } else {
            let expected = small_codec.encode_value(message, PlaintextEmbedding::Unsigned);
            let bound = small_codec.encode_value(1, PlaintextEmbedding::Unsigned) / 16;
            assert!(phase_error_magnitude(phase, expected, q) < bound);
        }
        assert_eq!(decoder.decrypt(output.as_view()).unwrap(), message);
    }

    // The public boundary rejects malformed complete ciphertexts, not just a
    // dimension rounded down from their storage length, before touching output.
    let input_len = input.as_ref().len();
    let output_len = output.as_ref().len();
    for (input_len, index, output_len) in [
        (input_len, n, output_len),
        (input_len, usize::MAX, output_len),
        (input_len - 1, 0, output_len),
        (input_len + 1, 0, output_len),
        (input_len, 0, output_len - 1),
        (input_len, 0, output_len + 1),
        (input_len, 0, 0),
    ] {
        let input = primus_glwe::GlweCiphertext::new(vec![0u64; input_len]);
        let mut output = primus_lwe::LweCiphertext::new(vec![7u64; output_len]);
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evaluator.return_ring_at_to(input.as_view(), index, output.as_mut_view());
        }));
        assert!(failed.is_err());
        assert!(output.as_ref().iter().all(|&x| x == 7));
    }
}

#[test]
fn ring_return_phase_and_layout_boundaries() {
    for dimension in [3, 69] {
        for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
            let mut same = config(BlindRotationMethod::Classic);
            same.order = order;
            let mut split = two_domain_config(BlindRotationMethod::Classic, order);
            split.small_lwe.cipher_modulus = ModulusConfig::Explicit(1u64 << 24);
            #[cfg(feature = "rustfft")]
            ring_return_phase::<primus_fft::RustFftTable, _>(same, dimension);
            #[cfg(feature = "rustfft")]
            ring_return_phase::<primus_fft::RustFftTable, _>(split, dimension);
            #[cfg(feature = "tfhe-fft")]
            ring_return_phase::<primus_fft::TfheFftTable, _>(same, dimension);
            #[cfg(feature = "tfhe-fft")]
            ring_return_phase::<primus_fft::TfheFftTable, _>(split, dimension);
        }
    }
}

/// Independent native schoolbook phase, including negacyclic wrap signs. This
/// inspects stored key rows without using the Fourier decryption implementation.
fn native_material_phase<T: TorusFftValue>(
    ciphertext: &[T],
    secret: &[T::SignedInteger],
    n: usize,
) -> Vec<T> {
    use primus_reduce::{ReduceAdd, ReduceSub};

    let modulus = NativeModulus::new();
    let (mask, body) = ciphertext.split_at(secret.len());
    let mut phase = body.to_vec();
    for (a, s) in primus_poly::PolynomialIter::new(mask, n).zip(secret.chunks_exact(n)) {
        for (degree, value) in phase.iter_mut().enumerate() {
            for (j, &s) in s.iter().enumerate() {
                let i = (degree + n - j) & (n - 1);
                let product = modulus.reduce_mul(a.as_ref()[i], modulus.encode_signed(s));
                *value = if i + j < n {
                    modulus.reduce_sub(*value, product)
                } else {
                    modulus.reduce_add(*value, product)
                };
            }
        }
    }
    phase
}

/// Check every row/level against the inferred body-row bit. Native Sparse/Block
/// rows have only sampled noise; an inverse-transformed classic row also has FFT
/// error. The separate exact-encryption tests check canonical spectra directly.
fn material_selector(
    ggsw: primus_lattice::ggsw::Ggsw<&[u64]>,
    parameters: &primus_glwe::GlevParameters<u64, NativeModulus<u64>>,
    secret: &[i64],
    error_bound: u64,
) -> u64 {
    let n = parameters.poly_length().get();
    let k = secret.len() / n;
    let body = ggsw.iter_glev(parameters.glev_len()).nth(k).unwrap();
    let row = body.iter_glwe(parameters.glwe_len()).next().unwrap();
    let scalar = parameters.basis().scalar_iter().next().unwrap();
    let phase = native_material_phase(row.as_ref(), secret, n);
    let bit =
        u64::from(phase_error_magnitude(phase[0], scalar, NativeModulus::new()) <= error_bound);
    for (r, glev) in ggsw.iter_glev(parameters.glev_len()).enumerate() {
        for (row, scalar) in glev
            .iter_glwe(parameters.glwe_len())
            .zip(parameters.basis().scalar_iter())
        {
            let phase = native_material_phase(row.as_ref(), secret, n);
            for (i, actual) in phase.into_iter().enumerate() {
                let expected = if r < k {
                    scalar
                        .wrapping_mul(bit)
                        .wrapping_mul(secret[r * n + i] as u64)
                        .wrapping_neg()
                } else if i == 0 {
                    scalar * bit
                } else {
                    0
                };
                assert!(
                    phase_error_magnitude(actual, expected, NativeModulus::new()) <= error_bound
                );
            }
        }
    }
    bit
}

/// Inspect the actual CBS bundle even when a return path does not consume its
/// KSK. Distinct q/Q, signed Z and signed/padded s make a target swap observable.
fn check_bundle_material<Table: FftTable>() {
    use primus_lattice::ggsw::Ggsw;
    use primus_lattice::glev::FourierGlevIter;
    use primus_tfhe_glwe_fourier::{ClientKey, KeyGenerator, key::BlindRotationKey};

    // Fixed N32/u64 fixture allowance for canonical FFT/inverse rounding plus
    // small sampled noise; much smaller than the least gadget weight 2^56.
    // This is a material-binding regression threshold, not a DFR estimate.
    const FOURIER_ERROR: u64 = 1 << 24;
    let decomposition = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: Some(DecompositionLevelCount::new(2)),
    };
    for method in [
        BlindRotationMethod::Classic,
        SPARSE,
        BlindRotationMethod::Block,
    ] {
        for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
            let mut pbs = two_domain_config::<u64>(method, order);
            pbs.bsk_poly_length = PolyLength::new(32);
            pbs.bsk_gadget.decomposition = decomposition;
            pbs.key_switching.decomposition = decomposition;
            pbs.key_switching.noise_standard_deviation = 2.5;
            let context = TfheContext::<u64, Table, _>::try_from_cbs_config(CbsConfig {
                pbs,
                gadget: CbsGadgetConfig {
                    trace: decomposition,
                    scheme_switch: decomposition,
                    output: decomposition,
                },
                input_encoding: CbsInputEncoding::Padded,
                fourier_trace_precision: primus_tfhe_glwe_fourier::FourierTracePrecision::Ordinary,
            })
            .unwrap();
            let parameters = context.parameters();
            let br = parameters.blind_rotation_params();
            let small = if method == SPARSE {
                vec![1, 0, 1, 0, 0, 1, 0, 0]
            } else if method == BlindRotationMethod::Block {
                // One selected block followed by an empty block.
                vec![0, 1, 0, 0, 0, 0]
            } else {
                vec![1023, 0, 1, 1023, 1, 0, 0, 1]
            };
            let ring: Vec<i64> = (0..br.glwe_size().mask_len())
                .map(|i| (i % 3) as i64 - 1)
                .collect();
            let client = ClientKey::new(
                primus_lwe::LweSecretKey::new(
                    small.clone(),
                    pbs.small_lwe.secret_key_distr,
                    parameters.small_lwe().cipher_modulus(),
                ),
                primus_glwe::GlweSecretKey::new(ring.clone(), br.glwe_size(), pbs.bsk_secret_distr),
                order,
            );
            let mut rng = StdRng::seed_from_u64(117);
            let server = KeyGenerator::new(&context)
                .try_generate_circuit_bootstrap_server_key(&client, &mut rng)
                .unwrap();
            let mut fft = context.new_fft_engine();
            match server.server_key().blind_rotation_key() {
                BlindRotationKey::Classic(key) => {
                    assert_eq!(key.size(), br.size());
                    assert_eq!(key.basis(), br.basis());
                    assert_eq!(
                        key.as_slice().len(),
                        2 * small.len() * br.fourier_ggsw_len()
                    );
                    let mut native = Ggsw::new(vec![0u64; br.ggsw_len()]);
                    for ((positive, negative), &s) in
                        key.iter_ternary_controls().unwrap().zip(&small)
                    {
                        for (control, expected) in [
                            (positive, u64::from(s == 1)),
                            (negative, u64::from(s == 1023)),
                        ] {
                            control.write_torus_form(&mut native, &mut fft);
                            assert_eq!(
                                material_selector(native.as_view(), br, &ring, FOURIER_ERROR),
                                expected
                            );
                        }
                    }
                }
                BlindRotationKey::Block(key) => {
                    assert_eq!(key.controls().size(), br.size());
                    assert_eq!(key.controls().basis(), br.basis());
                    assert_eq!(key.block_count(), 2);
                    for block in 0..key.block_count() {
                        let (indices, data) = key.block_data(block);
                        let controls = primus_lattice::ggsw::GgswIter::new(data, br.ggsw_len());
                        assert_eq!(controls.len(), indices.len() + 1);
                        let bits = &small[indices];
                        let dummy = 1 - bits.iter().sum::<u64>();
                        let expected = bits.iter().copied().chain(std::iter::once(dummy));
                        for (control, bit) in controls.zip(expected) {
                            // Exact native key rows retain only sampled noise:
                            // no forward/inverse Fourier roundtrip may create them.
                            assert_eq!(material_selector(control, br, &ring, 8), bit);
                        }
                    }
                }
                BlindRotationKey::Sparse(key) => {
                    let mut selected = vec![0u64; small.len()];
                    let mut dummy_count = 0;
                    assert_eq!(key.controls().size(), br.size());
                    assert_eq!(key.controls().basis(), br.basis());
                    for bucket in 0..key.bucket_count() {
                        let (indices, controls) = key.bucket(bucket);
                        assert_eq!(controls.len(), indices.len() + 1);
                        let mut bucket_sum = 0;
                        for (entry, control) in controls.enumerate() {
                            // sigma=0.7 has truncated support floor(12*sigma)=8;
                            // coefficient key generation adds no FFT rounding.
                            let bit = material_selector(control, br, &ring, 8);
                            bucket_sum += bit;
                            if entry < indices.len() {
                                selected[indices[entry]] += bit;
                            } else {
                                dummy_count += bit;
                            }
                        }
                        assert_eq!(bucket_sum, 1);
                    }
                    assert_eq!(selected, small);
                    assert_eq!(
                        dummy_count,
                        (key.bucket_count() - key.hamming_weight()) as u64
                    );
                }
            }
            let ks = server.server_key().glwe_key_switching_key();
            let output = parameters.glwe_key_switching().output();
            assert_eq!(ks.output_size(), output.size());
            assert_eq!(ks.basis(), output.basis());
            assert_eq!(
                ks.as_slice().len(),
                br.glwe_size().dimension().get() * output.fourier_glev_len()
            );
            // Build the target independently, including explicit-q signed decode
            // and zero padding; do not ask the key-generation helper for s_pad.
            let mut target = vec![0i64; output.glwe_size().mask_len()];
            for (dst, &s) in target.iter_mut().zip(&small) {
                *dst = if s == 1023 { -1 } else { s as i64 };
            }
            let mut native = primus_glwe::GlweCiphertext::new(vec![0u64; output.glwe_len()]);
            for (glev, source) in FourierGlevIter::new(ks.as_slice(), output.fourier_glev_len())
                .zip(client.glwe_secret_key().iter())
            {
                for (row, scalar) in glev
                    .iter_glwe(output.fourier_glwe_len())
                    .zip(output.basis().scalar_iter())
                {
                    row.write_torus_form(&mut native, &mut fft);
                    let phase = native_material_phase(native.as_ref(), &target, 32);
                    for (actual, &s) in phase.into_iter().zip(source) {
                        let expected = scalar.wrapping_mul(s as u64);
                        assert!(
                            phase_error_magnitude(actual, expected, NativeModulus::new())
                                <= FOURIER_ERROR
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn bundle_material_binds_selectors_dummies_and_padded_ks_target() {
    #[cfg(feature = "rustfft")]
    check_bundle_material::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check_bundle_material::<primus_fft::TfheFftTable>();
}

/// Quantization is exact at q=2N. Compare the actual coefficient output phase
/// with an independent integer negacyclic rotation, without Fourier decryption
/// or LUT compilation. The fixture allowance covers sampled and FFT error only;
/// it is neither a general numerical-error budget nor a DFR certificate.
#[test]
fn block_raw_rotation_matches_integer_oracle() {
    #[cfg(feature = "rustfft")]
    {
        check_block_raw_rotation::<u32, primus_fft::RustFftTable>();
        check_block_raw_rotation::<u64, primus_fft::RustFftTable>();
    }
    #[cfg(feature = "tfhe-fft")]
    {
        check_block_raw_rotation::<u32, primus_fft::TfheFftTable>();
        check_block_raw_rotation::<u64, primus_fft::TfheFftTable>();
    }
}

fn check_block_raw_rotation<T: TorusFftValue, Table: FftTable>() {
    use primus_tfhe::rotation::RotationModulusSwitch;
    use primus_tfhe_glwe_fourier::{
        ClientKey, KeyGenerator, block::BlockGlweBlindRotationWorkspace, key::BlindRotationKey,
    };

    // Empty blocks, every position in an odd-width block, an all-zero secret,
    // and a wider block exposing two aggregate pairs and one control tail.
    let secrets: &[(usize, &[u8])] = &[
        (1, &[0]),
        (1, &[1]),
        (2, &[1, 0, 0, 0]),
        (3, &[0, 0, 0]),
        (3, &[1, 0, 0]),
        (3, &[0, 1, 0]),
        (3, &[0, 0, 1]),
        (3, &[0, 0, 0, 0, 0, 0]),
        (3, &[0, 0, 0, 0, 1, 0]),
        (3, &[0, 0, 1, 0, 0, 0]),
        (3, &[0, 1, 0, 1, 0, 0]),
        (5, &[0, 0, 0, 0, 1, 0, 1, 0, 0, 0]),
    ];
    let n = 32;
    for (case, &(block_size, secret)) in secrets.iter().enumerate() {
        let mut config =
            two_domain_config(BlindRotationMethod::Block, PbsOrder::BootstrapKeyswitch);
        config.small_lwe.dimension = LweDimension::new(secret.len());
        config.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
            block_size,
            occupancy: BlockOccupancy::AtMostOne,
        };
        config.small_lwe.cipher_modulus = ModulusConfig::Explicit(T::as_from(2 * n));
        config.bsk_dimension = GlweDimension::new(1);
        config.bsk_poly_length = PolyLength::new(n);
        let context = TfheContext::<T, Table, _>::try_from_pbs_config(config).unwrap();
        let mut rng = StdRng::seed_from_u64(530 + case as u64);
        let generated = ClientKey::generate(context.parameters(), &mut rng);
        let client = ClientKey::new(
            primus_lwe::LweSecretKey::new(
                secret.iter().map(|&s| T::as_from(s)).collect(),
                config.small_lwe.secret_key_distr,
                context.parameters().small_lwe().cipher_modulus(),
            ),
            generated.glwe_secret_key().clone(),
            config.order,
        );
        let BlindRotationKey::Block(key) = KeyGenerator::new(&context)
            .try_generate_blind_rotation_key(&client, &mut rng)
            .unwrap()
        else {
            panic!("expected direct block key");
        };
        let mut workspace = BlockGlweBlindRotationWorkspace::new(&key);
        let rotation =
            RotationModulusSwitch::new(context.parameters().small_lwe().cipher_modulus(), 2 * n, 1);
        let modulus = NativeModulus::new();
        let scalar = T::ONE << (T::BITS - 7);
        let lut = Polynomial::new(
            (0..n)
                .map(|i| T::as_from((i * i + i / 3 + 5) % 8) * scalar)
                .collect::<Vec<_>>(),
        );
        let mut input: primus_lattice::lwe::Lwe<Vec<T>> =
            primus_lattice::lwe::Lwe::zero(secret.len());
        let mut output = context.allocate_accumulator_ciphertext();
        let mut fft = context.new_fft_engine();
        for (pattern, body) in [13, 0, n, 2 * n - 1].into_iter().enumerate() {
            let mut selected_sum = 0;
            for (i, (value, &s)) in input.a_mut().iter_mut().zip(secret).enumerate() {
                let exponent = if pattern == 0 {
                    0
                } else {
                    [0, n, 2 * n - 1][(i + pattern) % 3]
                };
                *value = T::as_from(exponent);
                selected_sum += exponent * usize::from(s);
            }
            *input.b_mut() = T::as_from(body);
            workspace.blind_rotate_lookup_table_to(
                &key,
                &input,
                &lut,
                &rotation,
                &mut output,
                &mut fft,
            );
            let phase =
                native_material_phase(output.as_ref(), client.glwe_secret_key().as_slice(), n);
            let exponent = (selected_sum + 2 * n - body) & (2 * n - 1);
            for (i, &value) in lut.as_ref().iter().enumerate() {
                let destination = i + exponent;
                let expected = if destination & n == 0 {
                    value
                } else {
                    modulus.reduce_neg(value)
                };
                assert!(
                    phase_error_magnitude(phase[destination & (n - 1)], expected, modulus)
                        <= scalar >> 4u32,
                    "secret {secret:?}, pattern {pattern}, coefficient {i}"
                );
            }
        }
    }
}
