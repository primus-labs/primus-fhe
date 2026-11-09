//! Small deterministic consumers of the recommended public workflow.
//! n=8/N=128 are arithmetic regression parameters, not security profiles.

use primus_encoding::phase_error_magnitude;
use primus_glwe::{GlweDimension, NttGlweSecretKey, SecretKeyDistr};
use primus_integer::FheUint;
use primus_lwe::LweDimension;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_reduce::RingContext;
use primus_reduce::{EncodeSigned, ReduceMul, ReduceNeg};
use primus_shape::PolyLength;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_glwe_ntt::circuit_bootstrap::{CbsGadgetParameters, CircuitBootstrapEvaluator};
use primus_tfhe_glwe_ntt::{
    BivariateLookupTable, BlindRotationMethod, BooleanGate, CbsConfig, CbsGadgetConfig,
    CbsInputEncoding, DecompositionConfig, GadgetEncryptionConfig, LweConfig, ModulusConfig,
    PbsConfig, PbsMessageConfig, PbsOrder, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

const SPARSE: BlindRotationMethod = BlindRotationMethod::Sparse {
    copy_count: 3,
    bucket_count: 8,
};

/// A Fourier-only selection is rejected before constructing an NTT table or keys.
#[test]
fn cbs_rejects_fourier_split_precision() {
    use primus_tfhe_glwe_ntt::{
        CircuitBootstrapParameterError, FourierTracePrecision, TfheContextError, TfheParameterError,
    };
    let mut pbs = config::<u64>(BlindRotationMethod::Classic);
    pbs.bsk_dimension = GlweDimension::new(1);
    let result = TfheContext::<u64, primus_ntt::U64NttTable>::try_from_cbs_config(CbsConfig {
        pbs,
        gadget: CbsGadgetConfig {
            trace: decomposition(),
            scheme_switch: decomposition(),
            output: decomposition(),
        },
        input_encoding: CbsInputEncoding::Padded,
        fourier_trace_precision: FourierTracePrecision::Split35,
    });
    assert!(matches!(
        result,
        Err(TfheContextError::Parameters(
            TfheParameterError::CircuitBootstrap(
                CircuitBootstrapParameterError::UnsupportedSplitTrace
            )
        ))
    ));
}

fn decomposition() -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: None,
    }
}

/// Keep rounding and transform error far below the test message spacing.
/// Sparse needs fixed-weight binary secrets; classic cases select binary/ternary below.
fn config<T: FheUint>(method: BlindRotationMethod) -> PbsConfig<T> {
    let modulus = ModulusConfig::Explicit(T::as_from(if T::BITS == 32 {
        998_244_353u64
    } else {
        1_125_899_906_826_241u64
    }));
    let secret = SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 3 };
    PbsConfig {
        small_lwe: LweConfig {
            dimension: LweDimension::new(8),
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

/// Exercise the shared Boolean affine preprocessing and signed gate LUTs through
/// real PBS/KS. A single key and workspace serve every gate at external t=4.
#[test]
fn boolean_gate_truth_tables() {
    let mut config = config::<u64>(BlindRotationMethod::Classic);
    config.messages = PbsMessageConfig::new(4);
    let context = TfheContext::<u64, U64NttTable>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(100);

    // Client: independent fresh inputs use the same external Boolean encoding.
    let (client, server) = context.try_generate_keys(&mut rng).unwrap();
    let secret = client.external_lwe_secret_key();
    let encryptor = context.boolean_encryptor(secret).unwrap();
    let decryptor = context.boolean_decryptor(secret).unwrap();
    let mut lhs = context.allocate_lwe_ciphertext();
    let mut rhs = context.allocate_lwe_ciphertext();
    let conditions = [false, true].map(|value| encryptor.encrypt(value, &mut rng).unwrap());

    // Server: reuse gate LUTs, intermediate storage and output across operations.
    let mut evaluator = context.boolean_evaluator(&server).unwrap();
    let mut output = context.allocate_lwe_ciphertext();
    for (value, input) in [false, true].into_iter().zip(&conditions) {
        evaluator.not_to(input.as_view(), output.as_mut_view());
        assert_eq!(decryptor.decrypt(output.as_view()).unwrap(), !value);
    }

    // Ordinary Boolean truth tables, ordered as (00, 01, 10, 11), form an oracle
    // independent of the evaluator's internal LUT scales and affine transforms.
    let gates = [
        (BooleanGate::And, [false, false, false, true]),
        (BooleanGate::Nand, [true, true, true, false]),
        (BooleanGate::Or, [false, true, true, true]),
        (BooleanGate::Nor, [true, false, false, false]),
        (BooleanGate::Xor, [false, true, true, false]),
        (BooleanGate::Xnor, [true, false, false, true]),
    ];
    for (index, (a, b)) in [(false, false), (false, true), (true, false), (true, true)]
        .into_iter()
        .enumerate()
    {
        encryptor
            .encrypt_to(a, lhs.as_mut_view(), &mut rng)
            .unwrap();
        encryptor
            .encrypt_to(b, rhs.as_mut_view(), &mut rng)
            .unwrap();
        for (gate, expected) in gates {
            evaluator.evaluate_binary_to(gate, lhs.as_view(), rhs.as_view(), output.as_mut_view());
            assert_eq!(
                decryptor.decrypt(output.as_view()).unwrap(),
                expected[index],
                "{gate:?}({a}, {b})"
            );
        }
        for (condition, input) in [false, true].into_iter().zip(&conditions) {
            evaluator.mux_to(
                input.as_view(),
                lhs.as_view(),
                rhs.as_view(),
                output.as_mut_view(),
            );
            assert_eq!(
                decryptor.decrypt(output.as_view()).unwrap(),
                if condition { a } else { b },
                "mux({condition}, {a}, {b})"
            );
        }
    }
}

/// Non-power-of-two packing, asymmetric domains and independent output encoding
/// must survive the complete PBS/KS chain, not just LUT compilation.
#[test]
fn bivariate_lookup_packs_and_evaluates_all_input_pairs() {
    let mut config = config::<u64>(BlindRotationMethod::Classic);
    config.messages = PbsMessageConfig::new(12).with_output_modulus(11);
    let context = TfheContext::<u64, U64NttTable>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(105);

    // Client: both inputs use the same external secret and unsigned t_in=12.
    let (client, server) = context.try_generate_keys(&mut rng).unwrap();
    let secret = client.external_lwe_secret_key();
    let encryptor = context.encryptor(secret).unwrap();
    let decryptor = context.pbs_decryptor(secret).unwrap();
    let mut lhs = context.allocate_lwe_ciphertext();
    let mut rhs = context.allocate_lwe_ciphertext();

    // Server: z=x+3*y fills the front half 0..6. Six distinct outputs, including
    // 10, exercise pair order and the full output domain independently of input padding.
    let parameters = context.parameters();
    let codecs = parameters
        .messages()
        .try_rounded_codecs(parameters.external_modulus(), parameters.ring_modulus())
        .unwrap();
    let function = |x: usize, y: usize| (x * x + x * y + 3 * y + 1) as u64;
    let lookup_table = BivariateLookupTable::try_new(
        3,
        2,
        config.bsk_poly_length,
        codecs.input_codec(),
        codecs.lut_output_codec(),
        function,
    )
    .unwrap();
    let mut evaluator = context.evaluator(&server).unwrap();
    let mut packed = context.allocate_lwe_ciphertext();
    let mut output = context.allocate_lwe_ciphertext();
    for x in 0..3 {
        for y in 0..2 {
            encryptor
                .encrypt_padded_to(x as u64, lhs.as_mut_view(), &mut rng)
                .unwrap();
            encryptor
                .encrypt_padded_to(y as u64, rhs.as_mut_view(), &mut rng)
                .unwrap();
            lookup_table.pack_to(lhs.as_view(), rhs.as_view(), packed.as_mut_view());
            evaluator.apply_lookup_table_to(
                packed.as_view(),
                lookup_table.lookup_table(),
                output.as_mut_view(),
            );
            assert_eq!(
                decryptor.decrypt(output.as_view()).unwrap(),
                function(x, y),
                "bivariate input ({x}, {y})"
            );
        }
    }
}

/// Two message programs share a context, key and evaluator. Rounded output
/// at t=8 feeds padded input at t=8; the final full-domain t=16 result may not
/// feed a padded t=16 program. Ciphertexts carry no encoding metadata.
fn chained_pbs<T: FheUint, Table: MonomialNttTable<ValueT = T>, LM>(config: PbsConfig<T, LM>)
where
    LM: RingContext<T> + TryFrom<ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
{
    let context = TfheContext::<T, Table, LM>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(101);
    // Client: only encrypted inputs and the evaluation key leave this side.
    let client = primus_tfhe_glwe_ntt::ClientKey::generate(context.parameters(), &mut rng);
    // Independently generated components retain the same client and context.
    let mut generator = primus_tfhe_glwe_ntt::KeyGenerator::new(&context);
    let blind_rotation = generator
        .try_generate_blind_rotation_key(&client, &mut rng)
        .unwrap();
    assert_eq!(
        matches!(
            blind_rotation,
            primus_tfhe_glwe_ntt::key::BlindRotationKey::Sparse(_)
        ),
        matches!(config.method, BlindRotationMethod::Sparse { .. }),
    );
    let key_switching = generator
        .try_generate_glwe_key_switching_key(
            context.parameters().glwe_key_switching(),
            &client,
            &mut rng,
        )
        .unwrap();
    let server = primus_tfhe_glwe_ntt::ServerKey::new(blind_rotation, key_switching);
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
fn many_lut_and_mvb<T: FheUint, Table: MonomialNttTable<ValueT = T>, LM>(
    mut config: PbsConfig<T, LM>,
) where
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
fn assert_gadget_phase<T: FheUint>(
    phase: &[T],
    secret: Option<&[T::SignedInteger]>,
    bit: T,
    scalar: T,
    modulus: BarrettModulus<T>,
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

/// Inspect and consume every gadget row/level before the ordinary encrypted CMux.
/// Both BR algorithms and PBS orders retain the same output sign/scale contract.
fn circuit_selection<T: FheUint, Table: MonomialNttTable<ValueT = T>, LM>(
    pbs: PbsConfig<T, LM>,
    input_encoding: CbsInputEncoding,
) where
    LM: RingContext<T> + TryFrom<ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
{
    let config = CbsConfig {
        fourier_trace_precision: primus_tfhe_glwe::FourierTracePrecision::Ordinary,
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
    let modulus = context.parameters().ring_modulus();
    let transformed_secret =
        NttGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), context.table());
    let mut phase = Polynomial::new(vec![T::ZERO; n]);
    let mut probe = context.allocate_accumulator_ciphertext();
    let mut scratch = vec![T::ZERO; n];
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
        let bit = T::as_from(selector(m));
        for (row, glev) in control.iter_ntt_glev(size.glev_len()).enumerate() {
            let secret = client.glwe_secret_key().iter().nth(row);
            for (ciphertext, scalar) in glev
                .iter_ntt_glwe(size.glwe_size().glwe_len())
                .zip(gadget.output_basis().scalar_iter())
            {
                transformed_secret.decrypt_phase_to(
                    &ciphertext,
                    &mut phase,
                    modulus,
                    context.table(),
                );
                assert_gadget_phase(phase.as_ref(), secret, bit, scalar, modulus);

                // A single coefficient equal to g_l decomposes as exactly +1
                // in row r/level l. All other digits are zero: an ordinary t8
                // CMux could hide a missing low level, but this probe cannot.
                probe.as_mut().fill(T::ZERO);
                probe.as_mut()[row * n] = scalar;
                cbs.external_product_to(control.as_view(), probe.as_view(), selected.as_mut_view());
                transformed_secret.decrypt_phase_coeff_to(
                    &selected,
                    &mut phase,
                    modulus,
                    context.table(),
                    &mut scratch,
                );
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
        primus_tfhe_glwe_ntt::Evaluator::try_from_parts(
            &context,
            &ks_parameters,
            server.server_key().blind_rotation_key(),
            server.server_key().glwe_key_switching_key(),
        ),
        Err(primus_tfhe_glwe_ntt::TfheEvaluationError::IncompatibleGlweKeySwitchingKey)
    ));
    let key = primus_tfhe_glwe_ntt::KeyGenerator::new(&context)
        .try_generate_glwe_key_switching_key(&ks_parameters, &client, &mut rng)
        .unwrap();
    let mut pbs =
        primus_tfhe_glwe_ntt::Evaluator::try_from_resources(resources, server.server_key())
            .unwrap();
    let mut independent = primus_tfhe_glwe_ntt::Evaluator::try_from_parts(
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
fn u32_classic_chain() {
    let mut config = config(BlindRotationMethod::Classic);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformBinary;
    chained_pbs::<u32, U32NttTable, _>(config);
}

#[test]
fn u64_ternary_batches() {
    let mut config = config(BlindRotationMethod::Classic);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    config.order = PbsOrder::KeyswitchBootstrap;
    many_lut_and_mvb::<u64, U64NttTable, _>(config);
}

#[test]
fn u32_sparse_batches() {
    let config = config(SPARSE);
    many_lut_and_mvb::<u32, U32NttTable, _>(config);
}

#[test]
fn u64_classic_cbs() {
    let mut config = config(BlindRotationMethod::Classic);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    config.order = PbsOrder::KeyswitchBootstrap;
    circuit_selection::<u64, U64NttTable, _>(config, CbsInputEncoding::Padded);
}

#[test]
fn u32_sparse_cbs() {
    let config = config(SPARSE);
    circuit_selection::<u32, U32NttTable, _>(config, CbsInputEncoding::Padded);
}

/// Q26 permits multiple four-source groups per u32 reduction; Q30 covers fallback.
#[test]
fn u32_sparse_bounded_aggregation_pbs() {
    let mut config = config::<u32>(SPARSE);
    config.small_lwe.dimension = LweDimension::new(32);
    config.small_lwe.cipher_modulus = ModulusConfig::Explicit(67_104_769);
    config.ring_modulus = ModulusConfig::Explicit(67_104_769);
    chained_pbs::<u32, U32NttTable, _>(config);
}

/// u64 uses bounded whole-bucket aggregation; u32 sparse cases use another kernel.
#[test]
fn u64_sparse_pbs_and_cbs() {
    let config = config(SPARSE);
    chained_pbs::<u64, U64NttTable, _>(config);
    circuit_selection::<u64, U64NttTable, _>(config, CbsInputEncoding::Padded);
}

/// q uses a power-of-two reducer independently of the accumulator representation.
/// Keep ring secret ternary/rank two to exercise signed padding and extraction.
fn two_domain_config<T: FheUint>(
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
        chained_pbs::<u64, U64NttTable, _>(config);
        many_lut_and_mvb::<u64, U64NttTable, _>(config);
        circuit_selection::<u64, U64NttTable, _>(config, CbsInputEncoding::Padded);
    }
}

#[test]
fn q1024_sparse_returns_and_cbs() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let config = two_domain_config(SPARSE, order);
        chained_pbs::<u32, U32NttTable, _>(config);
        many_lut_and_mvb::<u32, U32NttTable, _>(config);
        circuit_selection::<u32, U32NttTable, _>(config, CbsInputEncoding::Padded);
    }
}

/// The same reducer type may hold distinct q/Q values. Reject the Boolean
/// affine wrapper even in KS→BR, where its external modulus happens to be Q.
#[test]
fn two_domain_boolean_gate_is_rejected() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let mut config = config::<u32>(BlindRotationMethod::Classic);
        config.small_lwe.cipher_modulus = ModulusConfig::Explicit(12289);
        config.messages = PbsMessageConfig::new(4);
        config.order = order;
        let context = TfheContext::<u32, U32NttTable>::try_from_pbs_config(config).unwrap();
        let mut rng = StdRng::seed_from_u64(112);
        let (_, server) = context.try_generate_keys(&mut rng).unwrap();
        assert!(matches!(
            context.boolean_evaluator(&server),
            Err(primus_tfhe::TfheEvaluationError::BooleanRequiresSameModulus)
        ));
    }
}

/// Imported keys and raw quantizers must agree with the declared input domain.
#[test]
fn input_domain_binding_precedes_output_writes() {
    use primus_tfhe::TfheEvaluationError;
    use primus_tfhe::rotation::RotationModulusSwitch;
    use primus_tfhe_glwe_ntt::key::BlindRotationKey;

    for method in [BlindRotationMethod::Classic, SPARSE] {
        let config = two_domain_config::<u32>(method, PbsOrder::BootstrapKeyswitch);
        let context = TfheContext::<u32, U32NttTable, _>::try_from_pbs_config(config).unwrap();
        let mut rng = StdRng::seed_from_u64(114);
        let (_, server) = context.try_generate_keys(&mut rng).unwrap();
        // The shape, gadgets and ring modulus agree; only input q differs.
        let mut wrong_config = config;
        wrong_config.small_lwe.cipher_modulus = ModulusConfig::Explicit(512);
        let wrong_context =
            TfheContext::<u32, U32NttTable, _>::try_from_pbs_config(wrong_config).unwrap();
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
                        let mut workspace = primus_tfhe_glwe_ntt::blind_rotation::NttGlweBlindRotationWorkspace::new(key);
                        key.ntt_blind_rotate_lookup_table_to(
                            &input,
                            &lut,
                            &rotation,
                            &mut output,
                            context.parameters().ring_modulus(),
                            context.table(),
                            &mut workspace,
                        );
                    }
                    BlindRotationKey::Sparse(key) => {
                        let mut workspace =
                            primus_tfhe_glwe_ntt::sparse::SparseGlweBlindRotationWorkspace::new(
                                key,
                            );
                        workspace.blind_rotate_lookup_table_to(
                            key,
                            &input,
                            &lut,
                            &rotation,
                            &mut output,
                            context.table(),
                        );
                    }
                }
            }));
            assert!(result.is_err());
            assert!(output.as_ref().iter().all(|&x| x == 7));
        }
    }
}

/// Both orders use an independent q; classic ternary and sparse binary share the
/// MSB program/consumer contract. Existing padded tests retain u32/u64 coverage.
#[test]
fn msb_boolean_cbs() {
    // Same odd q=Q and the narrower coefficient word use the same program contract.
    circuit_selection::<u32, U32NttTable, _>(
        config(BlindRotationMethod::Classic),
        CbsInputEncoding::MsbBoolean,
    );
    for method in [BlindRotationMethod::Classic, SPARSE] {
        for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
            circuit_selection::<u64, U64NttTable, _>(
                two_domain_config(method, order),
                CbsInputEncoding::MsbBoolean,
            );
        }
    }
}

/// Missing operation state, invalid sparse geometry and imported secrets are
/// rejected before key sampling. A rejected call must leave the generator reusable.
#[test]
fn key_generation_boundaries() {
    type Table = U32NttTable;
    use primus_tfhe_glwe_ntt::{
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

/// Build a noiseless ring phase by schoolbook negacyclic convolution, independently
/// of encryption/extraction kernels. Nonconstant masks and two secret polynomials
/// expose signs, coefficient endpoints and a KS target with a partial last polynomial.
fn ring_return_phase<Table: MonomialNttTable<ValueT = u64>, LM>(
    mut config: PbsConfig<u64, LM>,
    small_dimension: usize,
) where
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
            ring_return_phase::<U64NttTable, _>(same, dimension);
            ring_return_phase::<U64NttTable, _>(split, dimension);
        }
    }
}

/// Batch scheduling must preserve every ciphertext, not just its decoded message.
/// Exercise odd/even bucket counts, short tails, repeated reuse and u32 headroom
/// both with four-source groups and with the canonical single-source fallback.
#[test]
fn sparse_batch_matches_single_inputs() {
    for q in [67_104_769u32, 134_215_681, 998_244_353] {
        for buckets in [7, 8] {
            check_sparse_batch::<u32, U32NttTable>(q, buckets);
        }
    }
    // u64 exercises the same four/pair/single schedule. The smaller modulus fits
    // a GGSW in one tile; the larger modulus reuses descriptors across tiles.
    for q in [65_537, 1_125_899_906_826_241] {
        for buckets in [7, 8] {
            check_sparse_batch::<u64, U64NttTable>(q, buckets);
        }
    }
}

fn check_sparse_batch<T: FheUint, Table: MonomialNttTable<ValueT = T>>(q: T, buckets: usize) {
    use primus_tfhe::rotation::RotationModulusSwitch;
    use primus_tfhe_glwe_ntt::{
        ClientKey, KeyGenerator,
        key::BlindRotationKey,
        sparse::{SparseGlweBlindRotationBatchWorkspace, SparseGlweBlindRotationWorkspace},
    };
    use rand::RngExt;

    let mut config = config::<T>(BlindRotationMethod::Sparse {
        copy_count: 3,
        bucket_count: buckets,
    });
    config.bsk_poly_length = PolyLength::new(32);
    config.ring_modulus = ModulusConfig::Explicit(q);
    config.small_lwe.cipher_modulus = ModulusConfig::Explicit(T::as_from(65537));
    let context = TfheContext::<T, Table>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(518);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let BlindRotationKey::Sparse(key) = KeyGenerator::new(&context)
        .try_generate_blind_rotation_key(&client, &mut rng)
        .unwrap()
    else {
        panic!("expected sparse key")
    };
    let mut single = SparseGlweBlindRotationWorkspace::new(&key);
    let mut batch = SparseGlweBlindRotationBatchWorkspace::new(&key);
    let rotation =
        RotationModulusSwitch::new(context.parameters().small_lwe().cipher_modulus(), 64, 1);
    // Arbitrary canonical inputs and a nonconstant LUT expose rotation/lane errors
    // without relying on a successful decode or on tiny fixture noise margins.
    let inputs: Vec<_> = (0..9)
        .map(|_| {
            let mut input = context.allocate_lwe_ciphertext();
            for value in input.as_mut() {
                *value = T::as_from(rng.random_range(0..65537u64));
            }
            input
        })
        .collect();
    let lut = Polynomial::new((0..32).map(|i| T::as_from(i * 37)).collect::<Vec<_>>());
    let mut expected = vec![context.allocate_accumulator_ciphertext(); inputs.len()];
    let mut actual = expected.clone();
    for (input, output) in inputs.iter().zip(&mut expected) {
        single.blind_rotate_lookup_table_to(&key, input, &lut, &rotation, output, context.table());
    }
    for count in [9, 0, 4, 1, 8, 5, 3, 2, 6, 7] {
        for output in &mut actual {
            output.as_mut().fill(T::ONE);
        }
        batch.blind_rotate_lookup_table_many_to(
            &key,
            &inputs[..count],
            &lut,
            &rotation,
            &mut actual[..count],
            context.table(),
        );
        for (got, want) in actual[..count].iter().zip(&expected) {
            assert_eq!(got.as_ref(), want.as_ref());
        }
        assert!(
            actual[count..]
                .iter()
                .all(|ct| ct.as_ref().iter().all(|&x| x == T::ONE))
        );
    }
    // A malformed late entry/count must not partially write earlier outputs.
    for output in &mut actual {
        output.as_mut().fill(T::ONE);
    }
    actual[8] = primus_lattice::glwe::Glwe::new(vec![T::ONE; 1]);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        batch.blind_rotate_lookup_table_many_to(
            &key,
            &inputs,
            &lut,
            &rotation,
            &mut actual,
            context.table(),
        );
    }));
    assert!(result.is_err());
    assert!(
        actual
            .iter()
            .all(|ct| ct.as_ref().iter().all(|&x| x == T::ONE))
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        batch.blind_rotate_lookup_table_many_to(
            &key,
            &inputs[..4],
            &lut,
            &rotation,
            &mut actual[..3],
            context.table(),
        );
    }));
    assert!(result.is_err());
    assert!(
        actual
            .iter()
            .all(|ct| ct.as_ref().iter().all(|&x| x == T::ONE))
    );
}
