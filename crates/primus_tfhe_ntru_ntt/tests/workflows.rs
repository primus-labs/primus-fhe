//! Small deterministic consumers of the recommended public workflow.
//! n=8/N=128 are arithmetic regression parameters, not security profiles.

use primus_encoding::phase_error_magnitude;
use primus_integer::FheUint;
use primus_modulus::PowOf2Modulus;
use primus_ntru::{LweDimension, SecretKeyDistr};
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_ntru_ntt::{
    BlindRotationMethod, CbsConfig, CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig,
    LweConfig, ModulusConfig, NtruProjectionMethod, PbsConfig, PbsMessageConfig, TfheContext,
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
/// Sparse needs fixed-weight binary secrets; classic cases select binary/ternary below.
fn config<T: FheUint>(method: BlindRotationMethod) -> PbsConfig<T, PowOf2Modulus<T>> {
    let modulus = ModulusConfig::Explicit(T::as_from(if T::BITS == 32 {
        998_244_353u64
    } else {
        1_125_899_906_826_241u64
    }));
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
fn chained_pbs<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    config: PbsConfig<T, PowOf2Modulus<T>>,
) {
    let context = TfheContext::<T, Table, _>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(101);
    // Client: only encrypted inputs and the evaluation key leave this side.
    let mut generator = primus_tfhe_ntru_ntt::KeyGenerator::new(&context);
    let client = generator.try_generate_client_key(&mut rng).unwrap();
    // Independent BR generation does not construct any return material.
    let blind_rotation = generator
        .try_generate_blind_rotation_key(&client, &mut rng)
        .unwrap();
    assert_eq!(
        blind_rotation.sparse_bootstrapping_key().is_some(),
        matches!(config.method, BlindRotationMethod::Sparse { .. }),
    );
    let key_switching = context
        .parameters()
        .try_generate_lwe_return_key(&client, &mut rng)
        .unwrap();
    let server = primus_tfhe_ntru_ntt::ServerKey::new(blind_rotation, key_switching);
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
fn many_lut_and_mvb<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    mut config: PbsConfig<T, PowOf2Modulus<T>>,
) {
    // Keep the established small-parameter ManyLUT noise margin at t_in=8;
    // use different defaults to detect accidental fallback to config messages.
    config.messages = PbsMessageConfig::new(T::as_from(16));
    let context = TfheContext::<T, Table, _>::try_from_pbs_config(config).unwrap();
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

/// Consume the predicate/selectors, then return ordinary NLEV/dual output for a
/// cross-strategy comparison with identical input and ordinary key-generation seeds.
fn circuit_selection<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    pbs: PbsConfig<T, PowOf2Modulus<T>>,
    projection: NtruProjectionMethod,
) -> (Vec<T>, Vec<T>) {
    let sparse = pbs.method == SPARSE;
    let context = TfheContext::<T, Table, _>::try_from_cbs_config(CbsConfig {
        pbs,
        projection,
        fourier_precision: primus_tfhe_ntru::FourierCbsPrecision::ORDINARY,
        gadget: CbsGadgetConfig {
            trace: decomposition(),
            scheme_switch: decomposition(),
            output: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(4),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
        },
    })
    .unwrap();
    // Secret/BR/ordinary trace/SS generation precedes strategy-specific material.
    // Fix its seed, and keep input encryption independent of extra key RNG draws.
    let mut rng = StdRng::seed_from_u64(103);
    let mut input_rng = StdRng::seed_from_u64(104);
    // Client: encrypt nonconstant candidate polynomials under the ring secret.
    let (client, server) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
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
        primus_tfhe_ntru_ntt::circuit_bootstrap::CircuitBootstrapEvaluator::try_with_lookup_table(
            &context,
            server.circuit_bootstrap_key(),
            msb,
        ),
        Err(primus_tfhe::TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable)
    ));
    let mut phase = Polynomial::new(vec![T::ZERO; n]);
    let mut probe = context.allocate_accumulator_ciphertext();
    let transformed =
        primus_ntru::NttNtruSecretKey::try_from_coeff_secret_key(secret, modulus, context.table())
            .unwrap();
    let mut transformed_probe = primus_lattice::ntru::NttNtru::new(vec![T::ZERO; n]);
    for m in [0, 3, 1, 2] {
        encryptor
            .encrypt_padded_to(T::as_from(m), input.as_mut_view(), &mut input_rng)
            .unwrap();
        cbs.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
        let bit = T::as_from(usize::from(m >= 2));
        for (row, scalar) in control.iter_ntt_ntru(n).zip(basis.scalar_iter()) {
            transformed.decrypt_phase_to(&row, &mut phase, modulus, context.table());
            assert_ngsw_phase(phase.as_ref(), secret.as_slice(), bit, scalar, modulus);
            // A lone gadget weight consumes exactly this output level. Ordinary
            // t8 CMux alone could hide a missing low level.
            probe.as_mut().fill(T::ZERO);
            probe.as_mut()[0] = scalar;
            cbs.external_product_to(control.as_view(), probe.as_view(), selected.as_mut_view());
            selected.write_ntt_form(&mut transformed_probe, context.table());
            transformed.decrypt_phase_to(&transformed_probe, &mut phase, modulus, context.table());
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
        primus_tfhe_ntru_ntt::Evaluator::try_from_resources(&context, foreign, server.server_key()),
        Err(primus_tfhe::TfheEvaluationError::IncompatibleLweReturnKey)
    ));
    let mut pbs = primus_tfhe_ntru_ntt::Evaluator::try_from_resources(
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
    let mut full = one_hot.allocate_ngsw_output();
    let mut ordinary_outputs = None;
    for m in [0, 3, 1, 2, 0] {
        encryptor
            .encrypt_padded_to(T::as_from(m), input.as_mut_view(), &mut input_rng)
            .unwrap();
        one_hot.one_hot_nonzero_ngsw_to(input.as_view(), &mut selectors);
        one_hot.one_hot_ngsw_to(input.as_view(), &mut full);
        assert_eq!(&full[one_hot.ngsw_selector_len()..], selectors);
        // Full output also computes delta_0; consume it independently.
        let zero = one_hot.ngsw_selectors(&full).selector(0).unwrap();
        one_hot.cmux_to(
            zero,
            candidates[0].as_view(),
            candidates[1].as_view(),
            selected.as_mut_view(),
        );
        ring_client.decrypt_to(&selected, &mut decoded);
        assert_eq!(decoded, messages[usize::from(m == 0)]);
        one_hot.cmux_k_to(
            one_hot.nonzero_ngsw_selectors(&selectors),
            candidates[0].as_view(),
            &candidates[1..],
            selected.as_mut_view(),
        );
        ring_client.decrypt_to(&selected, &mut decoded);
        assert_eq!(decoded, messages[m], "one-hot input {m}");
        if m == 3 {
            // Dual output retains ordinary trace/SS even for a fused strategy.
            // Full and compact dual outputs share exactly the same nonzero rows.
            let mut nlev = one_hot.allocate_nlev_output();
            let mut standalone = one_hot.allocate_nlev_output();
            one_hot.one_hot_nlev_to(input.as_view(), &mut standalone);
            one_hot.one_hot_nlev_and_nonzero_ngsw_to(input.as_view(), &mut nlev, &mut selectors);
            assert_eq!(nlev, standalone);
            one_hot.one_hot_to(input.as_view(), &mut nlev, &mut full);
            assert_eq!(nlev, standalone);
            assert_eq!(&full[one_hot.ngsw_selector_len()..], selectors);
            ordinary_outputs = Some((nlev, full.clone()));
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
    if sparse {
        // Paired BR callbacks must preserve the owning evaluator's strategy and
        // the NLEV/dual exception. Compare against single-input calls byte-for-byte.
        let mut inputs = [input.clone(), input];
        for (message, input) in [0, 3].into_iter().zip(&mut inputs) {
            encryptor
                .encrypt_padded_to(T::as_from(message), input.as_mut_view(), &mut input_rng)
                .unwrap();
        }
        assert_sparse_pair_matches_single(one_hot, [inputs[0].as_view(), inputs[1].as_view()]);
    }
    ordinary_outputs.unwrap()
}

/// Scoped pair callbacks reuse the same projection owner, strategy and dirty buffers.
fn assert_sparse_pair_matches_single<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    one_hot: primus_tfhe_ntru_ntt::OneHotEvaluator<'_, T, Table>,
    inputs: [primus_tfhe_ntru_ntt::Lwe<&[T]>; 2],
) {
    let (mut operation, mut resources) = one_hot.into_parts();
    let mut pair = operation.new_sparse_pair_workspace(&resources).unwrap();
    let mut nlev = operation.allocate_nlev_output();
    let mut ngsw = operation.allocate_nonzero_ngsw_output();
    let mut expected_nlev = [nlev.clone(), nlev.clone()];
    let mut expected_ngsw = [ngsw.clone(), ngsw.clone()];
    // Reuse dirty buffers across NGSW-only, NLEV-only and dual calls.
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
        operation.with_sparse_pair(
            [inputs[0].as_view(), inputs[1].as_view()],
            &mut pair,
            &mut resources,
            |i, projection| {
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
    }
}

#[test]
fn u32_classic_chain() {
    let mut config = config(BlindRotationMethod::Classic);
    config.external_lwe.secret_key_distr = SecretKeyDistr::UniformBinary;
    chained_pbs::<u32, U32NttTable>(config);
}

#[test]
fn u64_ternary_batches() {
    let mut config = config(BlindRotationMethod::Classic);
    config.external_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    many_lut_and_mvb::<u64, U64NttTable>(config);
}

#[test]
fn u32_sparse_batches() {
    let config = config(SPARSE);
    many_lut_and_mvb::<u32, U32NttTable>(config);
}

#[test]
fn u64_classic_cbs() {
    let mut config = config(BlindRotationMethod::Classic);
    config.external_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    use NtruProjectionMethod::*;
    let baseline = circuit_selection::<u64, U64NttTable>(config, Separate);
    for projection in [FusedLastStage, FusedLastThreeStages, PairedTrace] {
        let ordinary = circuit_selection::<u64, U64NttTable>(config, projection);
        // Fixed input/BR/trace/SS material: NLEV and dual NGSW must be identical,
        // independently of the selected NGSW-only algorithm and later KS sampling.
        assert_eq!(ordinary, baseline, "{projection:?}");
    }
}

#[test]
fn u32_sparse_cbs() {
    let config = config(SPARSE);
    circuit_selection::<u32, U32NttTable>(config, NtruProjectionMethod::PairedTrace);
}

/// Equal gadget bases do not make CBS material from another ring compatible.
#[test]
fn default_cbs_rejects_mixed_ring_material() {
    use primus_tfhe_ntru_ntt::{CircuitBootstrapServerKey, TfheEvaluationError};

    type Context = TfheContext<u32, U32NttTable, PowOf2Modulus<u32>>;
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

    // BR/KS and the program match this context; only trace/SS use another N.
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
#[test]
fn key_generation_boundaries() {
    type Table = U32NttTable;
    use primus_ntru::{NtruError, NtruSecretKey};
    use primus_tfhe_ntru_ntt::{ClientKey, KeyGenerationError, KeyGenerator, TfheKeyError};
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
    let other = primus_tfhe_ntru_ntt::PbsParameters::try_from_config(other_config).unwrap();
    assert!(matches!(
        generator.try_generate_circuit_bootstrap_keys_with_public_lift(
            Some(other.blind_rotation()),
            &mut rng
        ),
        Err(KeyGenerationError::IncompatiblePublicLiftParameters)
    ));

    // Sparse preflight must also precede client generation in both complete paths.
    let mut invalid_config = config;
    invalid_config.method = BlindRotationMethod::Sparse {
        copy_count: 0,
        bucket_count: 8,
    };
    let invalid =
        TfheContext::<u32, Table, _>::try_from_cbs_config(primus_tfhe_ntru_ntt::CbsConfig {
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
fn projection_selection_is_bound_to_cbs_material() {
    use NtruProjectionMethod::*;
    use primus_tfhe_ntru_ntt::circuit_bootstrap::{
        CircuitBootstrapEvaluator, OneHotCircuitBootstrapEvaluator,
    };
    use primus_tfhe_ntru_ntt::{
        CbsConfig, CbsParameters, NtruProjectionMethod, TfheEvaluationError,
    };
    type Context = TfheContext<u32, U32NttTable, PowOf2Modulus<u32>>;
    let pbs = config(BlindRotationMethod::Classic);
    let gadget = CbsGadgetConfig {
        trace: decomposition(),
        scheme_switch: decomposition(),
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(4),
            level_count: Some(DecompositionLevelCount::new(2)),
        },
    };
    let plain = Context::try_from_pbs_config(pbs).unwrap();
    // The convenience constructor's default is independent of the performance presets.
    let default = Context::try_from_pbs_config(pbs)
        .unwrap()
        .try_with_circuit_bootstrap(gadget)
        .unwrap();
    assert_eq!(default.cbs_parameters().unwrap().projection(), Separate);
    for preset in [
        primus_tfhe_ntru_ntt::experimental::CLASSIC_CBS_U64,
        primus_tfhe_ntru_ntt::experimental::CLASSIC_ONE_HOT_U64,
    ] {
        assert_eq!(preset.projection, PairedTrace);
    }
    let mut rng = StdRng::seed_from_u64(107);
    // PBS-only setup must reject CBS key generation before any material is sampled.
    assert!(matches!(
        plain.try_generate_circuit_bootstrap_keys(&mut rng),
        Err(primus_tfhe_ntru::KeyGenerationError::MissingCircuitBootstrapParameters)
    ));
    for projection in [Separate, FusedLastStage, FusedLastThreeStages, PairedTrace] {
        let context = Context::try_from_cbs_config(CbsConfig {
            pbs,
            gadget,
            projection,
            fourier_precision: primus_tfhe_ntru::FourierCbsPrecision::ORDINARY,
        })
        .unwrap();
        let (_, server) = context
            .try_generate_circuit_bootstrap_keys(&mut rng)
            .unwrap();
        let key = server.circuit_bootstrap_key();
        assert_eq!(context.cbs_parameters().unwrap().projection(), projection);
        assert_eq!(key.projection_method(), projection);
        context.circuit_bootstrap_evaluator(&server).unwrap();
        context.one_hot_evaluator(&server).unwrap();

        // Same domain/bases, different projection: reject every configured binding.
        let other_method = if projection == Separate {
            PairedTrace
        } else {
            Separate
        };
        let other = Context::try_from_cbs_parameters(
            CbsParameters::try_with_config(plain.parameters().clone(), gadget, other_method)
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            other.circuit_bootstrap_evaluator_with_lookup_table(
                &server,
                other.compile_cbs_identity().unwrap(),
            ),
            Err(TfheEvaluationError::IncompatibleCircuitBootstrapKey)
        ));
        assert!(matches!(
            other.one_hot_evaluator(&server),
            Err(primus_tfhe_ntru::OneHotBootstrapError::Evaluation(
                TfheEvaluationError::IncompatibleCircuitBootstrapKey
            ))
        ));
        let codec = other.cbs_parameters().unwrap().input_codec();
        assert!(matches!(
            CircuitBootstrapEvaluator::try_new(&other, key, codec),
            Err(TfheEvaluationError::IncompatibleCircuitBootstrapKey)
        ));
        assert!(matches!(
            CircuitBootstrapEvaluator::try_with_lookup_table(
                &other,
                key,
                other.compile_cbs_identity().unwrap(),
            ),
            Err(TfheEvaluationError::IncompatibleCircuitBootstrapKey)
        ));
        assert!(matches!(
            OneHotCircuitBootstrapEvaluator::try_new(&other, key, codec),
            Err(primus_tfhe_ntru::OneHotBootstrapError::Evaluation(
                TfheEvaluationError::IncompatibleCircuitBootstrapKey
            ))
        ));

        // PBS-only component composition takes the supplied key's algorithm.
        CircuitBootstrapEvaluator::try_new(&plain, key, codec).unwrap();
        CircuitBootstrapEvaluator::try_with_lookup_table(
            &plain,
            key,
            other.compile_cbs_identity().unwrap(),
        )
        .unwrap();
        OneHotCircuitBootstrapEvaluator::try_new(&plain, key, codec).unwrap();
    }
}
