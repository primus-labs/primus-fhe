use primus_encoding::{RoundedCodec, phase_error_magnitude};
use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_lwe::LweCiphertext;
use primus_modulus::PowOf2Modulus;
use primus_ntru::{BlockOccupancy, FourierNgswCiphertext, SecretKeyDistr};
use primus_shape::PolyLength;
use primus_tfhe::{
    CbsInputEncoding, CircuitBootstrapLookupTable, DecompositionBaseLog, DecompositionLevelCount,
};
use primus_tfhe_ntru_fourier::{
    BlindRotationMethod, CbsGadgetConfig, CircuitBootstrapServerKey, ClientKey,
    DecompositionConfig, Evaluator, Lwe, PbsConfig, TfheContext, TfheEvaluationError,
    circuit_bootstrap::{CbsEvaluator, CircuitBootstrapEvaluator},
};
use rand::{SeedableRng, rngs::StdRng};

use super::{
    fixture::{PhaseDecryptor, RingSelection, config, decomposition},
    one_hot::check_one_hot_selection,
    pbs::{check_chain, check_many_lut_and_mvb},
};

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

/// Reuse one CBS bundle across the gadget, return and one-hot contracts.
pub(super) fn circuit_selection<T: TorusFftValue, Table: FftTable>(
    pbs: PbsConfig<T, PowOf2Modulus<T>>,
    check_pbs: bool,
) {
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
    if check_pbs {
        // The fixed-weight Classic workflow exercises all three PBS forms
        // with the existing CBS key rather than building two more key sets.
        check_chain(
            &context,
            &client,
            server.server_key(),
            &mut StdRng::seed_from_u64(101),
        );
        check_many_lut_and_mvb(&context, &client, server.server_key());
    }
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

    let secret = client.accumulator_ntru_secret_key();
    let n = context.parameters().poly_length().get();
    // Avoid a short periodic pattern that could hide a coefficient rotation.
    let messages = (0..4)
        .map(|r| {
            (0..n)
                .map(|i| T::as_from(((i >> r) + i / 7 + r) % 4))
                .collect()
        })
        .collect();
    let mut ring = RingSelection::new(&context, secret, messages, &mut rng);
    let program = context
        .compile_cbs_fn(|m| T::as_from(usize::from(m >= 2)))
        .unwrap();
    let mut cbs = context
        .circuit_bootstrap_evaluator_with_lookup_table(&server, program)
        .unwrap();
    reject_msb_program(&context, &server);
    let mut oracle = PhaseDecryptor::new(&context, secret);
    let (input, mut control) = check_predicate(
        &context,
        &client,
        &mut cbs,
        &mut ring,
        &mut oracle,
        &mut rng,
    );
    check_cbs_return(
        &context,
        &client,
        &server,
        cbs,
        input.as_view(),
        &mut control,
        &ring,
    );
    check_one_hot_selection(
        &context,
        &client,
        &server,
        input,
        &mut ring,
        &mut oracle,
        &mut rng,
    );
}

/// Reject GLWE's post-trace correction at the advanced binding boundary,
/// even with matching q/Q, shape and output basis.
fn reject_msb_program<T: TorusFftValue, Table: FftTable>(
    context: &TfheContext<T, Table, PowOf2Modulus<T>>,
    server: &CircuitBootstrapServerKey<T>,
) {
    let basis = context.cbs_parameters().unwrap().gadget().output_basis();
    let modulus = context.parameters().accumulator_ntru().cipher_modulus();
    let input_codec =
        RoundedCodec::new(T::TWO, context.parameters().external_lwe().cipher_modulus());
    let msb = CircuitBootstrapLookupTable::try_from_fn(
        context.parameters().poly_length(),
        &input_codec,
        CbsInputEncoding::MsbBoolean,
        basis,
        modulus,
        T::as_from,
    )
    .unwrap();
    assert!(matches!(
        CircuitBootstrapEvaluator::try_with_lookup_table(
            context,
            server.circuit_bootstrap_key(),
            msb
        ),
        Err(TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable)
    ));
}

/// Check both predicate outcomes, every NGSW row and its one-level product.
fn check_predicate<T: TorusFftValue, Table: FftTable>(
    context: &TfheContext<T, Table, PowOf2Modulus<T>>,
    client: &ClientKey<T>,
    cbs: &mut CbsEvaluator<'_, T, Table>,
    ring: &mut RingSelection<'_, T, Table>,
    oracle: &mut PhaseDecryptor<'_, T, Table>,
    rng: &mut StdRng,
) -> (LweCiphertext<T>, FourierNgswCiphertext<Vec<Complex64>>) {
    let secret = client.accumulator_ntru_secret_key().as_slice();
    let n = context.parameters().poly_length().get();
    let modulus = context.parameters().accumulator_ntru().cipher_modulus();
    let basis = context.cbs_parameters().unwrap().gadget().output_basis();
    let encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
    let mut input = context.allocate_lwe_ciphertext();
    let mut control = cbs.allocate_output();
    let mut probe = context.allocate_accumulator_ciphertext();
    for m in [0, 2] {
        encryptor
            .encrypt_padded_to(T::as_from(m), input.as_mut_view(), rng)
            .unwrap();
        cbs.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
        let bit = T::as_from(usize::from(m >= 2));
        for (row, scalar) in control.iter_ntru(n / 2).zip(basis.scalar_iter()) {
            assert_ngsw_phase(oracle.row_phase(&row), secret, bit, scalar, modulus);
            // Consume each level independently before the encrypted t8 CMux.
            probe.as_mut().fill(T::ZERO);
            probe.as_mut()[0] = scalar;
            cbs.external_product_to(
                control.as_view(),
                probe.as_view(),
                ring.selected.as_mut_view(),
            );
            assert_ngsw_phase(
                oracle.coefficient_phase(&ring.selected),
                secret,
                bit,
                scalar,
                modulus,
            );
        }
        cbs.cmux_to(
            control.as_view(),
            ring.candidates[0].as_view(),
            ring.candidates[1].as_view(),
            ring.selected.as_mut_view(),
        );
        assert_eq!(
            ring.client.decrypt(&ring.selected),
            ring.messages[usize::from(m >= 2)],
            "CBS input {m}"
        );
    }
    (input, control)
}

/// Reject foreign resources before writing, then return the actual selected
/// polynomial through LWE extraction and reuse the resources for ordinary PBS.
fn check_cbs_return<T: TorusFftValue, Table: FftTable>(
    context: &TfheContext<T, Table, PowOf2Modulus<T>>,
    client: &ClientKey<T>,
    server: &CircuitBootstrapServerKey<T>,
    cbs: CbsEvaluator<'_, T, Table>,
    input: Lwe<&[T]>,
    control: &mut FourierNgswCiphertext<Vec<Complex64>>,
    ring: &RingSelection<'_, T, Table>,
) {
    let n = context.parameters().poly_length().get();
    // Equal numeric domains do not establish the operation/resource identity.
    // Reject before writing, then transfer the original CBS resources to PBS.
    let other =
        TfheContext::<T, Table, _>::try_from_parameters(context.parameters().clone()).unwrap();
    let mut foreign = server.bootstrap_resources(&other).unwrap();
    let (mut operation, resources) = cbs.into_parts();
    control.as_mut().fill(Default::default());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        operation.circuit_bootstrap_to(input.as_view(), control, &mut foreign);
    }));
    assert!(result.is_err());
    assert!(control.as_ref().iter().all(|v| *v == Default::default()));
    assert!(matches!(
        Evaluator::try_from_resources(context, foreign, server.server_key(),),
        Err(TfheEvaluationError::IncompatibleLweReturnKey)
    ));
    let mut pbs = Evaluator::try_from_resources(context, resources, server.server_key()).unwrap();
    // Consume the last real CBS→CMux result at both extraction endpoints.
    let mut returned_ring = context.allocate_lwe_ciphertext();
    let ring_decryptor = context
        .ring_return_decryptor(client.external_lwe_secret_key(), T::as_from(8))
        .unwrap();
    for index in [0, 1, n - 1] {
        pbs.return_ring_at_to(ring.selected.as_view(), index, returned_ring.as_mut_view());
        assert_eq!(
            ring_decryptor.decrypt(returned_ring.as_view()).unwrap(),
            ring.messages[1][index]
        );
    }
    let identity = context
        .pbs_lookup_table_compiler()
        .unwrap()
        .compile_fn(T::as_from)
        .unwrap();
    let returned = pbs.apply_lookup_table(input, &identity);
    let decryptor = context
        .pbs_decryptor(client.external_lwe_secret_key())
        .unwrap();
    assert_eq!(
        decryptor.decrypt(returned.as_view()).unwrap(),
        T::as_from(2)
    );
}

#[cfg(feature = "rustfft")]
#[test]
fn rustfft_u32_classic_cbs() {
    let mut config = config(BlindRotationMethod::Classic);
    config.external_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    circuit_selection::<u32, primus_fft::RustFftTable>(config, false);
}

#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_u64_fixed_weight_classic_workflows() {
    let config = config(BlindRotationMethod::Classic);
    circuit_selection::<u64, primus_fft::TfheFftTable>(config, true);
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
