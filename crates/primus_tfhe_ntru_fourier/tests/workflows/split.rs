use primus_fft::{Complex64, FftTable};
use primus_lattice::nlev::FourierNlev;
use primus_lwe::LweCiphertext;
use primus_modulus::PowOf2Modulus;
use primus_ntru::{
    BlockOccupancy, FourierNtruExternalProductWorkspace, LweDimension, NtruSecretKey,
    SecretKeyDistr,
};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_ntru_fourier::{
    BlindRotationMethod, CbsConfig, CbsGadgetConfig, CircuitBootstrapServerKey, ClientKey,
    DecompositionConfig, FourierCbsPrecision, FourierNgswSelectors, FourierPrecision as P,
    KeyGenerator, NtruProjectionMethod, OneHotEvaluator, PbsMessageConfig, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

use super::{
    fixture::{RingSelection, config, decomposition, native_phase},
    one_hot::assert_pair_matches_single,
    pbs::check_many_lut_and_mvb,
};

/// Shared parameter preparation is representation-independent; only the backend
/// rejects fusion, for both raw configuration and independently prepared parameters.
fn reject_unsupported_projection<Table: FftTable>() {
    use NtruProjectionMethod::*;
    use primus_tfhe_ntru_fourier::{CbsParameters, TfheContextError};
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

/// The separately sampled ordinary NLEV[1] lifts a public polynomial even
/// when split BR has an all-zero first block.
fn assert_public_lift<Table: FftTable>(
    context: &TfheContext<u64, Table, PowOf2Modulus<u64>>,
    secret: &NtruSecretKey<u64>,
    lift: &FourierNlev<Vec<Complex64>>,
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
    let mut product = FourierNtruExternalProductWorkspace::new(context.parameters().poly_length());
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
    // Both logN parities, multirow output and unequal trace/SS limb widths.
    for (split_br, projection, n, message_modulus, levels, occupancy) in [
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
        check_split_case::<Table>(split_br, projection, n, message_modulus, levels, occupancy);
    }
}

/// Run the precision and projection combination using one prepared key bundle.
fn check_split_case<Table: FftTable>(
    split_br: bool,
    projection: NtruProjectionMethod,
    n: usize,
    message_modulus: u64,
    levels: usize,
    occupancy: Option<BlockOccupancy>,
) {
    use NtruProjectionMethod::{PairedTrace, Separate};

    let c = split_config(split_br, projection, n, message_modulus, levels, occupancy);
    let method = c.pbs.method;
    let last_message = message_modulus / 2 - 1;
    let context = TfheContext::<u64, Table, _>::try_from_cbs_config(c).unwrap();
    assert_eq!(
        context
            .cbs_parameters()
            .unwrap()
            .gadget()
            .output_basis()
            .level_count()
            .get(),
        levels
    );
    let mut rng = StdRng::seed_from_u64(if method == BlindRotationMethod::Block {
        106
    } else {
        414
    });
    // Both ordinary and split Block BR need independent lift material.
    // AtMostOne exercises each with an empty first block.
    let public_lift_requested =
        occupancy == Some(BlockOccupancy::AtMostOne) && (!split_br || projection == Separate);
    let (client, server, public_lift) = KeyGenerator::new(&context)
        .try_generate_circuit_bootstrap_keys_with_public_lift(
            public_lift_requested.then_some(context.parameters().blind_rotation()),
            &mut rng,
        )
        .unwrap();
    if split_br && method == BlindRotationMethod::Block && projection == Separate {
        // The same split BR key also handles interleaved stride four and MVB factor lifts.
        check_many_lut_and_mvb(&context, &client, server.server_key());
    }
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

    let messages = (0..2)
        .map(|r| (0..n).map(|i| ((i / 7 + i + r) % 4) as u64).collect())
        .collect();
    let mut ring = RingSelection::new(
        &context,
        client.accumulator_ntru_secret_key(),
        messages,
        &mut rng,
    );
    let mut input = check_pbs_and_cbs(
        &context,
        &client,
        &server,
        &mut ring,
        last_message,
        &mut rng,
    );
    if projection == PairedTrace {
        let check_zero = split_br && occupancy == Some(BlockOccupancy::AtMostOne);
        check_split_selectors(
            &context, &client, &server, &mut ring, &mut input, check_zero, &mut rng,
        );
    }

    // Pair differentials cover ordinary BR with split projection, both
    // split BR occupancy laws, and the nonshared Separate projection.
    let check_pair = matches!(
        (split_br, projection, occupancy),
        (false, PairedTrace, Some(BlockOccupancy::AtMostOne))
            | (true, PairedTrace, Some(_))
            | (true, Separate, Some(BlockOccupancy::ExactlyOne) | None)
    );
    if check_pair {
        let encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
        let mut inputs = [input.clone(), input.clone(), input];
        for (m, input) in [0, last_message, 1].into_iter().zip(&mut inputs) {
            encryptor
                .encrypt_padded_to(m, input.as_mut_view(), &mut rng)
                .unwrap();
        }
        assert_pair_matches_single(
            context.one_hot_evaluator(&server).unwrap(),
            inputs.each_ref().map(|input| input.as_view()),
            method == BlindRotationMethod::Block,
        );
    }
}

/// Prepare the BR and projection precisions independently. The fused path
/// deliberately uses unequal trace and scheme-switch limb widths.
fn split_config(
    split_br: bool,
    projection: NtruProjectionMethod,
    n: usize,
    message_modulus: u64,
    levels: usize,
    occupancy: Option<BlockOccupancy>,
) -> CbsConfig<u64, PowOf2Modulus<u64>> {
    use NtruProjectionMethod::Separate;

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
    pbs_config.messages = PbsMessageConfig::new(message_modulus);
    CbsConfig {
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
            blind_rotation: if split_br {
                P::Split { low_bits: 40 }
            } else {
                P::Ordinary
            },
            trace: P::Split { low_bits: 40 },
            scheme_switch: if split_br || projection != Separate {
                P::Split { low_bits: 35 }
            } else {
                P::Ordinary
            },
        },
    }
}

/// Exercise a single split-configured BSK through ordinary PBS and encrypted
/// CBS selection, reusing one LWE input at both ends of the message interval.
fn check_pbs_and_cbs<Table: FftTable>(
    context: &TfheContext<u64, Table, PowOf2Modulus<u64>>,
    client: &ClientKey<u64>,
    server: &CircuitBootstrapServerKey<u64>,
    ring: &mut RingSelection<'_, u64, Table>,
    last_message: u64,
    rng: &mut StdRng,
) -> LweCiphertext<u64> {
    let encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
    let mut cbs = context
        .circuit_bootstrap_evaluator_with_lookup_table(
            server,
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
            .encrypt_padded_to(m, input.as_mut_view(), rng)
            .unwrap();
        let output = pbs.apply_lookup_table(input.as_view(), &lut);
        assert_eq!(decoder.decrypt(output.as_view()).unwrap(), m);
        cbs.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
        cbs.cmux_to(
            control.as_view(),
            ring.candidates[0].as_view(),
            ring.candidates[1].as_view(),
            ring.selected.as_mut_view(),
        );
        ring.client.decrypt_to(&ring.selected, &mut ring.decoded);
        assert_eq!(ring.decoded, ring.messages[usize::from(m >= 2)]);
    }

    input
}

/// Consume full and compact Fourier controls. For the one-target fallback
/// the two routes round differently, so decode their outputs independently.
fn check_split_selectors<Table: FftTable>(
    context: &TfheContext<u64, Table, PowOf2Modulus<u64>>,
    client: &ClientKey<u64>,
    server: &CircuitBootstrapServerKey<u64>,
    ring: &mut RingSelection<'_, u64, Table>,
    input: &mut LweCiphertext<u64>,
    check_zero: bool,
    rng: &mut StdRng,
) {
    let encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
    let message_modulus = context.parameters().messages().input_modulus;
    let last_message = message_modulus / 2 - 1;
    let basis = context.cbs_parameters().unwrap().gadget().output_basis();
    let is_block = context.parameters().blind_rotation_method() == BlindRotationMethod::Block;
    let mut one_hot = context.one_hot_evaluator(server).unwrap();
    let mut full = one_hot.allocate_ngsw_output();
    let mut nonzero = one_hot.allocate_nonzero_ngsw_output();
    let mut nlev = one_hot.allocate_nlev_output();
    for m in [last_message, 0] {
        encryptor
            .encrypt_padded_to(m, input.as_mut_view(), rng)
            .unwrap();
        one_hot.one_hot_ngsw_to(input.as_view(), &mut full);
        one_hot.one_hot_nonzero_ngsw_to(input.as_view(), &mut nonzero);
        let len = one_hot.ngsw_selector_len();
        if message_modulus > 4 || basis.level_count().get() > 1 {
            assert_eq!(&full[len..], &nonzero);
        } else {
            let selectors = one_hot.nonzero_ngsw_selectors(&nonzero);
            check_selected_controls(&mut one_hot, selectors, ring, m);
        }
        let selectors = one_hot.ngsw_selectors(&full);
        check_selected_controls(&mut one_hot, selectors, ring, m);

        // The split AtMostOne fixture also consumes dual controls at zero:
        // the compact controls are all false and full delta_0 is true.
        if m == 0 && !check_zero {
            continue;
        }
        one_hot.one_hot_nlev_and_nonzero_ngsw_to(input.as_view(), &mut nlev, &mut nonzero);
        let selectors = one_hot.nonzero_ngsw_selectors(&nonzero);
        check_selected_controls(&mut one_hot, selectors, ring, m);
        if is_block {
            let mut standalone = one_hot.allocate_nlev_output();
            one_hot.one_hot_nlev_to(input.as_view(), &mut standalone);
            assert_eq!(standalone, nlev);
            assert_split_nlev_phases(
                &one_hot,
                &nlev,
                client.accumulator_ntru_secret_key().as_slice(),
                basis,
                m,
            );
            one_hot.one_hot_to(input.as_view(), &mut nlev, &mut full);
            assert_eq!(standalone, nlev);
            let selectors = one_hot.ngsw_selectors(&full);
            check_selected_controls(&mut one_hot, selectors, ring, m);
        }
    }
}

fn check_selected_controls<Table: FftTable>(
    one_hot: &mut OneHotEvaluator<'_, u64, Table>,
    selectors: FourierNgswSelectors<'_>,
    ring: &mut RingSelection<'_, u64, Table>,
    m: u64,
) {
    for (r, control) in selectors.iter() {
        one_hot.cmux_to(
            control,
            ring.candidates[0].as_view(),
            ring.candidates[1].as_view(),
            ring.selected.as_mut_view(),
        );
        ring.client.decrypt_to(&ring.selected, &mut ring.decoded);
        assert_eq!(ring.decoded, ring.messages[usize::from(r as u64 == m)]);
    }
}

/// Decrypt the coefficient NLEV rows with the independent negacyclic oracle.
fn assert_split_nlev_phases<Table: FftTable>(
    one_hot: &OneHotEvaluator<'_, u64, Table>,
    nlev: &[u64],
    secret: &[i64],
    basis: &primus_decompose::primitive::ApproxSignedBasis<u64>,
    m: u64,
) {
    for (selector, control) in one_hot.nlev_selectors(nlev).iter() {
        for (row, scalar) in control.iter_ntru(secret.len()).zip(basis.scalar_iter()) {
            let phase = native_phase(row.as_ref(), secret);
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
