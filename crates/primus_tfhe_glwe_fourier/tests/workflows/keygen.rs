//! Key generation and imported-secret contracts.

use primus_encoding::phase_error_magnitude;
use primus_fft::FftTable;
use primus_glwe::{BlockOccupancy, GlweDimension, SecretKeyDistr};
use primus_modulus::NativeModulus;
use primus_shape::PolyLength;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_glwe_fourier::{
    BlindRotationMethod, CbsConfig, CbsGadgetConfig, CbsInputEncoding, ClientKey,
    DecompositionConfig, PbsOrder, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

use super::oracle::native_material_phase;
use super::parameters::{cbs_gadget, config, two_domain_config};

/// Missing operation state and incompatible imported secrets are rejected
/// before key sampling. A rejected call leaves the generator reusable.
fn check_key_generation_boundaries<Table: FftTable>() {
    use primus_tfhe_glwe_fourier::{KeyGenerationError, KeyGenerator};
    use rand::Rng;

    let gadget = cbs_gadget();
    let mut config = config::<u32>(BlindRotationMethod::Classic);
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
        block_generator.try_generate_blind_rotation_key(&invalid_block, &mut key_rng),
        Err(KeyGenerationError::ClientKey(_))
    ));
    assert!(matches!(
        block_generator.try_generate_server_key(&invalid_block, &mut key_rng),
        Err(KeyGenerationError::ClientKey(_))
    ));
    assert!(matches!(
        block_generator.try_generate_circuit_bootstrap_server_key(&invalid_block, &mut key_rng),
        Err(KeyGenerationError::ClientKey(_))
    ));

    let context = context
        .try_with_circuit_bootstrap(
            gadget,
            CbsInputEncoding::Padded,
            primus_tfhe_glwe::FourierTracePrecision::Ordinary,
        )
        .unwrap();
    let mut generator = KeyGenerator::new(&context);
    let (small, ring, _) = client.clone().into_parts();
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

/// Check every row/level against the inferred body-row bit. Native Block
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
    for (method, occupancy) in [
        (BlindRotationMethod::Classic, BlockOccupancy::AtMostOne),
        (BlindRotationMethod::Block, BlockOccupancy::AtMostOne),
        (BlindRotationMethod::Block, BlockOccupancy::ExactlyOne),
    ] {
        for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
            let mut pbs = two_domain_config::<u64>(method, order);
            if method == BlindRotationMethod::Block {
                pbs.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
                    block_size: 3,
                    occupancy,
                };
            }
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
            let small = if method == BlindRotationMethod::Block {
                // Keep the optional empty block only in the AtMostOne fixture.
                vec![
                    0,
                    1,
                    0,
                    0,
                    0,
                    u64::from(occupancy == BlockOccupancy::ExactlyOne),
                ]
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
                    assert_eq!(key.size(), br.size());
                    assert_eq!(key.basis(), br.basis());
                    assert_eq!(key.blocks().len(), 2);
                    assert_eq!(key.occupancy(), occupancy);
                    for (indices, controls, dummy) in key.blocks() {
                        let controls = primus_lattice::ggsw::GgswIter::new(controls, br.ggsw_len());
                        let dummy_control =
                            primus_lattice::ggsw::GgswIter::new(dummy, br.ggsw_len());
                        let has_dummy = occupancy == BlockOccupancy::AtMostOne;
                        assert_eq!(controls.len(), indices.len());
                        assert_eq!(dummy_control.len(), usize::from(has_dummy));
                        let bits = &small[indices];
                        let dummy = 1 - bits.iter().sum::<u64>();
                        let expected = bits.iter().copied().chain(has_dummy.then_some(dummy));
                        for (control, bit) in controls.chain(dummy_control).zip(expected) {
                            // Exact native key rows retain only sampled noise:
                            // no forward/inverse Fourier roundtrip may create them.
                            assert_eq!(material_selector(control, br, &ring, 8), bit);
                        }
                    }
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
