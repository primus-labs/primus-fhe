//! GLWE-specific capacity, external client roles and BR/return domains.

use primus_glwe::GlweDimension;
use primus_lwe::{LweDimension, LweSecretKey};
use primus_modulus::NativeModulus;
use primus_shape::PolyLength;
use primus_tfhe::{BlindRotationMethod, DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_glwe::{
    BlockOccupancy, CbsGadgetConfig, CbsParameters, ClientKey, DecompositionConfig,
    GadgetEncryptionConfig, LweConfig, ModulusConfig, PbsConfig, PbsMessageConfig, PbsOrder,
    PbsParameters, SecretKeyDistr, TfheKeyError, TfheParameterError,
};
use rand::{SeedableRng, rngs::StdRng};

fn decomposition(base: u32) -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(base),
        level_count: None,
    }
}

/// Stored groups follow the declared law; public ring-KS padding is not a block.
#[test]
fn block_control_storage_binds_complete_logical_groups() {
    use primus_tfhe_glwe::{BlockBootstrappingKeyError, BlockGlweBootstrappingKey};

    let parameters = PbsParameters::try_from_config(config(PbsOrder::BootstrapKeyswitch)).unwrap();
    let gadget = parameters.blind_rotation_params();
    let ggsw_len = gadget.ggsw_len();
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        let count = 3 + usize::from(occupancy == BlockOccupancy::AtMostOne);
        let data: Vec<u32> = (0..2 * count * ggsw_len)
            .map(|index| index as u32)
            .collect();
        let key = BlockGlweBootstrappingKey::try_new(
            data.clone(),
            LweDimension::new(6),
            3,
            occupancy,
            gadget,
            NativeModulus::<u32>::new(),
        )
        .unwrap();
        assert_eq!(key.occupancy(), occupancy);
        assert_eq!(key.block_count(), 2);
        assert_eq!(key.controls().input_dimension(), LweDimension::new(6));
        for block_index in 0..2 {
            let (range, controls) = key.block_data(block_index);
            assert_eq!(range, 3 * block_index..3 * (block_index + 1));
            assert_eq!(
                controls,
                &data[count * block_index * ggsw_len..count * (block_index + 1) * ggsw_len]
            );
        }
        for block_size in [0, 4] {
            assert!(matches!(
                BlockGlweBootstrappingKey::try_new(
                    data.clone(),
                    LweDimension::new(6),
                    block_size,
                    occupancy,
                    gadget,
                    NativeModulus::<u32>::new(),
                ),
                Err(BlockBootstrappingKeyError::InvalidBlockGeometry { .. })
            ));
        }
        assert!(matches!(
            BlockGlweBootstrappingKey::try_new(
                vec![0; data.len() - 1],
                LweDimension::new(6),
                3,
                occupancy,
                gadget,
                NativeModulus::<u32>::new(),
            ),
            Err(BlockBootstrappingKeyError::StorageLengthMismatch { .. })
        ));
        let other = if occupancy == BlockOccupancy::AtMostOne {
            BlockOccupancy::ExactlyOne
        } else {
            BlockOccupancy::AtMostOne
        };
        assert!(matches!(
            BlockGlweBootstrappingKey::try_new(
                data,
                LweDimension::new(6),
                3,
                other,
                gadget,
                NativeModulus::<u32>::new(),
            ),
            Err(BlockBootstrappingKeyError::StorageLengthMismatch { .. })
        ));
    }
}

/// Precision is an operation choice even without a compiled Fourier backend.
/// Its numerical restrictions are checked once when preparing CBS parameters.
#[test]
fn split_trace_precision_requires_native_u64_rank_one_and_bounded_secret() {
    use primus_tfhe_glwe::{
        CbsInputEncoding, CircuitBootstrapParameterError, FourierTracePrecision,
    };

    let prepare = |pbs| {
        CbsParameters::try_with_config(
            PbsParameters::try_from_config(pbs).unwrap(),
            gadget(),
            CbsInputEncoding::Padded,
            FourierTracePrecision::Split35,
        )
    };
    let unsupported = || {
        TfheParameterError::CircuitBootstrap(CircuitBootstrapParameterError::UnsupportedSplitTrace)
    };
    let mut narrow = config(PbsOrder::BootstrapKeyswitch);
    narrow.bsk_dimension = GlweDimension::new(1);
    assert!(matches!(
        CbsParameters::try_with_config(
            PbsParameters::try_from_config(narrow).unwrap(),
            gadget(),
            CbsInputEncoding::Padded,
            FourierTracePrecision::Split35,
        ),
        Err(error) if error == unsupported()
    ));

    let pbs: PbsConfig<u64, NativeModulus<u64>> = PbsConfig {
        small_lwe: LweConfig {
            dimension: LweDimension::new(17),
            cipher_modulus: ModulusConfig::Native,
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 1.0,
        },
        ring_modulus: ModulusConfig::Native,
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(32),
        bsk_secret_distr: SecretKeyDistr::UniformTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: decomposition(4),
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: decomposition(3),
            noise_standard_deviation: 3.2,
        },
        method: BlindRotationMethod::Classic,
        messages: PbsMessageConfig::new(8),
        order: PbsOrder::BootstrapKeyswitch,
    };
    assert!(prepare(pbs).is_ok());
    for invalid in [
        PbsConfig {
            bsk_dimension: GlweDimension::new(2),
            ..pbs
        },
        PbsConfig {
            bsk_secret_distr: SecretKeyDistr::Gaussian {
                standard_deviation: 1.0,
            },
            ..pbs
        },
    ] {
        assert!(matches!(prepare(invalid), Err(error) if error == unsupported()));
    }
}

fn config(order: PbsOrder) -> PbsConfig<u32, NativeModulus<u32>> {
    PbsConfig {
        small_lwe: LweConfig {
            dimension: LweDimension::new(17),
            cipher_modulus: ModulusConfig::Native,
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 1.0,
        },
        ring_modulus: ModulusConfig::Native,
        bsk_dimension: GlweDimension::new(2),
        bsk_poly_length: PolyLength::new(32),
        bsk_secret_distr: SecretKeyDistr::UniformTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: decomposition(4),
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: decomposition(3),
            noise_standard_deviation: 3.2,
        },
        method: BlindRotationMethod::Classic,
        messages: PbsMessageConfig::new(8),
        order,
    }
}

fn gadget() -> CbsGadgetConfig {
    CbsGadgetConfig {
        trace: decomposition(4),
        scheme_switch: decomposition(4),
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(4),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    }
}

#[test]
fn clients_preserve_external_roles_and_message_overrides() {
    // BR→KS uses the small encoded secret; KS→BR uses the signed kN ring secret.
    // Public encryption needs no transform table or bootstrapping key.
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let parameters = PbsParameters::try_from_config(config(order)).unwrap();
        let mut rng = StdRng::seed_from_u64(103);
        let client = ClientKey::generate(&parameters, &mut rng);
        let secret = client.external_lwe_secret_key();
        let public_key = parameters
            .try_generate_public_key(secret, &mut rng)
            .unwrap();
        let encryptor = parameters.public_encryptor(&public_key).unwrap();
        let decryptor = parameters.pbs_decryptor(secret).unwrap();
        for message in [0, 3, 7] {
            let ciphertext = encryptor.encrypt(message, &mut rng).unwrap();
            assert_eq!(decryptor.decrypt(ciphertext.as_view()).unwrap(), message);
        }

        // A per-operation override reuses the keys and sampling domain while
        // admitting messages outside the original t=8 domain.
        let explicit_decoder = parameters
            .pbs_decryptor_with_message_modulus(secret, 16)
            .unwrap();
        let private = parameters
            .encryptor_with_message_modulus(secret, 16)
            .unwrap();
        let public = parameters
            .public_encryptor_with_message_modulus(&public_key, 16)
            .unwrap();
        for ciphertext in [
            private.encrypt(15, &mut rng).unwrap(),
            public.encrypt(15, &mut rng).unwrap(),
        ] {
            assert_eq!(explicit_decoder.decrypt(ciphertext.as_view()).unwrap(), 15);
        }

        // The shared decoder factory must retain Scaled's stricter recovery
        // check. Rounded can represent this domain; fixed delta=1 cannot.
        assert!(
            parameters
                .pbs_decryptor_with_message_modulus(secret, u32::MAX)
                .is_ok()
        );
        assert!(matches!(
            parameters.ring_return_decryptor(secret, u32::MAX),
            Err(primus_tfhe_glwe::TfheClientError::Client(
                primus_tfhe_glwe::ClientError::Encoding(
                    primus_encoding::CodecError::InsufficientScaleRecovery
                )
            ))
        ));
    }
}

#[test]
fn capacity_and_padded_return_follow_pbs_order() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        for n in [17, 33, 64] {
            let mut config = config(order);
            config.small_lwe.dimension = LweDimension::new(n);
            let parameters = PbsParameters::try_from_config(config).unwrap();
            let ks = parameters.glwe_key_switching();
            assert_eq!(ks.output_dimension().get(), n.div_ceil(32));
            assert_eq!(
                ks.output().secret_key_distr(),
                SecretKeyDistr::UniformBinary
            );
            assert_eq!(ks.output().noise_standard_deviation(), 3.2);
            assert_eq!(
                parameters
                    .blind_rotation_params()
                    .noise_standard_deviation(),
                0.7
            );
            assert_eq!(
                parameters.external_lwe_dimension().get(),
                if order == PbsOrder::BootstrapKeyswitch {
                    n
                } else {
                    64
                }
            );
        }
    }
    let mut too_large = config(PbsOrder::BootstrapKeyswitch);
    too_large.small_lwe.dimension = LweDimension::new(65);
    assert!(matches!(
        PbsParameters::try_from_config(too_large),
        Err(TfheParameterError::SmallLweDimensionExceedsGlweCapacity {
            small_lwe_dimension: 65,
            capacity: 64
        })
    ));
}

/// Logical blocks stop at n; ring-KS public padding is not another sampled block.
#[test]
fn block_controls_validate_imports_and_preserve_public_zero_padding() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let mut cfg = config(order);
        cfg.small_lwe.dimension = LweDimension::new(6);
        for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
            cfg.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
                block_size: 3,
                occupancy,
            };
            for method in [BlindRotationMethod::Classic, BlindRotationMethod::Block] {
                cfg.method = method;
                let parameters = PbsParameters::try_from_config(cfg).unwrap();
                let mut rng = StdRng::seed_from_u64(109);
                let generated = ClientKey::generate(&parameters, &mut rng);
                generated.check_compatible(&parameters).unwrap();
                let (_, ring, _) = generated.into_parts();
                let empty_block = if occupancy == BlockOccupancy::ExactlyOne {
                    Err(TfheKeyError::InvalidLweSecretKeyBlock)
                } else {
                    Ok(())
                };
                for (coefficients, expected) in [
                    (vec![0; 6], empty_block.clone()),
                    (vec![0, 0, 0, 0, 1, 0], empty_block.clone()),
                    (vec![0, 1, 0, 0, 0, 1], Ok(())),
                    (
                        vec![1, 1, 0, 0, 0, 0],
                        Err(TfheKeyError::InvalidLweSecretKeyBlock),
                    ),
                    (
                        vec![2, 0, 0, 0, 0, 0],
                        Err(TfheKeyError::InvalidLweSecretKeyCoefficient),
                    ),
                ] {
                    let check_distribution = coefficients == [0, 1, 0, 0, 0, 1];
                    let client = ClientKey::new(
                        LweSecretKey::new(
                            coefficients.clone(),
                            cfg.small_lwe.secret_key_distr,
                            NativeModulus::new(),
                        ),
                        ring.clone(),
                        order,
                    );
                    assert_eq!(client.check_compatible(&parameters), expected);
                    if check_distribution {
                        let mut other = cfg;
                        other.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
                            block_size: 3,
                            occupancy: if occupancy == BlockOccupancy::AtMostOne {
                                BlockOccupancy::ExactlyOne
                            } else {
                                BlockOccupancy::AtMostOne
                            },
                        };
                        other.method = BlindRotationMethod::Classic;
                        let other = PbsParameters::try_from_config(other).unwrap();
                        assert_eq!(
                            client.check_compatible(&other),
                            Err(TfheKeyError::LweSecretKeyDistributionMismatch)
                        );
                    }
                    if expected.is_ok() {
                        let padded = client.padded_small_glwe_secret_key(&parameters);
                        let prefix: Vec<i32> = coefficients.iter().map(|&x| x as i32).collect();
                        assert_eq!(&padded.as_slice()[..6], prefix);
                        assert!(padded.as_slice()[6..].iter().all(|&x| x == 0));
                        assert_eq!(padded.as_slice().len(), 32);
                        assert_eq!(padded.distr(), cfg.small_lwe.secret_key_distr);
                    }
                }
            }
        }
    }
    let mut wrong_distribution = config(PbsOrder::BootstrapKeyswitch);
    wrong_distribution.method = BlindRotationMethod::Block;
    assert!(matches!(
        PbsParameters::try_from_config(wrong_distribution),
        Err(TfheParameterError::InvalidBlockSecretDistribution)
    ));
}

/// Import/binding must track both domains; client factories select q or Q once.
#[test]
fn independent_domains_bind_clients_and_ring_material() {
    use primus_encoding::RoundedCodec;
    use primus_modulus::PowOf2Modulus;
    use primus_tfhe_glwe::TfheClientError;
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let base = config(order);
        let config = PbsConfig::<u32, NativeModulus<u32>, PowOf2Modulus<u32>> {
            small_lwe: LweConfig {
                cipher_modulus: ModulusConfig::Explicit(1024),
                dimension: base.small_lwe.dimension,
                secret_key_distr: SecretKeyDistr::UniformTernary,
                noise_standard_deviation: 0.7,
            },
            ring_modulus: base.ring_modulus,
            bsk_dimension: base.bsk_dimension,
            bsk_poly_length: base.bsk_poly_length,
            bsk_secret_distr: base.bsk_secret_distr,
            bsk_gadget: base.bsk_gadget,
            key_switching: base.key_switching,
            method: base.method,
            messages: base.messages,
            order,
        };
        let parameters = PbsParameters::try_from_config(config).unwrap();
        // The prepared conversion must start at ring Q in either order, even
        // when the external client is already at q. Check half ties and wrap
        // with a wider-integer oracle, independently of the switch kernel.
        let switch = parameters.ring_to_small_modulus_switch().unwrap();
        for value in [0, (1 << 21) - 1, 1 << 21, (1 << 21) + 1, u32::MAX] {
            let expected = (((u64::from(value) * 1024 + (1 << 31)) >> 32) & 1023) as u32;
            assert_eq!(switch.switch(value), expected);
        }
        assert!(
            PbsParameters::try_from_config(base)
                .unwrap()
                .ring_to_small_modulus_switch()
                .is_none()
        );
        let mut rng = StdRng::seed_from_u64(111);
        let client = ClientKey::generate(&parameters, &mut rng);
        let secret = client.external_lwe_secret_key();
        let public = parameters
            .try_generate_public_key(secret, &mut rng)
            .unwrap();
        let encryptor = parameters.public_encryptor(&public).unwrap();
        let decryptor = parameters.pbs_decryptor(secret).unwrap();
        let encrypted = encryptor.encrypt_padded(3, &mut rng).unwrap();
        assert_eq!(decryptor.decrypt(encrypted.as_view()).unwrap(), 3);
        assert_eq!(
            parameters.glwe_key_switching().output().basis().modulus(),
            None
        );
        assert_eq!(
            parameters.external_modulus_value(),
            if order == PbsOrder::BootstrapKeyswitch {
                Some(1024)
            } else {
                None
            }
        );
        // Independently construct the expected low-level client. Identical RNG
        // streams must produce identical coordinates, proving selection of the
        // secret, dimension, q/Q, fresh noise and Rounded scale together.
        let mut actual_rng = StdRng::seed_from_u64(912);
        let mut expected_rng = StdRng::seed_from_u64(912);
        let actual = parameters
            .encryptor(secret)
            .unwrap()
            .encrypt_padded(3, &mut actual_rng)
            .unwrap();
        let expected = match order {
            PbsOrder::BootstrapKeyswitch => {
                let lwe = parameters.small_lwe();
                let codec = RoundedCodec::new(8, lwe.cipher_modulus());
                let params = primus_tfhe::LweClientParameters::try_from_parts(
                    lwe.dimension(),
                    &codec,
                    lwe.noise_distribution(),
                )
                .unwrap();
                primus_tfhe::Encryptor::try_new(params, client.small_lwe_secret_key().as_view())
                    .unwrap()
                    .encrypt_padded(3, &mut expected_rng)
                    .unwrap()
            }
            PbsOrder::KeyswitchBootstrap => {
                let glwe = parameters.blind_rotation_params();
                let codec = RoundedCodec::new(8, glwe.cipher_modulus());
                let params = primus_tfhe::LweClientParameters::try_from_parts(
                    LweDimension::from(glwe.glwe_size()),
                    &codec,
                    glwe.noise_distribution(),
                )
                .unwrap();
                let key = primus_lwe::LweSecretKeyRef::Signed(client.glwe_secret_key().as_slice());
                primus_tfhe::Encryptor::try_new(params, key)
                    .unwrap()
                    .encrypt_padded(3, &mut expected_rng)
                    .unwrap()
            }
        };
        assert_eq!(actual.as_ref(), expected.as_ref());
        let wrong_role = match order {
            PbsOrder::BootstrapKeyswitch => {
                primus_tfhe_glwe::ExternalLweSecretKey::ExtractedGlwe(client.glwe_secret_key())
            }
            PbsOrder::KeyswitchBootstrap => {
                primus_tfhe_glwe::ExternalLweSecretKey::SmallLwe(client.small_lwe_secret_key())
            }
        };
        assert!(matches!(
            parameters.encryptor(wrong_role),
            Err(TfheClientError::IncompatibleKey(
                primus_tfhe_glwe::TfheKeyError::PbsOrderMismatch { .. }
            ))
        ));
        let cbs = CbsParameters::try_with_config(
            parameters.clone(),
            gadget(),
            primus_tfhe::CbsInputEncoding::Padded,
            primus_tfhe_glwe::FourierTracePrecision::Ordinary,
        )
        .unwrap();
        assert_eq!(
            cbs.br_control_codec().ciphertext_modulus(),
            PowOf2Modulus::new(1024)
        );
    }
}
