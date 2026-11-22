//! Key generation and imported-secret contracts.

use primus_glwe::{BlockOccupancy, GlweDimension, SecretKeyDistr};
use primus_ntt::U32NttTable;
use primus_shape::PolyLength;
use primus_tfhe_glwe_ntt::{
    BlindRotationMethod, CbsConfig, CbsInputEncoding, ClientKey, PbsOrder, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

use super::parameters::{cbs_gadget, config};

/// Missing operation state and incompatible imported secrets are
/// rejected before key sampling. A rejected call must leave the generator reusable.
#[test]
fn key_generation_boundaries() {
    type Table = U32NttTable;
    use primus_tfhe_glwe_ntt::{KeyGenerationError, KeyGenerator};
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

    // Imported block coefficients must be checked before sampling any key rows.
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
    assert_eq!(
        block_generator
            .try_generate_server_key(&invalid_block, &mut key_rng)
            .err(),
        Some(KeyGenerationError::ClientKey(
            primus_tfhe_glwe_ntt::TfheKeyError::InvalidLweSecretKeyBlock,
        ))
    );
    assert_eq!(
        block_generator
            .try_generate_circuit_bootstrap_server_key(&invalid_block, &mut key_rng)
            .err(),
        Some(KeyGenerationError::ClientKey(
            primus_tfhe_glwe_ntt::TfheKeyError::InvalidLweSecretKeyBlock,
        ))
    );

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

/// Independent BR setup owns the raw coefficient check before encrypting rows.
#[test]
fn raw_classic_rejects_invalid_secret_before_sampling() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use primus_glwe::{NttGlweGadgetEncryptWorkspace, NttGlweSecretKey};
    use primus_lwe::LweSecretKey;
    use primus_tfhe_glwe_ntt::key::BlindRotationKey;
    use rand::Rng;

    let config = config::<u32>(BlindRotationMethod::Classic);
    let context = TfheContext::<u32, U32NttTable>::try_from_pbs_config(config).unwrap();
    let parameters = context.parameters();
    let gadget = parameters.blind_rotation_params();
    let client = ClientKey::generate(parameters, &mut StdRng::seed_from_u64(117));
    let ring = NttGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), context.table());
    let mut workspace = NttGlweGadgetEncryptWorkspace::new(gadget.size());
    let mut rng = StdRng::seed_from_u64(118);

    for distribution in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
    ] {
        let mut coefficients = vec![0; parameters.small_lwe().dimension().get()];
        coefficients[0] = 2;
        let secret = LweSecretKey::new(
            coefficients,
            distribution,
            parameters.small_lwe().cipher_modulus(),
        );
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                BlindRotationKey::try_generate(
                    &secret,
                    &ring,
                    gadget,
                    BlindRotationMethod::Classic,
                    context.table(),
                    &mut rng,
                    &mut workspace,
                )
            }))
            .is_err()
        );
    }
    assert_eq!(rng.next_u64(), StdRng::seed_from_u64(118).next_u64());
}
