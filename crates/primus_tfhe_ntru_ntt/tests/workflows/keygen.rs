//! Key generation, imported secret validation and failed-setup reuse.

use primus_ntru::{BlockOccupancy, SecretKeyDistr};
use primus_ntt::U32NttTable;
use primus_shape::PolyLength;
use primus_tfhe::DecompositionLevelCount;
use primus_tfhe_ntru_ntt::{BlindRotationMethod, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

use super::fixture::{cbs_gadget, config};

/// Keygen rejects incompatible imports before sampling, including f that cannot
/// be represented at return q or inverted at Q. Error paths leave scratch reusable.
#[test]
fn key_generation_boundaries() {
    type Table = U32NttTable;
    use primus_ntru::{NtruError, NtruSecretKey};
    use primus_tfhe_ntru_ntt::{ClientKey, KeyGenerationError, KeyGenerator, TfheKeyError};
    use rand::Rng;

    let mut config = config::<u32>(BlindRotationMethod::Classic);
    config.bsk_poly_length = PolyLength::new(64);
    let context = TfheContext::<u32, Table, _>::try_from_pbs_config(config)
        .unwrap()
        .try_with_circuit_bootstrap(cbs_gadget(Some(DecompositionLevelCount::new(3))))
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

    // Imported direct-block support is checked before sampling any key rows.
    let mut block_config = config;
    block_config.method = BlindRotationMethod::Block;
    block_config.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
        block_size: 2,
        occupancy: BlockOccupancy::AtMostOne,
    };
    let block_context = TfheContext::<u32, Table, _>::try_from_pbs_config(block_config)
        .unwrap()
        .try_with_circuit_bootstrap(cbs_gadget(None))
        .unwrap();
    let mut block_generator = KeyGenerator::new(&block_context);
    let mut invalid_support = vec![0; 8];
    invalid_support[..2].fill(1);
    let invalid_block_client = ClientKey::new(
        primus_lwe::LweSecretKey::new(
            invalid_support,
            block_config.external_lwe.secret_key_distr,
            block_context.parameters().external_lwe().cipher_modulus(),
        ),
        imported(8, 1).accumulator_ntru_secret_key().clone(),
    );
    assert_eq!(
        block_generator
            .try_generate_blind_rotation_key(&invalid_block_client, &mut rng)
            .err(),
        Some(KeyGenerationError::ClientKey(
            TfheKeyError::InvalidClientSecretKeyBlock,
        ))
    );
    assert_eq!(
        block_generator
            .try_generate_circuit_bootstrap_server_key(&invalid_block_client, &mut rng)
            .err(),
        Some(KeyGenerationError::ClientKey(
            TfheKeyError::InvalidClientSecretKeyBlock,
        ))
    );

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
