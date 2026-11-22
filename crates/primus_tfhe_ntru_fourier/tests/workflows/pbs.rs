use primus_fft::{FftTable, TorusFftValue};
use primus_modulus::PowOf2Modulus;
use primus_ntru::{BlockOccupancy, LweDimension, SecretKeyDistr};
use primus_tfhe_ntru_fourier::{
    BlindRotationMethod, ClientKey, KeyGenerator, PbsConfig, PbsMessageConfig, ServerKey,
    TfheContext, TfheEvaluationError, bootstrap::BootstrapResources,
};
use rand::{SeedableRng, rngs::StdRng};

use super::fixture::config;

/// Two message programs share a context, key and evaluator. Rounded output
/// at t=8 feeds padded input at t=8; the final full-domain t=16 result may not
/// feed a padded t=16 program. Ciphertexts carry no encoding metadata.
/// Block fixtures also reuse these keys for ManyLUT and MVB.
pub(super) fn check_pbs_workflows<T: TorusFftValue, Table: FftTable>(
    config: PbsConfig<T, PowOf2Modulus<T>>,
) {
    let context = TfheContext::<T, Table, _>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(101);
    // Client: only encrypted inputs and the evaluation key leave this side.
    let mut generator = KeyGenerator::new(&context);
    let client = generator.try_generate_client_key(&mut rng).unwrap();
    // Independent BR generation does not construct any return material.
    let blind_rotation = generator
        .try_generate_blind_rotation_key(&client, &mut rng)
        .unwrap();
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
            BootstrapResources::try_new(&other, &blind_rotation),
            Err(TfheEvaluationError::IncompatibleBlindRotationKey)
        ));
    }
    let key_switching = context
        .parameters()
        .try_generate_lwe_return_key(&client, &mut rng)
        .unwrap();
    let server = ServerKey::new(blind_rotation, key_switching);
    check_chain(&context, &client, &server, &mut rng);
    if config.method == BlindRotationMethod::Block {
        check_many_lut_and_mvb(&context, &client, &server);
    }
}

pub(super) fn check_chain<T: TorusFftValue, Table: FftTable>(
    context: &TfheContext<T, Table, PowOf2Modulus<T>>,
    client: &ClientKey<T>,
    server: &ServerKey<T>,
    rng: &mut StdRng,
) {
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
    let mut evaluator = context.evaluator(server).unwrap();
    let mut middle = context.allocate_lwe_ciphertext();
    let mut output = context.allocate_lwe_ciphertext();
    for x in [7, 1, 2, 0] {
        encryptor
            .encrypt_padded_to(T::as_from(x), input.as_mut_view(), rng)
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
    assert!(encryptor.encrypt_padded(T::as_from(10), rng).is_err());
}

/// Three ManyLUT output lanes require a fourth padding lane. MVB uses one
/// integer output scale, consumed through the Scaled client factory. Nine MVB
/// outputs exercise a complete eight-output return tile and its trailing output.
#[cfg(feature = "rustfft")]
fn many_lut_and_mvb<T: TorusFftValue, Table: FftTable>(mut config: PbsConfig<T, PowOf2Modulus<T>>) {
    // Keep the established small-parameter ManyLUT noise margin at t_in=8;
    // use different defaults to detect accidental fallback to config messages.
    config.messages = PbsMessageConfig::new(T::as_from(16));
    let context = TfheContext::<T, Table, _>::try_from_pbs_config(config).unwrap();
    let (client, server) = context
        .try_generate_keys(&mut StdRng::seed_from_u64(102))
        .unwrap();
    check_many_lut_and_mvb(&context, &client, &server);
}

/// The same programs run with a reused PBS key. The outputs use distinct
/// Rounded and Scaled encodings, both with the explicit 8→4 message space.
pub(super) fn check_many_lut_and_mvb<T: TorusFftValue, Table: FftTable>(
    context: &TfheContext<T, Table, PowOf2Modulus<T>>,
    client: &ClientKey<T>,
    server: &ServerKey<T>,
) {
    let mut rng = StdRng::seed_from_u64(102);
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
    let mut pbs = context.evaluator(server).unwrap();
    let mut mvb = context.mvb_evaluator(server).unwrap();
    let mut lanes = vec![context.allocate_lwe_ciphertext(); 3];
    let mut factors = vec![context.allocate_lwe_ciphertext(); 9];

    if context.parameters().blind_rotation_method() == BlindRotationMethod::Classic {
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
    }

    for x in [0, 3] {
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

#[test]
fn u32_classic_chain() {
    let mut config = config(BlindRotationMethod::Classic);
    config.external_lwe.secret_key_distr = SecretKeyDistr::UniformBinary;
    #[cfg(feature = "rustfft")]
    check_pbs_workflows::<u32, primus_fft::RustFftTable>(config);
    #[cfg(feature = "tfhe-fft")]
    check_pbs_workflows::<u32, primus_fft::TfheFftTable>(config);

    // Classic controls also consume correlated block-binary secrets unchanged.
    config.external_lwe.dimension = LweDimension::new(6);
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        config.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
            block_size: 3,
            occupancy,
        };
        #[cfg(feature = "rustfft")]
        check_pbs_workflows::<u32, primus_fft::RustFftTable>(config);
        #[cfg(feature = "tfhe-fft")]
        check_pbs_workflows::<u32, primus_fft::TfheFftTable>(config);
    }
}

#[cfg(feature = "rustfft")]
#[test]
fn rustfft_u32_ternary_batches() {
    let mut config = config(BlindRotationMethod::Classic);
    config.external_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    many_lut_and_mvb::<u32, primus_fft::RustFftTable>(config);
}
