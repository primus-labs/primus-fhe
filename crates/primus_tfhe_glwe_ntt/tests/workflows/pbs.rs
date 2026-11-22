//! Chained PBS and batched lookup workflows.

use primus_glwe::{BlockOccupancy, SecretKeyDistr};
use primus_integer::FheUint;
use primus_lwe::LweDimension;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_reduce::RingContext;
use primus_tfhe_glwe_ntt::{
    BivariateLookupTable, BlindRotationMethod, BooleanGate, ClientKey, ModulusConfig, PbsConfig,
    PbsMessageConfig, PbsOrder, ServerKey, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

use super::parameters::{config, two_domain_config};

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

/// Share independently generated BR/KS components across PBS, ManyLUT and MVB.
pub(super) struct PbsFixture<T: FheUint, Table: MonomialNttTable<ValueT = T>, LM: RingContext<T>> {
    context: TfheContext<T, Table, LM>,
    client: ClientKey<T>,
    server: ServerKey<T>,
    rng: StdRng,
}

impl<T, Table, LM> PbsFixture<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: RingContext<T> + TryFrom<ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
{
    pub(super) fn new(mut config: PbsConfig<T, LM>) -> Self {
        // The chain uses the default t=8 decoder for the intermediate. ManyLUT
        // and MVB override both defaults, with t_in=8 and t_out=4.
        config.messages = PbsMessageConfig::new(T::as_from(16)).with_output_modulus(T::as_from(8));
        let context = TfheContext::<T, Table, LM>::try_from_pbs_config(config).unwrap();
        let mut rng = StdRng::seed_from_u64(101);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        // Independently generated components retain the same client and context.
        let mut generator = primus_tfhe_glwe_ntt::KeyGenerator::new(&context);
        let blind_rotation = generator
            .try_generate_blind_rotation_key(&client, &mut rng)
            .unwrap();
        let key_switching = generator
            .try_generate_glwe_key_switching_key(
                context.parameters().glwe_key_switching(),
                &client,
                &mut rng,
            )
            .unwrap();
        let server = ServerKey::new(blind_rotation, key_switching);
        Self {
            context,
            client,
            server,
            rng,
        }
    }

    /// A rounded t=8 result feeds a second padded program in the same workspace.
    pub(super) fn check_chain(&mut self) {
        let context = &self.context;
        let secret = self.client.external_lwe_secret_key();
        let first_messages =
            PbsMessageConfig::new(T::as_from(16)).with_output_modulus(T::as_from(8));
        let second_messages =
            PbsMessageConfig::new(T::as_from(8)).with_output_modulus(T::as_from(16));
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
        let mut evaluator = context.evaluator(&self.server).unwrap();
        let mut middle = context.allocate_lwe_ciphertext();
        let mut output = context.allocate_lwe_ciphertext();
        for x in [0, 7, 2] {
            encryptor
                .encrypt_padded_to(T::as_from(x), input.as_mut_view(), &mut self.rng)
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
        assert!(
            encryptor
                .encrypt_padded(T::as_from(10), &mut self.rng)
                .is_err()
        );
    }

    /// Check the padded output lane, changing strides, and Scaled MVB factors.
    pub(super) fn check_batches(&mut self) {
        let context = &self.context;
        let secret = self.client.external_lwe_secret_key();
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
        let compiler = context
            .pbs_lookup_table_compiler_with_messages(messages)
            .unwrap();
        let lut = compiler.compile_interleaved_fn(3, function).unwrap();
        let ordinary = compiler.compile_fn(|x| function(x, 0)).unwrap();
        let pair = compiler.compile_interleaved_fn(2, function).unwrap();
        let program = context
            .compile_mvb_fn_with_messages(messages, 4, 9, function)
            .unwrap();
        let mut pbs = context.evaluator(&self.server).unwrap();
        let mut mvb = context.mvb_evaluator(&self.server).unwrap();
        let mut lanes = vec![context.allocate_lwe_ciphertext(); 3];
        let mut factors = vec![context.allocate_lwe_ciphertext(); 9];
        for x in [0, 3] {
            encryptor
                .encrypt_padded_to(T::as_from(x), input.as_mut_view(), &mut self.rng)
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
}

#[test]
fn u32_classic_chain() {
    let mut config = config(BlindRotationMethod::Classic);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformBinary;
    PbsFixture::<u32, U32NttTable, _>::new(config).check_chain();

    // The logical block width need not divide the padded ring-KS target length.
    config.small_lwe.dimension = LweDimension::new(6);
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        config.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
            block_size: 3,
            occupancy,
        };
        for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
            config.order = order;
            PbsFixture::<u32, U32NttTable, _>::new(config).check_chain();
        }
    }
}

#[test]
fn u64_ternary_batches() {
    let mut config = config(BlindRotationMethod::Classic);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    config.order = PbsOrder::KeyswitchBootstrap;
    PbsFixture::<u64, U64NttTable, _>::new(config).check_batches();
}

/// Consume direct blocks through ordinary PBS and changing ManyLUT strides,
/// then factorized MVB. Input q differs from the ring modulus.
#[test]
fn u32_block_pbs_and_batches() {
    let mut config = two_domain_config(BlindRotationMethod::Block, PbsOrder::BootstrapKeyswitch);
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        config.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
            block_size: 3,
            occupancy,
        };
        let mut fixture = PbsFixture::<u32, U32NttTable, _>::new(config);
        fixture.check_chain();
        fixture.check_batches();
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
