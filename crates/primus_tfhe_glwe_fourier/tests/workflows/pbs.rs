//! Chained PBS and batched lookup workflows.

use primus_fft::{FftTable, TorusFftValue};
use primus_glwe::{BlockOccupancy, SecretKeyDistr};
use primus_lwe::LweDimension;
use primus_reduce::RingContext;
use primus_tfhe_glwe_fourier::{
    BlindRotationMethod, ClientKey, ModulusConfig, PbsConfig, PbsMessageConfig, PbsOrder,
    ServerKey, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

use super::parameters::config;

/// Share independently generated BR/KS components across PBS, ManyLUT and MVB.
pub(super) struct PbsFixture<T: TorusFftValue, Table: FftTable, LM: RingContext<T>> {
    context: TfheContext<T, Table, LM>,
    client: ClientKey<T>,
    server: ServerKey<T>,
    rng: StdRng,
}

impl<T, Table, LM> PbsFixture<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
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
        let mut generator = primus_tfhe_glwe_fourier::KeyGenerator::new(&context);
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
fn u32_binary_classic_chain() {
    fn check<Table: FftTable>() {
        let mut config = config(BlindRotationMethod::Classic);
        config.small_lwe.secret_key_distr = SecretKeyDistr::UniformBinary;
        PbsFixture::<u32, Table, _>::new(config).check_chain();

        // The logical block width need not divide the padded ring-KS target length.
        config.small_lwe.dimension = LweDimension::new(6);
        for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
            config.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
                block_size: 3,
                occupancy,
            };
            for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
                config.order = order;
                PbsFixture::<u32, Table, _>::new(config).check_chain();
            }
        }
    }
    #[cfg(feature = "rustfft")]
    check::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check::<primus_fft::TfheFftTable>();
}

#[cfg(feature = "rustfft")]
#[test]
fn rustfft_u32_ternary_batches() {
    let mut config = config(BlindRotationMethod::Classic);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    config.order = PbsOrder::KeyswitchBootstrap;
    PbsFixture::<u32, primus_fft::RustFftTable, _>::new(config).check_batches();
}
