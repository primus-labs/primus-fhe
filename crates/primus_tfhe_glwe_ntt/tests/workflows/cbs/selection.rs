//! Program binding, gadget-row checks, encrypted selection and return.

use primus_encoding::phase_error_magnitude;
use primus_glwe::NttGlweSecretKey;
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use primus_reduce::RingContext;
use primus_reduce::{EncodeSigned, ReduceMul, ReduceNeg};
use primus_tfhe::DecompositionBaseLog;
use primus_tfhe_glwe_ntt::circuit_bootstrap::{CbsGadgetParameters, CircuitBootstrapEvaluator};
use primus_tfhe_glwe_ntt::{
    CbsConfig, CbsInputEncoding, ClientKey, ModulusConfig, PbsConfig, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

use primus_glwe::GlweCiphertext;
use primus_lattice::ggsw::NttGgsw;
use primus_tfhe_glwe_ntt::{
    AccumulatorClient, CbsEncryptor, CbsEvaluator, CircuitBootstrapServerKey, Evaluator,
    LweCiphertext, LweSecretKeyRef,
};

use crate::parameters::cbs_gadget;

/// Check every coefficient against the canonical GGSW phase: -F(m)*g*s_r
/// for a mask row, or F(m)*g at coefficient zero for the body row.
/// The scalar/16 allowance belongs only to this fixed small fixture, whose
/// BR/trace/SS use all decomposition levels. It detects missing/scaled/sign-flipped
/// rows; it is neither a general gadget-noise budget nor a DFR bound.
fn assert_gadget_phase<T: FheUint>(
    phase: &[T],
    secret: Option<&[T::SignedInteger]>,
    bit: T,
    scalar: T,
    modulus: BarrettModulus<T>,
) {
    let weight = modulus.reduce_mul(bit, scalar);
    for (i, &actual) in phase.iter().enumerate() {
        let expected = if let Some(secret) = secret {
            modulus.reduce_neg(modulus.reduce_mul(weight, modulus.encode_signed(secret[i])))
        } else if i == 0 {
            weight
        } else {
            T::ZERO
        };
        assert!(
            phase_error_magnitude(actual, expected, modulus) <= scalar >> 4u32,
            "coefficient {i}, scalar {scalar:?}, actual {actual:?}, expected {expected:?}"
        );
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CbsCoverage {
    Selection,
    Bindings,
}

/// Inspect and consume every gadget row/level before the ordinary encrypted CMux.
/// Both BR algorithms and PBS orders retain the same output sign/scale contract.
pub(super) fn circuit_selection<T: FheUint, Table: MonomialNttTable<ValueT = T>, LM>(
    pbs: PbsConfig<T, LM>,
    input_encoding: CbsInputEncoding,
    coverage: CbsCoverage,
) where
    LM: RingContext<T> + TryFrom<ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
{
    let config = CbsConfig {
        fourier_trace_precision: primus_tfhe_glwe::FourierTracePrecision::Ordinary,
        input_encoding,
        pbs,
        gadget: cbs_gadget(),
    };
    let context = TfheContext::<T, Table, LM>::try_from_cbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(103);
    // Client: encrypt nonconstant candidate polynomials under the ring secret.
    let (client, server) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    let mut selection = CbsSelection::new(&context, &client, &server, rng);
    selection.check(config, coverage);
}

/// Owns the candidate ciphertexts and buffers reused across selection and rebinding.
struct CbsSelection<'a, T: FheUint, Table: MonomialNttTable<ValueT = T>, LM: RingContext<T>> {
    context: &'a TfheContext<T, Table, LM>,
    client: &'a ClientKey<T>,
    server: &'a CircuitBootstrapServerKey<T>,
    ring_client: AccumulatorClient<'a, T, Table, LM>,
    messages: Vec<Vec<T>>,
    candidates: Vec<GlweCiphertext<Vec<T>>>,
    input: LweCiphertext<T>,
    selected: GlweCiphertext<Vec<T>>,
    decoded: Vec<T>,
    rng: StdRng,
}

impl<'a, T, Table, LM> CbsSelection<'a, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: RingContext<T> + TryFrom<ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
{
    fn new(
        context: &'a TfheContext<T, Table, LM>,
        client: &'a ClientKey<T>,
        server: &'a CircuitBootstrapServerKey<T>,
        mut rng: StdRng,
    ) -> Self {
        let mut ring_client = context
            .accumulator_client(client.glwe_secret_key(), T::as_from(8))
            .unwrap();
        // Avoid a short periodic pattern that could hide an incorrect coefficient rotation.
        let messages: Vec<Vec<T>> = (0..2)
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
        let input = context.allocate_lwe_ciphertext();
        let decoded = vec![T::ZERO; 128];

        let selected = context.allocate_accumulator_ciphertext();
        Self {
            context,
            client,
            server,
            ring_client,
            messages,
            candidates,
            input,
            selected,
            decoded,
            rng,
        }
    }

    /// Check program binding, then consume the selected ciphertext through the PBS return path.
    fn check(&mut self, config: CbsConfig<T, LM>, coverage: CbsCoverage) {
        let context = self.context;
        let client = self.client;
        let server = self.server;
        let input_encoding = config.input_encoding;
        let encryptor = context
            .cbs_encryptor(client.external_lwe_secret_key())
            .unwrap();
        if input_encoding == CbsInputEncoding::MsbBoolean {
            let parameters = context.cbs_parameters().unwrap();
            // Same t=2, q/Q and basis, but padded t=2 has a different domain/geometry.
            let wrong = parameters
                .gadget()
                .compile_lookup_table(parameters.br_control_codec(), CbsInputEncoding::Padded)
                .unwrap();
            assert!(
                context
                    .circuit_bootstrap_evaluator_with_lookup_table(server, wrong)
                    .is_err()
            );
            self.input.as_mut().fill(T::ONE);
            assert!(
                encryptor
                    .encrypt_to(T::as_from(2), self.input.as_mut_view(), &mut self.rng)
                    .is_err()
            );
            assert!(self.input.as_ref().iter().all(|v| *v == T::ONE));
        }

        // Server: compile the predicate, then choose the encrypted branch.
        let program = context
            .compile_cbs_fn(|m| T::as_from(selector(input_encoding, m)))
            .unwrap();
        // A valid gadget program compiled at the wrong BR input q must fail binding.
        let wrong_input = primus_encoding::RoundedCodec::new(
            T::as_from(8),
            primus_modulus::PowOf2Modulus::new(T::as_from(512)),
        );
        let wrong_program = context
            .cbs_parameters()
            .unwrap()
            .gadget()
            .compile_lookup_table(&wrong_input, primus_tfhe::CbsInputEncoding::Padded)
            .unwrap();
        assert!(matches!(
            context.circuit_bootstrap_evaluator_with_lookup_table(server, wrong_program),
            Err(primus_tfhe::TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable)
        ));
        let mut cbs = context
            .circuit_bootstrap_evaluator_with_lookup_table(server, program)
            .unwrap();
        let mut control = cbs.allocate_output();
        self.check_selection(input_encoding, &encryptor, &mut cbs, &mut control);
        let on_input = selection_inputs(input_encoding)[1];
        let n = context
            .parameters()
            .blind_rotation_params()
            .poly_length()
            .get();
        // Transfer the CBS workspace and return a coefficient of the selected ciphertext.
        let (_, resources) = cbs.into_parts();
        let mut pbs =
            primus_tfhe_glwe_ntt::Evaluator::try_from_resources(resources, server.server_key())
                .unwrap();
        let mut returned_lwe = context.allocate_lwe_ciphertext();
        let ring_decryptor = context
            .ring_return_decryptor(client.external_lwe_secret_key(), T::as_from(8))
            .unwrap();
        pbs.return_ring_at_to(self.selected.as_view(), n - 1, returned_lwe.as_mut_view());
        assert_eq!(
            ring_decryptor.decrypt(returned_lwe.as_view()).unwrap(),
            self.messages[selector(input_encoding, on_input)][n - 1]
        );
        if coverage == CbsCoverage::Bindings {
            self.check_rebinding(config, &encryptor, pbs, &mut control, &mut returned_lwe);
        }
    }

    /// Inspect the generated controls and exercise their gadget weights before CMux.
    fn check_selection(
        &mut self,
        input_encoding: CbsInputEncoding,
        encryptor: &CbsEncryptor<'_, T, LweSecretKeyRef<'_, T>, LM>,
        cbs: &mut CbsEvaluator<'_, T, Table>,
        control: &mut NttGgsw<Vec<T>>,
    ) {
        let Self {
            context,
            client,
            ring_client,
            messages,
            candidates,
            input,
            selected,
            decoded,
            rng,
            ..
        } = self;
        let [off_input, on_input] = selection_inputs(input_encoding);
        let gadget = context.cbs_parameters().unwrap().gadget();
        let size = gadget.output_size();
        let n = size.glwe_size().poly_length().get();
        let modulus = context.parameters().ring_modulus();
        let transformed_secret =
            NttGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), context.table());
        let mut phase = Polynomial::new(vec![T::ZERO; n]);
        let mut probe = context.allocate_accumulator_ciphertext();
        let mut scratch = vec![T::ZERO; n];
        let public_key = (input_encoding == CbsInputEncoding::MsbBoolean).then(|| {
            context
                .parameters()
                .try_generate_public_key(client.external_lwe_secret_key(), rng)
                .unwrap()
        });
        for m in [off_input, on_input] {
            if let Some(public_key) = public_key.as_ref().filter(|_| m == 1) {
                context
                    .cbs_public_encryptor(public_key)
                    .unwrap()
                    .encrypt_to(T::as_from(m), input.as_mut_view(), rng)
                    .unwrap();
            } else {
                encryptor
                    .encrypt_to(T::as_from(m), input.as_mut_view(), rng)
                    .unwrap();
            }
            cbs.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
            let bit = T::as_from(selector(input_encoding, m));
            for (row, glev) in control.iter_ntt_glev(size.glev_len()).enumerate() {
                let secret = client.glwe_secret_key().iter().nth(row);
                for (ciphertext, scalar) in glev
                    .iter_ntt_glwe(size.glwe_size().glwe_len())
                    .zip(gadget.output_basis().scalar_iter())
                {
                    transformed_secret.decrypt_phase_to(
                        &ciphertext,
                        &mut phase,
                        modulus,
                        context.table(),
                    );
                    assert_gadget_phase(phase.as_ref(), secret, bit, scalar, modulus);

                    // A single coefficient equal to g_l decomposes as exactly +1
                    // in row r/level l. All other digits are zero: an ordinary t8
                    // CMux could hide a missing low level, but this probe cannot.
                    probe.as_mut().fill(T::ZERO);
                    probe.as_mut()[row * n] = scalar;
                    cbs.external_product_to(
                        control.as_view(),
                        probe.as_view(),
                        selected.as_mut_view(),
                    );
                    transformed_secret.decrypt_phase_coeff_to(
                        selected,
                        &mut phase,
                        modulus,
                        context.table(),
                        &mut scratch,
                    );
                    assert_gadget_phase(phase.as_ref(), secret, bit, scalar, modulus);
                }
            }
            cbs.cmux_to(
                control.as_view(),
                candidates[0].as_view(),
                candidates[1].as_view(),
                selected.as_mut_view(),
            );
            ring_client.decrypt_to(selected, decoded);
            assert_eq!(
                *decoded,
                messages[selector(input_encoding, m)],
                "CBS input {m}"
            );
        }
    }

    /// Rebind the existing BR material to independent CBS and KS parameters.
    fn check_rebinding(
        &mut self,
        config: CbsConfig<T, LM>,
        encryptor: &CbsEncryptor<'_, T, LweSecretKeyRef<'_, T>, LM>,
        pbs: Evaluator<'_, T, Table>,
        control: &mut NttGgsw<Vec<T>>,
        returned_lwe: &mut LweCiphertext<T>,
    ) {
        // Shorten the evaluator lifetime to the scope of the alternate CBS parameters.
        let mut pbs = pbs;
        let Self {
            context,
            client,
            server,
            ring_client,
            messages,
            candidates,
            input,
            selected,
            decoded,
            rng,
        } = self;
        let input_encoding = config.input_encoding;
        let on_input = selection_inputs(input_encoding)[1];
        // Reuse the circuit material with another output basis of the same layout.
        // An old program cannot silently inherit the newly selected gadget scales.
        let mut alternate_config = config.gadget;
        alternate_config.output.log_basis = DecompositionBaseLog::new(3);
        let alternate =
            CbsGadgetParameters::try_from_config(context.parameters(), alternate_config).unwrap();
        let original_program = context.compile_cbs_identity().unwrap();
        assert!(matches!(
            CircuitBootstrapEvaluator::try_new(
                pbs.bootstrap_resources(),
                &alternate,
                server.circuit_bootstrap_key(),
                original_program,
            ),
            Err(primus_tfhe::TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable)
        ));
        let program = alternate
            .compile_lookup_table_fn(
                context.cbs_parameters().unwrap().br_control_codec(),
                input_encoding,
                |m| T::as_from(selector(input_encoding, m)),
            )
            .unwrap();
        let mut operation = CircuitBootstrapEvaluator::try_new(
            pbs.bootstrap_resources(),
            &alternate,
            server.circuit_bootstrap_key(),
            program,
        )
        .unwrap();

        // Recover the configured return from the complete bundle. Independently
        // supplied KS material remains supported through the explicit binding boundary.
        let mut ks_config = config.pbs.key_switching;
        ks_config.decomposition.log_basis = DecompositionBaseLog::new(3);
        let ks_parameters = context
            .parameters()
            .try_key_switching_parameters(ks_config)
            .unwrap();
        assert!(matches!(
            primus_tfhe_glwe_ntt::Evaluator::try_from_parts(
                context,
                &ks_parameters,
                server.server_key().blind_rotation_key(),
                server.server_key().glwe_key_switching_key(),
            ),
            Err(primus_tfhe_glwe_ntt::TfheEvaluationError::IncompatibleGlweKeySwitchingKey)
        ));
        let key = primus_tfhe_glwe_ntt::KeyGenerator::new(context)
            .try_generate_glwe_key_switching_key(&ks_parameters, client, rng)
            .unwrap();
        let mut independent = primus_tfhe_glwe_ntt::Evaluator::try_from_parts(
            context,
            &ks_parameters,
            server.server_key().blind_rotation_key(),
            &key,
        )
        .unwrap();
        let identity = context
            .pbs_lookup_table_compiler()
            .unwrap()
            .compile_fn(T::as_from)
            .unwrap();
        let decryptor = context
            .pbs_decryptor(client.external_lwe_secret_key())
            .unwrap();
        // Sharing a context never changes ordinary PBS input encoding. Re-encrypt
        // through its own client before handing the same message to the PBS identity.
        let pbs_encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
        let m = on_input;
        encryptor
            .encrypt_to(T::as_from(m), input.as_mut_view(), rng)
            .unwrap();
        operation.circuit_bootstrap_to(input.as_view(), control, pbs.bootstrap_resources_mut());
        operation.cmux_to(
            control,
            &candidates[0],
            &candidates[1],
            selected,
            pbs.bootstrap_resources_mut(),
        );
        ring_client.decrypt_to(selected, decoded);
        assert_eq!(*decoded, messages[selector(input_encoding, m)]);
        pbs_encryptor
            .encrypt_padded_to(T::as_from(m), input.as_mut_view(), rng)
            .unwrap();
        pbs.apply_lookup_table_to(input.as_view(), &identity, returned_lwe.as_mut_view());
        assert_eq!(
            decryptor.decrypt(returned_lwe.as_view()).unwrap(),
            T::as_from(m)
        );
        independent.apply_lookup_table_to(input.as_view(), &identity, returned_lwe.as_mut_view());
        assert_eq!(
            decryptor.decrypt(returned_lwe.as_view()).unwrap(),
            T::as_from(m)
        );

        // A numerically equal but separately owned context cannot replace the
        // operation's bound resources, even when importing the same key material.
        let other = TfheContext::<T, Table, LM>::try_from_cbs_parameters(
            context.cbs_parameters().unwrap().clone(),
        )
        .unwrap();
        let mut other_resources = server.bootstrap_resources(&other).unwrap();
        control.as_mut().fill(Default::default());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            operation.circuit_bootstrap_to(input.as_view(), control, &mut other_resources);
        }));
        assert!(result.is_err());
        assert!(control.as_ref().iter().all(|v| *v == Default::default()));
    }
}

/// MSB uses NOT so the negative slope exercises the post-trace offset.
fn selector(encoding: CbsInputEncoding, message: usize) -> usize {
    match encoding {
        CbsInputEncoding::Padded => usize::from(message >= 2),
        CbsInputEncoding::MsbBoolean => 1 - message,
    }
}

fn selection_inputs(encoding: CbsInputEncoding) -> [usize; 2] {
    match encoding {
        CbsInputEncoding::Padded => [1, 2],
        CbsInputEncoding::MsbBoolean => [1, 0],
    }
}
