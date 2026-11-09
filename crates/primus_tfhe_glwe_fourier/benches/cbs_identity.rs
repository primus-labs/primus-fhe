//! cargo bench -p primus_tfhe_glwe_fourier --bench cbs_identity -- --test
//! CMUX2 (ordinary) / CMUX3 (Split35) derived identity CBS; setup and validation are untimed.
//! PRIMUS_CBS_ENCODING=padded|msb compares input encodings without changing gadgets.
//! bit*_cmux includes both CBS and its encrypted CMux consumer.
//! Parameters differ from the author's input/KS protocol and are not certified presets.
//! Historical comparisons: guides/performance/bootstrap-functional-comparison.md
//! Add --features tfhe-fft to measure both Fourier engines.
//! Split35 cases require split-trace (enabled by default); for TFHE-FFT alone
//! with both trace representations, use --no-default-features --features tfhe-fft,split-trace.

#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
mod workloads {
    use criterion::{BenchmarkId, Criterion, Throughput};
    use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
    use primus_fft::FftTable;
    use primus_glwe::{GlweDimension, SecretKeyDistr};
    use primus_lwe::LweDimension;
    use primus_shape::PolyLength;
    use primus_tfhe_glwe_fourier::{
        BlindRotationMethod, CbsConfig, CbsGadgetConfig, DecompositionConfig,
        FourierTracePrecision, GadgetEncryptionConfig, LweConfig, ModulusConfig, PbsConfig,
        PbsMessageConfig, PbsOrder, TfheContext,
    };
    use rand::{SeedableRng, rngs::StdRng};
    use std::hint::black_box;
    type Word = u64;
    const NATIVE_Q: f64 = (1u128 << 64) as f64;
    const ALPHA: f64 = 9.251_199_746_767_56e-5;
    const BETA: f64 = 9.251_199_746_767_56e-16;

    /// Keep the original padded workload unless the MSB comparison is requested.
    fn input_encoding() -> primus_tfhe::CbsInputEncoding {
        match std::env::var("PRIMUS_CBS_ENCODING") {
            Err(std::env::VarError::NotPresent) => primus_tfhe::CbsInputEncoding::Padded,
            Ok(value) if value == "padded" => primus_tfhe::CbsInputEncoding::Padded,
            Ok(value) if value == "msb" => primus_tfhe::CbsInputEncoding::MsbBoolean,
            other => panic!("use PRIMUS_CBS_ENCODING=padded or msb, got {other:?}"),
        }
    }

    /// Freeze both fields: keeping maximum levels would change the workload.
    const fn decomposition(base_log: u32, level_count: usize) -> DecompositionConfig {
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(base_log),
            level_count: Some(DecompositionLevelCount::new(level_count)),
        }
    }

    /// CMUX2 and CMUX3 share these gadgets; only their trace precision differs.
    /// The input encoding is selected below. Primus retains ring KS and normalized
    /// reverse trace, so even MSB is a derived protocol, not a certified preset.
    const fn comparison_config() -> CbsConfig<Word> {
        CbsConfig {
            fourier_trace_precision: primus_tfhe_glwe::FourierTracePrecision::Ordinary,
            input_encoding: primus_tfhe::CbsInputEncoding::Padded,
            pbs: PbsConfig {
                small_lwe: LweConfig {
                    dimension: LweDimension::new(636),
                    cipher_modulus: ModulusConfig::Native,
                    secret_key_distr: SecretKeyDistr::UniformBinary,
                    noise_standard_deviation: ALPHA * NATIVE_Q,
                },
                ring_modulus: ModulusConfig::Native,
                bsk_dimension: GlweDimension::new(1),
                bsk_poly_length: PolyLength::new(2048),
                bsk_secret_distr: SecretKeyDistr::UniformBinary,
                bsk_gadget: GadgetEncryptionConfig {
                    decomposition: decomposition(15, 2),
                    noise_standard_deviation: BETA * NATIVE_Q,
                },
                method: BlindRotationMethod::Classic,
                key_switching: GadgetEncryptionConfig {
                    decomposition: decomposition(2, 5),
                    noise_standard_deviation: ALPHA * NATIVE_Q,
                },
                messages: PbsMessageConfig::new(4),
                // The external input uses the ring secret and fresh β noise.
                // Small-LWE α is not a substitute for the actual KS output.
                order: PbsOrder::KeyswitchBootstrap,
            },
            gadget: CbsGadgetConfig {
                trace: decomposition(7, 6),
                scheme_switch: decomposition(17, 2),
                output: decomposition(4, 4),
            },
        }
    }

    fn benchmark<Table: FftTable>(
        c: &mut Criterion,
        engine: &str,
        precision: FourierTracePrecision,
    ) {
        let mut config = comparison_config();
        config.input_encoding = input_encoding();
        config.fourier_trace_precision = precision;
        let context = TfheContext::<Word, Table>::try_from_cbs_config(config).unwrap();
        // Client: setup is untimed; key, input and candidate streams have separate seeds.
        let mut key_rng = StdRng::seed_from_u64(42);
        let (client, server) = context
            .try_generate_circuit_bootstrap_keys(&mut key_rng)
            .unwrap();
        let encryptor = context
            .cbs_encryptor(client.external_lwe_secret_key())
            .unwrap();
        let mut input_rng = StdRng::seed_from_u64(1042);
        let inputs: Vec<_> = (0..2)
            .map(|bit| {
                let mut input = context.allocate_lwe_ciphertext();
                encryptor
                    .encrypt_to(bit, input.as_mut_view(), &mut input_rng)
                    .unwrap();
                input
            })
            .collect();
        let n = comparison_config().pbs.bsk_poly_length.get();
        let mut ring_client = context
            .accumulator_client(client.glwe_secret_key(), 8)
            .unwrap();
        let messages: Vec<Vec<Word>> = (0..2)
            .map(|r| {
                (0..n)
                    .map(|i| (((i >> r) + i / 7 + r) & 3) as Word)
                    .collect()
            })
            .collect();
        let mut candidate_rng = StdRng::seed_from_u64(2042);
        let candidates: Vec<_> = messages
            .iter()
            .map(|m| ring_client.encrypt(m, &mut candidate_rng))
            .collect();
        let mut decoded = vec![0; n];

        // Server: each Boolean control must select a real encrypted polynomial.
        // A failed consumer aborts the benchmark before any timing is registered.
        let mut evaluator = context.circuit_bootstrap_evaluator(&server).unwrap();
        let mut control = evaluator.allocate_output();
        let mut selected = context.allocate_accumulator_ciphertext();
        for (bit, input) in inputs.iter().enumerate() {
            evaluator.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
            evaluator.cmux_to(
                control.as_view(),
                candidates[0].as_view(),
                candidates[1].as_view(),
                selected.as_mut_view(),
            );
            ring_client.decrypt_to(&selected, &mut decoded);
            assert_eq!(decoded, messages[bit], "CBS bit{bit} consumer failed");
        }

        // Time only identity CBS ending in a consumable transform-domain GGSW.
        // This gate checks the measured fixtures; it is not a failure-rate estimate.
        let variant = if precision == FourierTracePrecision::Ordinary {
            ""
        } else {
            "/split35"
        };
        // Preserve historical IDs: CMUX2.../split35 is the CMUX3 gadget group,
        // not a second ordinary CMUX2 measurement or an exact author protocol.
        let case = if config.input_encoding == primus_tfhe::CbsInputEncoding::Padded {
            "CMUX2-native-t4-ringks-derived"
        } else {
            "CMUX2-native-msb-ringks-derived"
        };
        let mut group = c.benchmark_group(format!(
            "cbs/glwe/{engine}/identity_to_fourier_ggsw/{case}{variant}/complete"
        ));
        group.throughput(Throughput::Elements(1));
        group.sampling_mode(criterion::SamplingMode::Flat);
        for (bit, input) in inputs.iter().enumerate() {
            // Seed this bit even when Criterion filters out its CBS-only measurement.
            evaluator.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
            group.bench_function(BenchmarkId::new(format!("bit{bit}"), "u64"), |b| {
                b.iter(|| {
                    evaluator
                        .circuit_bootstrap_to(black_box(input.as_view()), control.as_mut_view());
                    black_box(control.as_view());
                })
            });
            evaluator.cmux_to(
                control.as_view(),
                candidates[0].as_view(),
                candidates[1].as_view(),
                selected.as_mut_view(),
            );
            ring_client.decrypt_to(&selected, &mut decoded);
            assert_eq!(decoded, messages[bit], "timed CBS bit{bit} consumer failed");
            group.bench_function(BenchmarkId::new(format!("bit{bit}_cmux"), "u64"), |b| {
                b.iter(|| {
                    evaluator
                        .circuit_bootstrap_to(black_box(input.as_view()), control.as_mut_view());
                    evaluator.cmux_to(
                        control.as_view(),
                        candidates[0].as_view(),
                        candidates[1].as_view(),
                        selected.as_mut_view(),
                    );
                    black_box(selected.as_view());
                })
            });
            // Check the actual complete-request output without rerunning the server.
            ring_client.decrypt_to(&selected, &mut decoded);
            assert_eq!(decoded, messages[bit], "timed CBS bit{bit} consumer failed");
        }
        group.finish();
    }
    pub(super) fn benchmarks(c: &mut Criterion) {
        let precisions = [
            FourierTracePrecision::Ordinary,
            #[cfg(feature = "split-trace")]
            FourierTracePrecision::Split35,
        ];
        for precision in precisions {
            #[cfg(feature = "rustfft")]
            benchmark::<primus_fft::RustFftTable>(c, "rustfft", precision);
            #[cfg(feature = "tfhe-fft")]
            benchmark::<primus_fft::TfheFftTable>(c, "tfhe-fft", precision);
        }
    }
}
#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
criterion::criterion_group! {
    name = benches;
    config = criterion::Criterion::default().sample_size(20)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3));
    targets = workloads::benchmarks
}
#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
criterion::criterion_main!(benches);

#[cfg(not(any(feature = "rustfft", feature = "tfhe-fft")))]
fn main() {
    panic!("enable rustfft or tfhe-fft to run this benchmark");
}
