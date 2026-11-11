//! cargo bench -p primus_tfhe_glwe_fourier --bench pbs
//! RustFFT is the default. Use `--no-default-features --features tfhe-fft` for
//! TFHE-FFT alone, or `--features tfhe-fft` to measure both engines.
//! PRIMUS_PBS_CASE=tfhe-fft/low selects the 4-to-4-bit comparison (or /high).
//! Parameters and comparison limits: guides/development/testing.md#tfhe-benchmarks
//! One iteration is one server request. Setup and correctness checks are untimed.

#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
mod workloads {
    use criterion::{Criterion, Throughput};
    use primus_fft::{FftTable, TorusFftValue};
    use primus_glwe::{GlweDimension, SecretKeyDistr};
    use primus_lwe::LweDimension;
    use primus_shape::PolyLength;
    use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
    use primus_tfhe_glwe_fourier::{
        BlindRotationMethod, DecompositionConfig, GadgetEncryptionConfig, LweConfig, ModulusConfig,
        PbsConfig, PbsMessageConfig, TfheContext, experimental,
    };
    use rand::{SeedableRng, rngs::StdRng};
    use std::hint::black_box;

    /// The u32 fixture follows the documented dense profile; never truncate a u64 config.
    fn dense_u32() -> PbsConfig<u32> {
        let decomposition = |log, levels| DecompositionConfig {
            log_basis: DecompositionBaseLog::new(log),
            level_count: Some(DecompositionLevelCount::new(levels)),
        };
        PbsConfig {
            small_lwe: LweConfig {
                dimension: LweDimension::new(866),
                cipher_modulus: ModulusConfig::Native,
                noise_standard_deviation: 2.046_151_696_979_124e-6 * 4294967296.0,
                secret_key_distr: SecretKeyDistr::UniformBinary,
            },
            ring_modulus: ModulusConfig::Native,
            bsk_dimension: GlweDimension::new(1),
            bsk_poly_length: PolyLength::new(2048),
            bsk_secret_distr: SecretKeyDistr::UniformBinary,
            bsk_gadget: GadgetEncryptionConfig {
                decomposition: decomposition(8, 3),
                noise_standard_deviation: 6.4,
            },
            key_switching: GadgetEncryptionConfig {
                decomposition: decomposition(2, 13),
                noise_standard_deviation: 6.4,
            },
            method: BlindRotationMethod::Classic,
            order: primus_tfhe_glwe_fourier::PbsOrder::BootstrapKeyswitch,
            messages: PbsMessageConfig::new(32),
        }
    }

    /// Prepare one complete PBS at its actual word, modulus and return domain.
    fn measure<Word: TorusFftValue, Table: FftTable>(
        c: &mut Criterion,
        engine: &str,
        case: &str,
        config: PbsConfig<Word>,
    ) {
        let context = TfheContext::<Word, Table>::try_from_pbs_config(config).unwrap();
        // Client: fixed seeds keep setup and inputs reproducible.
        let mut key_rng = StdRng::seed_from_u64(42);
        let (client, server) = context.try_generate_keys(&mut key_rng).unwrap();
        let secret = client.external_lwe_secret_key();
        let encryptor = context.encryptor(secret).unwrap();
        let decryptor = context.pbs_decryptor(secret).unwrap();
        let mut rng = StdRng::seed_from_u64(4242);
        let mut input = context.allocate_lwe_ciphertext();

        // Server: allocate/compile before Criterion's closure, then check the returned LWE.
        let table = context
            .pbs_lookup_table_compiler()
            .unwrap()
            .compile_fn(|x| Word::as_from((3 * x + 1) % 16))
            .unwrap();
        let mut evaluator = context.evaluator(&server).unwrap();
        let mut output = context.allocate_lwe_ciphertext();
        for message in [0, 7] {
            encryptor
                .encrypt_padded_to(Word::as_from(message), input.as_mut_view(), &mut rng)
                .unwrap();
            evaluator.apply_lookup_table_to(input.as_view(), &table, output.as_mut_view());
            assert_eq!(
                decryptor.decrypt(output.as_view()).unwrap(),
                Word::as_from((3 * message + 1) % 16)
            );
        }
        let mut group = c.benchmark_group(format!("pbs/glwe/{engine}"));
        group.throughput(Throughput::Elements(1)); // Complete requests, not output count.
        group.bench_function(case, |b| {
            b.iter(|| {
                evaluator.apply_lookup_table_to(
                    black_box(input.as_view()),
                    black_box(&table),
                    output.as_mut_view(),
                );
                black_box(output.as_view());
            })
        });
        group.finish();
        assert_eq!(
            decryptor.decrypt(output.as_view()).unwrap(),
            Word::as_from(6)
        );
    }

    fn benchmark<Table: FftTable>(c: &mut Criterion, engine: &str) {
        measure::<u32, Table>(c, engine, "classic_dense/u32", dense_u32());
        measure::<u64, Table>(
            c,
            engine,
            "classic_dense/u64",
            experimental::CLASSIC_PBS_U64,
        );
    }

    /// Frozen comparison card: independent n1024/h128 and k1/N4096 secrets.
    /// Decomposition pairs below are (base log, levels); this is not a security preset.
    fn comparison_config(high: bool) -> PbsConfig<u64> {
        let gadget = |log, levels, noise| GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(log),
                level_count: Some(DecompositionLevelCount::new(levels)),
            },
            noise_standard_deviation: noise,
        };
        let lwe_noise = 3.2 * 2f64.powi(40);
        PbsConfig {
            small_lwe: LweConfig {
                dimension: LweDimension::new(1024),
                cipher_modulus: ModulusConfig::Native,
                noise_standard_deviation: lwe_noise,
                secret_key_distr: SecretKeyDistr::FixedHammingWeightBinary {
                    hamming_weight: 128,
                },
            },
            ring_modulus: ModulusConfig::Native,
            bsk_dimension: GlweDimension::new(1),
            bsk_poly_length: PolyLength::new(4096),
            bsk_secret_distr: SecretKeyDistr::UniformBinary,
            bsk_gadget: if high {
                gadget(5, 9, 1.5)
            } else {
                gadget(10, 4, 1.5)
            },
            key_switching: if high {
                gadget(2, 9, lwe_noise)
            } else {
                gadget(3, 6, lwe_noise)
            },
            method: BlindRotationMethod::Classic,
            order: primus_tfhe_glwe_fourier::PbsOrder::BootstrapKeyswitch,
            messages: PbsMessageConfig::new(32),
        }
    }

    fn comparison_function(message: u64) -> u64 {
        ((13 * message) ^ (message >> 2)) & 15
    }

    /// Recover the full phase independently of the codec, including the padding half.
    fn check_comparison_return(ciphertext: &[u64], secret: &[u64], message: u64) {
        let q = 1u128 << 64;
        assert_eq!(ciphertext.len(), secret.len() + 1);
        let dot: u128 = ciphertext[..secret.len()]
            .iter()
            .zip(secret)
            .map(|(&a, &s)| u128::from(a) * u128::from(s))
            .sum();
        let phase = (u128::from(ciphertext[secret.len()]) + q - dot % q) % q;
        let center = (u128::from(message) * q + 16) / 32;
        let error = (phase + q - center) % q;
        assert!(
            error.min(q - error) < q / 64,
            "returned phase crossed the decoding half-cell"
        );
    }

    /// All validation and client work stay outside the complete server request.
    fn comparison<Table: FftTable>(c: &mut Criterion, engine: &str, profile: &str) {
        let context =
            TfheContext::<u64, Table>::try_from_pbs_config(comparison_config(profile == "high"))
                .unwrap();
        let (client, server) = context
            .try_generate_keys(&mut StdRng::seed_from_u64(42))
            .unwrap();
        let secret = client.external_lwe_secret_key();
        assert_eq!(
            client.small_lwe_secret_key().as_ref().iter().sum::<u64>(),
            128
        );
        assert!(
            client
                .small_lwe_secret_key()
                .as_ref()
                .iter()
                .all(|&s| s <= 1)
        );
        let encryptor = context.encryptor(secret).unwrap();
        let decryptor = context.pbs_decryptor(secret).unwrap();
        let mut input = context.allocate_lwe_ciphertext();
        let mut output = context.allocate_lwe_ciphertext();
        let table = context
            .pbs_lookup_table_compiler()
            .unwrap()
            .compile_fn(|m| comparison_function(m as u64))
            .unwrap();
        let mut evaluator = context.evaluator(&server).unwrap();
        let mut input_rng = StdRng::seed_from_u64(1042);
        for message in 0..16 {
            encryptor
                .encrypt_padded_to(message, input.as_mut_view(), &mut input_rng)
                .unwrap();
            assert!(input.as_ref()[..1024].iter().any(|&a| a != 0));
            evaluator.apply_lookup_table_to(input.as_view(), &table, output.as_mut_view());
            let expected = comparison_function(message);
            assert_eq!(
                decryptor.decrypt(output.as_view()).unwrap(),
                expected,
                "input={message}"
            );
            check_comparison_return(
                output.as_ref(),
                client.small_lwe_secret_key().as_ref(),
                expected,
            );
        }
        // Reset the input stream so adding validation cases cannot change the timed fixture.
        input_rng = StdRng::seed_from_u64(1042);
        encryptor
            .encrypt_padded_to(13, input.as_mut_view(), &mut input_rng)
            .unwrap();
        evaluator.apply_lookup_table_to(input.as_view(), &table, output.as_mut_view());
        check_comparison_return(output.as_ref(), client.small_lwe_secret_key().as_ref(), 10);
        let mut group = c.benchmark_group("pbs4/glwe");
        group.sampling_mode(criterion::SamplingMode::Flat);
        group.throughput(Throughput::Elements(1));
        group.bench_function(format!("{engine}/{profile}"), |b| {
            b.iter(|| {
                evaluator.apply_lookup_table_to(
                    black_box(input.as_view()),
                    black_box(&table),
                    output.as_mut_view(),
                );
                black_box(output.as_view());
            })
        });
        group.finish();
        assert_eq!(decryptor.decrypt(output.as_view()).unwrap(), 10);
        check_comparison_return(output.as_ref(), client.small_lwe_secret_key().as_ref(), 10);
    }

    pub(super) fn benchmarks(c: &mut Criterion) {
        // Opt-in selection happens before key generation, including feature validation.
        if let Some(selected) = std::env::var_os("PRIMUS_PBS_CASE") {
            let selected = selected
                .into_string()
                .expect("PRIMUS_PBS_CASE must be UTF-8");
            let (engine, profile) = selected
                .split_once('/')
                .expect("use engine/low or engine/high");
            assert!(
                matches!(profile, "low" | "high"),
                "invalid comparison profile: {profile}"
            );
            match engine {
                #[cfg(feature = "rustfft")]
                "rustfft" => comparison::<primus_fft::RustFftTable>(c, engine, profile),
                #[cfg(feature = "tfhe-fft")]
                "tfhe-fft" => comparison::<primus_fft::TfheFftTable>(c, engine, profile),
                _ => panic!("unsupported or disabled PRIMUS_PBS_CASE={selected:?}"),
            }
            return;
        }

        #[cfg(feature = "rustfft")]
        benchmark::<primus_fft::RustFftTable>(c, "rustfft");
        #[cfg(feature = "tfhe-fft")]
        benchmark::<primus_fft::TfheFftTable>(c, "tfhe-fft");
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
