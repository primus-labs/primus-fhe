//! cargo bench -p primus_tfhe_glwe_ntt --bench cbs_identity -- --test
//! PRIMUS_CBS_DOMAIN=same or split selects the explicit q=Q/q1024 comparison.
//! LightFHE CMUX2 (G1) derived identity CBS; setup and real CMux validation are untimed.
//! PRIMUS_CBS_ENCODING=padded|msb compares input encodings without changing gadgets.
//! bit*_cmux includes both CBS and its encrypted CMux consumer.
//! Parameters differ from the author's input/KS protocol and are not certified presets.
//! Comparison scope: guides/performance/README.md#tfhe-comparisons

use criterion::{BenchmarkId, Criterion, Throughput};
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::phase_error_magnitude;
use primus_glwe::NttGlweSecretKey;
use primus_glwe::{GlweDimension, SecretKeyDistr};
use primus_lwe::LweDimension;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntt::U64NttTable as Table;
use primus_poly::Polynomial;
use primus_reduce::{EncodeSigned, ReduceMul, ReduceNeg, RingContext};
use primus_shape::PolyLength;
use primus_tfhe_glwe_ntt::{
    BlindRotationMethod, CbsConfig, CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig,
    LweConfig, ModulusConfig, PbsConfig, PbsMessageConfig, PbsOrder, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

type Word = u64;
const Q54: Word = 18_014_398_509_404_161;
const CASE: &str = "CMUX2-derived-Q54-t4";

/// Keep the original padded workload unless the MSB comparison is requested.
fn input_encoding() -> primus_tfhe::CbsInputEncoding {
    match std::env::var("PRIMUS_CBS_ENCODING") {
        Err(std::env::VarError::NotPresent) => primus_tfhe::CbsInputEncoding::Padded,
        Ok(value) if value == "padded" => primus_tfhe::CbsInputEncoding::Padded,
        Ok(value) if value == "msb" => primus_tfhe::CbsInputEncoding::MsbBoolean,
        other => panic!("use PRIMUS_CBS_ENCODING=padded or msb, got {other:?}"),
    }
}

/// Specify both gadget fields explicitly: retaining the maximum levels would
/// change the frozen workload and its output weights.
const fn decomposition(base_log: u32, level_count: usize) -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(base_log),
        level_count: Some(DecompositionLevelCount::new(level_count)),
    }
}

/// Benchmark-local candidate, separate from the backend's teaching configs.
/// Padded t4 and discrete sampling differ from the author's p2/MSB protocol.
/// Preserve declared normalized input sigma; do not silently reduce noise.
fn comparison_config<LM: RingContext<Word>>(
    input_modulus: ModulusConfig<LM>,
    input_noise: f64,
) -> CbsConfig<Word, LM> {
    CbsConfig {
        fourier_trace_precision: primus_tfhe_glwe::FourierTracePrecision::Ordinary,
        input_encoding: input_encoding(),
        pbs: PbsConfig {
            small_lwe: LweConfig {
                dimension: LweDimension::new(571),
                cipher_modulus: input_modulus,
                secret_key_distr: SecretKeyDistr::UniformBinary,
                noise_standard_deviation: input_noise,
            },
            ring_modulus: ModulusConfig::Explicit(Q54),
            bsk_dimension: GlweDimension::new(1),
            bsk_poly_length: PolyLength::new(2048),
            bsk_secret_distr: SecretKeyDistr::UniformBinary,
            bsk_gadget: GadgetEncryptionConfig {
                decomposition: decomposition(17, 2),
                noise_standard_deviation: 3.2,
            },
            method: BlindRotationMethod::Classic,
            // Required by the complete Context/key bundle for downstream LWE
            // returns. This independent auxiliary choice is NOT an author KS
            // parameter and is never consumed by direct-input CBS below.
            key_switching: GadgetEncryptionConfig {
                decomposition: decomposition(8, 6),
                noise_standard_deviation: 3.2,
            },
            messages: PbsMessageConfig::new(4),
            order: PbsOrder::BootstrapKeyswitch,
        },
        gadget: CbsGadgetConfig {
            trace: decomposition(13, 3),
            scheme_switch: decomposition(19, 2),
            output: decomposition(4, 4),
        },
    }
}

fn measure<LM>(c: &mut Criterion, case: &str, config: CbsConfig<Word, LM>)
where
    LM: RingContext<Word> + TryFrom<ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
{
    let context = TfheContext::<Word, Table, LM>::try_from_cbs_config(config).unwrap();
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
    let n = config.pbs.bsk_poly_length.get();
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
    let gadget = context.cbs_parameters().unwrap().gadget();
    let size = gadget.output_size();
    let modulus = context.parameters().ring_modulus();
    let transformed_secret =
        NttGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), context.table());
    let mut phase = Polynomial::new(vec![0; n]);
    for (bit, input) in inputs.iter().enumerate() {
        evaluator.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
        // A bit-level consumer alone could hide a missing low gadget row.
        // Validate every row/level at its own scale before registering timings.
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
                for (i, &actual) in phase.as_ref().iter().enumerate() {
                    let weight = modulus.reduce_mul(bit as u64, scalar);
                    let expected = match secret {
                        Some(secret) => modulus.reduce_neg(
                            modulus.reduce_mul(weight, modulus.encode_signed(secret[i])),
                        ),
                        None if i == 0 => weight,
                        None => 0,
                    };
                    assert!(
                        phase_error_magnitude(actual, expected, modulus) <= scalar / 16,
                        "CBS row {row}, coefficient {i} exceeds diagnostic margin"
                    );
                }
            }
        }
        evaluator.cmux_to(
            control.as_view(),
            candidates[0].as_view(),
            candidates[1].as_view(),
            selected.as_mut_view(),
        );
        ring_client.decrypt_to(&selected, &mut decoded);
        assert_eq!(decoded, messages[bit], "CBS bit{bit} consumer failed");
    }

    // Preserve old padded IDs; the MSB case differs only in its input/program encoding.
    let case = if config.input_encoding == primus_tfhe::CbsInputEncoding::Padded {
        case.to_owned()
    } else {
        format!("{}/msb", case.trim_end_matches("-t4"))
    };
    // Time identity CBS ending in a consumable transform-domain GGSW.
    // This gate checks the measured fixtures; it is not a failure-rate estimate.
    let mut group = c.benchmark_group(format!("cbs/glwe/ntt/identity_to_ntt_ggsw/{case}"));
    group.throughput(Throughput::Elements(1));
    group.sampling_mode(criterion::SamplingMode::Flat);
    for (bit, input) in inputs.iter().enumerate() {
        // Seed this bit even when Criterion filters out its CBS-only measurement.
        evaluator.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
        group.bench_function(BenchmarkId::new(format!("bit{bit}"), "u64"), |b| {
            b.iter(|| {
                evaluator.circuit_bootstrap_to(black_box(input.as_view()), control.as_mut_view());
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
        // A separate complete request includes actual use of the generated control.
        group.bench_function(BenchmarkId::new(format!("bit{bit}_cmux"), "u64"), |b| {
            b.iter(|| {
                evaluator.circuit_bootstrap_to(black_box(input.as_view()), control.as_mut_view());
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
fn benchmark(c: &mut Criterion) {
    match std::env::var("PRIMUS_CBS_DOMAIN") {
        Err(std::env::VarError::NotPresent) => measure::<BarrettModulus<u64>>(
            c,
            CASE,
            comparison_config(ModulusConfig::Explicit(Q54), 3.2 * Q54 as f64 / 1024.0),
        ),
        Ok(domain) if domain == "same" => measure::<BarrettModulus<u64>>(
            c,
            "same",
            comparison_config(ModulusConfig::Explicit(Q54), 3.2 * Q54 as f64 / 1024.0),
        ),
        Ok(domain) if domain == "split" => measure::<PowOf2Modulus<u64>>(
            c,
            "split",
            comparison_config(ModulusConfig::Explicit(1024), 3.2),
        ),
        other => panic!("use PRIMUS_CBS_DOMAIN=same or split, got {other:?}"),
    }
}

criterion::criterion_group! {
    name = benches;
    config = criterion::Criterion::default().sample_size(20)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3));
    targets = benchmark
}
criterion::criterion_main!(benches);
