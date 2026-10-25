//! Opt-in paired q=Q/q1024 workload; single-threaded complete PBS requests.
//! PRIMUS_DOMAIN_CASE=split/bk (or same/bk, split/kb, same/kb).
//! cargo bench -p primus_tfhe_glwe_fourier --bench modulus_domains --no-default-features --features tfhe-fft
//! G1-inspired padded t4, not MSB encoding or a certified parameter set.

use criterion::{Criterion, Throughput};
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_fft::TfheFftTable as Table;
use primus_glwe::{GlweDimension, SecretKeyDistr};
use primus_lwe::LweDimension;
use primus_modulus::NativeModulus;
use primus_modulus::PowOf2Modulus;
use primus_reduce::RingContext;
use primus_shape::PolyLength;
use primus_tfhe_glwe_fourier::{
    BlindRotationMethod, DecompositionConfig, GadgetEncryptionConfig, LweConfig, ModulusConfig,
    PbsConfig, PbsMessageConfig, PbsOrder, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

/// Hold Q, geometry and ring gadgets fixed; express fresh input noise in q units.
fn config<LM: RingContext<u64>>(
    input_modulus: ModulusConfig<LM>,
    input_noise: f64,
    order: PbsOrder,
) -> PbsConfig<u64, LM> {
    PbsConfig {
        small_lwe: LweConfig {
            dimension: LweDimension::new(571),
            cipher_modulus: input_modulus,
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: input_noise,
        },
        ring_modulus: ModulusConfig::Native,
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(2048),
        bsk_secret_distr: SecretKeyDistr::UniformBinary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(17),
                level_count: Some(DecompositionLevelCount::new(2)),
            },
            noise_standard_deviation: 3.2,
        },
        // Auxiliary ring-KS choice for this example, not an author parameter.
        key_switching: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(6)),
            },
            noise_standard_deviation: 3.2,
        },
        method: BlindRotationMethod::Classic,
        messages: PbsMessageConfig::new(4),
        order,
    }
}

/// No client work or setup belongs to the measured request. Recheck the final
/// fixture so a failing evaluator cannot leave behind a successful timing.
fn measure<LM>(c: &mut Criterion, case: &str, config: PbsConfig<u64, LM>)
where
    LM: RingContext<u64> + TryFrom<ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
{
    let context = TfheContext::<u64, Table, LM>::try_from_pbs_config(config).unwrap();
    let mut key_rng = StdRng::seed_from_u64(42);
    let (client, server) = context.try_generate_keys(&mut key_rng).unwrap();
    let secret = client.external_lwe_secret_key();
    let encryptor = context.encryptor(secret).unwrap();
    let decryptor = context.pbs_decryptor(secret).unwrap();
    let table = context
        .pbs_lookup_table_compiler()
        .unwrap()
        .compile_fn(|m| 1 - m as u64)
        .unwrap();
    let mut evaluator = context.evaluator(&server).unwrap();
    let mut output = context.allocate_lwe_ciphertext();
    let mut input = context.allocate_lwe_ciphertext();
    let mut input_rng = StdRng::seed_from_u64(1042);
    for message in [0, 1, 0, 1] {
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut input_rng)
            .unwrap();
        evaluator.apply_lookup_table_to(input.as_view(), &table, output.as_mut_view());
        assert_eq!(decryptor.decrypt(output.as_view()).unwrap(), 1 - message);
    }
    // Keep the timed fixture independent of the untimed validation loop.
    input_rng = StdRng::seed_from_u64(1042);
    encryptor
        .encrypt_padded_to(1, input.as_mut_view(), &mut input_rng)
        .unwrap();
    evaluator.apply_lookup_table_to(input.as_view(), &table, output.as_mut_view());
    assert_eq!(decryptor.decrypt(output.as_view()).unwrap(), 0);
    let mut group = c.benchmark_group("pbs/domains/tfhe-fft");
    group.throughput(Throughput::Elements(1));
    group.sampling_mode(criterion::SamplingMode::Flat);
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
    assert_eq!(decryptor.decrypt(output.as_view()).unwrap(), 0);
}

fn benchmarks(c: &mut Criterion) {
    let case = std::env::var("PRIMUS_DOMAIN_CASE")
        .expect("set PRIMUS_DOMAIN_CASE=same/bk, split/bk, same/kb or split/kb");
    let (domain, order) = case.split_once('/').expect("use domain/order");
    let order = match order {
        "bk" => PbsOrder::BootstrapKeyswitch,
        "kb" => PbsOrder::KeyswitchBootstrap,
        _ => panic!("unsupported PBS order: {order}"),
    };
    match domain {
        "same" => measure::<NativeModulus<u64>>(
            c,
            &case,
            config(
                ModulusConfig::Native,
                3.2 * (1u128 << 64) as f64 / 1024.0,
                order,
            ),
        ),
        "split" => measure::<PowOf2Modulus<u64>>(
            c,
            &case,
            config(ModulusConfig::Explicit(1024), 3.2, order),
        ),
        _ => panic!("unsupported input domain: {domain}"),
    }
}
criterion::criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(2));
    targets = benchmarks
}
criterion::criterion_main!(benches);
