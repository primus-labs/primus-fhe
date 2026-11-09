//! cargo bench -p primus_tfhe_glwe_ntt --bench mvb
//! Parameters and comparison limits: guides/development/testing.md#tfhe-benchmarks
//! One iteration is one server request. Setup and correctness checks are untimed.

use criterion::{Criterion, Throughput};
use primus_ntt::U64NttTable as Table;
use primus_tfhe_glwe_ntt::{TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

type Word = u64;

fn benchmark(c: &mut Criterion) {
    let engine = "ntt";
    let config = experimental::CLASSIC_THRESHOLD_MVB_U64;
    let context = TfheContext::<Word, Table>::try_from_pbs_config(config).unwrap();
    // Client: keys, inputs and candidate ciphertexts are all prepared outside timing.
    let mut rng = StdRng::seed_from_u64(42);
    let (client, server) = context.try_generate_keys(&mut rng).unwrap();
    let encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
    let mut input = context.allocate_lwe_ciphertext();
    let decryptor = context
        .mvb_decryptor(client.external_lwe_secret_key())
        .unwrap();

    // Server: one request returns all output LWE ciphertexts, including key switching.
    const DOMAIN: usize = 64;
    const OUTPUTS: usize = 17;
    let thresholds: Vec<_> = (1..=OUTPUTS).map(|i| i * DOMAIN / (OUTPUTS + 1)).collect();
    let function = |x: usize, lane: usize| Word::from(x >= thresholds[lane]);
    let table = context.compile_mvb_fn(DOMAIN, OUTPUTS, function).unwrap();
    let mut evaluator = context.mvb_evaluator(&server).unwrap();
    let mut outputs = vec![context.allocate_lwe_ciphertext(); OUTPUTS];
    for message in [12, 45] {
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();
        evaluator.apply_lookup_table_to(input.as_view(), &table, &mut outputs);
        for (i, output) in outputs.iter().enumerate() {
            assert_eq!(
                decryptor.decrypt(output.as_view()).unwrap(),
                function(message as usize, i)
            );
        }
    }
    let mut group = c.benchmark_group(format!("mvb/glwe/{engine}"));
    group.throughput(Throughput::Elements(1)); // Complete requests, not output count.
    group.bench_function("17_thresholds/u64", |b| {
        b.iter(|| {
            evaluator.apply_lookup_table_to(
                black_box(input.as_view()),
                black_box(&table),
                &mut outputs,
            );
            black_box(&outputs);
        })
    });
    group.finish();
    for (i, output) in outputs.iter().enumerate() {
        assert_eq!(
            decryptor.decrypt(output.as_view()).unwrap(),
            function(45, i)
        );
    }
}

fn benchmarks(c: &mut Criterion) {
    benchmark(c);
}

criterion::criterion_group! {
    name = benches;
    config = criterion::Criterion::default().sample_size(20)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3));
    targets = benchmarks
}
criterion::criterion_main!(benches);
