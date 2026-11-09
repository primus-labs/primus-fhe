//! cargo bench -p primus_tfhe_ntru_fourier --bench many_lut
//! RustFFT is the default. Use `--no-default-features --features tfhe-fft` for
//! TFHE-FFT alone, or `--features tfhe-fft` to measure both engines.
//! Parameters and comparison limits: guides/development/testing.md#tfhe-benchmarks
//! One iteration is one server request. Setup and correctness checks are untimed.

#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
mod workloads {
    use criterion::{Criterion, Throughput};
    use primus_fft::FftTable;
    use primus_tfhe_ntru_fourier::{TfheContext, experimental};
    use rand::{SeedableRng, rngs::StdRng};
    use std::hint::black_box;

    type Word = u64;

    fn benchmark<Table: FftTable>(c: &mut Criterion, engine: &str) {
        let config = experimental::CLASSIC_MANY_LUT_U64;
        let context = TfheContext::<Word, Table, _>::try_from_pbs_config(config).unwrap();
        // Client: keys, inputs and candidate ciphertexts are all prepared outside timing.
        let mut rng = StdRng::seed_from_u64(42);
        let (client, server) = context.try_generate_keys(&mut rng).unwrap();
        let encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
        let mut input = context.allocate_lwe_ciphertext();
        let decryptor = context
            .pbs_decryptor(client.external_lwe_secret_key())
            .unwrap();

        // Server: one request returns all output LWE ciphertexts, including key switching.
        let function = |x: usize, lane: usize| {
            if lane == 0 {
                (x / 2) as Word
            } else {
                Word::from(x >= 5)
            }
        };
        let table = context
            .pbs_lookup_table_compiler()
            .unwrap()
            .compile_interleaved_fn(2, function)
            .unwrap();
        let mut evaluator = context.evaluator(&server).unwrap();
        let mut outputs = vec![context.allocate_lwe_ciphertext(); 2];
        for message in [4, 6] {
            encryptor
                .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
                .unwrap();
            evaluator.apply_interleaved_lookup_table_to(input.as_view(), &table, &mut outputs);
            for (i, output) in outputs.iter().enumerate() {
                assert_eq!(
                    decryptor.decrypt(output.as_view()).unwrap(),
                    function(message as usize, i)
                );
            }
        }
        let mut group = c.benchmark_group(format!("many_lut/ntru/{engine}"));
        group.throughput(Throughput::Elements(1)); // Complete requests, not output count.
        group.bench_function("grade_flag/u64", |b| {
            b.iter(|| {
                evaluator.apply_interleaved_lookup_table_to(
                    black_box(input.as_view()),
                    black_box(&table),
                    &mut outputs,
                );
                black_box(&outputs);
            })
        });
        group.finish();
        for (i, output) in outputs.iter().enumerate() {
            assert_eq!(decryptor.decrypt(output.as_view()).unwrap(), function(6, i));
        }
    }

    pub(super) fn benchmarks(c: &mut Criterion) {
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
