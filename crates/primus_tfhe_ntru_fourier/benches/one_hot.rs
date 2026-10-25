//! cargo bench -p primus_tfhe_ntru_fourier --bench one_hot
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
        let config = experimental::CLASSIC_ONE_HOT_U64;
        let context = TfheContext::<Word, Table, _>::try_from_cbs_config(config).unwrap();
        // Client: keys, inputs and candidate ciphertexts are all prepared outside timing.
        let mut rng = StdRng::seed_from_u64(42);
        let (client, server) = context
            .try_generate_circuit_bootstrap_keys(&mut rng)
            .unwrap();
        let encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
        let mut input = context.allocate_lwe_ciphertext();
        let n = config.pbs.bsk_poly_length.get();
        let mut ring_client = context
            .accumulator_client(client.accumulator_ntru_secret_key(), 8)
            .unwrap();
        let messages: Vec<Vec<Word>> = (0..4)
            .map(|r| (0..n).map(|i| ((i * (r + 1) + r) % 4) as Word).collect())
            .collect();
        let candidates: Vec<_> = messages
            .iter()
            .map(|m| ring_client.encrypt(m, &mut rng))
            .collect();
        let mut decoded = vec![0; n];

        // Server: time selector construction and its actual consumption, not ring decryption.
        let mut selected = context.allocate_accumulator_ciphertext();
        let mut evaluator = context.one_hot_evaluator(&server).unwrap();
        let mut selectors = evaluator.allocate_nonzero_ngsw_output();
        for message in [0, 3] {
            encryptor
                .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
                .unwrap();
            evaluator.one_hot_nonzero_ngsw_to(input.as_view(), &mut selectors);
            evaluator.cmux_k_to(
                evaluator.nonzero_ngsw_selectors(&selectors),
                candidates[0].as_view(),
                &candidates[1..],
                selected.as_mut_view(),
            );
            ring_client.decrypt_to(&selected, &mut decoded);
            assert_eq!(decoded, messages[message as usize]);
        }
        let mut group = c.benchmark_group(format!("one_hot/ntru/{engine}"));
        group.throughput(Throughput::Elements(1)); // Complete requests, not output count.
        group.bench_function("select4/u64", |b| {
            b.iter(|| {
                evaluator.one_hot_nonzero_ngsw_to(black_box(input.as_view()), &mut selectors);
                evaluator.cmux_k_to(
                    evaluator.nonzero_ngsw_selectors(&selectors),
                    candidates[0].as_view(),
                    &candidates[1..],
                    selected.as_mut_view(),
                );
                black_box(selected.as_view());
            })
        });
        group.finish();
        ring_client.decrypt_to(&selected, &mut decoded);
        assert_eq!(decoded, messages[3]);
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
