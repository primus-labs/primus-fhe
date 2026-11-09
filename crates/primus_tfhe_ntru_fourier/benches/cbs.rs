//! cargo bench -p primus_tfhe_ntru_fourier --bench cbs
//! RustFFT is the default. Use `--no-default-features --features tfhe-fft` for
//! TFHE-FFT alone, or `--features tfhe-fft` to measure both engines.
//! Parameters and comparison limits: guides/development/testing.md#tfhe-benchmarks
//! One iteration is one server request. Setup and correctness checks are untimed.

#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
mod workloads {
    use criterion::{Criterion, Throughput};
    use primus_fft::FftTable;
    use primus_tfhe_ntru_fourier::{Evaluator, TfheContext, experimental};
    use rand::{SeedableRng, rngs::StdRng};
    use std::hint::black_box;

    type Word = u64;

    fn benchmark<Table: FftTable>(c: &mut Criterion, engine: &str) {
        let config = experimental::CLASSIC_CBS_U64;
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
        let messages: Vec<Vec<Word>> = (0..2)
            .map(|r| (0..n).map(|i| ((i * (r + 1) + r) % 4) as Word).collect())
            .collect();
        let candidates: Vec<_> = messages
            .iter()
            .map(|m| ring_client.encrypt(m, &mut rng))
            .collect();
        let decryptor = context
            .ring_return_decryptor(client.external_lwe_secret_key(), 8)
            .unwrap();
        let mut returned = context.allocate_lwe_ciphertext();
        let index = 1;

        // Server: one predicate CBS, one CMux and one coefficient returned as LWE.
        let mut selected = context.allocate_accumulator_ciphertext();
        let program = context.compile_cbs_fn(|m| Word::from(m >= 2)).unwrap();
        let cbs = context
            .circuit_bootstrap_evaluator_with_lookup_table(&server, program)
            .unwrap();
        let mut control = cbs.allocate_output();
        let (mut cbs, resources) = cbs.into_parts();
        let mut evaluator =
            Evaluator::try_from_resources(&context, resources, server.server_key()).unwrap();
        for message in [1, 3] {
            encryptor
                .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
                .unwrap();
            cbs.circuit_bootstrap_to(
                input.as_view(),
                &mut control,
                evaluator.bootstrap_resources_mut(),
            );
            cbs.cmux_to(
                &control,
                &candidates[0],
                &candidates[1],
                &mut selected,
                evaluator.bootstrap_resources_mut(),
            );
            evaluator.return_ring_at_to(selected.as_view(), index, returned.as_mut_view());
            assert_eq!(
                decryptor.decrypt(returned.as_view()).unwrap(),
                messages[usize::from(message >= 2)][index]
            );
        }
        let mut group = c.benchmark_group(format!("cbs/ntru/{engine}"));
        group.throughput(Throughput::Elements(1)); // Complete requests, not output count.
        group.bench_function("predicate_cmux_return/u64", |b| {
            b.iter(|| {
                cbs.circuit_bootstrap_to(
                    black_box(input.as_view()),
                    &mut control,
                    evaluator.bootstrap_resources_mut(),
                );
                cbs.cmux_to(
                    &control,
                    &candidates[0],
                    &candidates[1],
                    &mut selected,
                    evaluator.bootstrap_resources_mut(),
                );
                evaluator.return_ring_at_to(selected.as_view(), index, returned.as_mut_view());
                black_box(returned.as_view());
            })
        });
        group.finish();
        assert_eq!(
            decryptor.decrypt(returned.as_view()).unwrap(),
            messages[1][index]
        );
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
