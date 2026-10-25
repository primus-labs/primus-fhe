//! NTRU key switching, automorphism, trace, expansion and scheme switching.
//! Each case reuses output/workspace; projection and prefix expansion have different contracts.
//! cargo bench -p primus_ntru --bench primitives --features ntt,rustfft,tfhe-fft -- 'ntt/n4096/logb3'
//! Functional u64 workloads: sparse ternary keys, sigma 3.2, maximum basis length.
//! Setup is excluded; these parameters do not establish cryptographic security.

use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_encoding::PlaintextEmbedding;
use primus_shape::PolyLength;
use std::{hint::black_box, time::Duration};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNgswCiphertext, FourierNlevCiphertext, FourierNtruSchemeSwitchKey, FourierNtruTraceKey,
    FourierNtruTraceWorkspace, NlevCiphertext, NttNgswCiphertext, NttNlevCiphertext,
    NttNtruSchemeSwitchKey, NttNtruTraceKey, NttNtruTraceWorkspace,
};
use primus_ntru::{
    FourierNtruAutomorphismKey, FourierNtruAutomorphismWorkspace, FourierNtruCiphertext,
    FourierNtruEncryptWorkspace, FourierNtruExternalProductWorkspace,
    FourierNtruGadgetEncryptWorkspace, FourierNtruKeySwitchingKey, FourierNtruSecretKey,
    NlevParameters, NtruCiphertext, NtruParameters, NttNtruAutomorphismKey,
    NttNtruAutomorphismWorkspace, NttNtruCiphertext, NttNtruExternalProductWorkspace,
    NttNtruGadgetEncryptWorkspace, NttNtruKeySwitchingKey, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

fn ntt(c: &mut Criterion, n: usize) {
    let mut rng = StdRng::seed_from_u64(42);
    let modulus = BarrettModulus::new(1_125_899_906_826_241u64);
    let poly_length = PolyLength::new(n);
    let parameters =
        NtruParameters::new(poly_length, 16, modulus, SecretKeyDistr::SparseTernary, 3.2);
    let table = UintNttTable::new(poly_length, modulus).unwrap();
    let (coeff_key, key) =
        NttNtruSecretKey::generate_pair(parameters.encryption_parameters(), &table, &mut rng)
            .unwrap();
    let message = Polynomial::new(
        (0..n)
            .map(|i| if i < 8 { i as u64 } else { 0 })
            .collect::<Vec<_>>(),
    );
    let transformed = key.encrypt_message(
        &message,
        &parameters,
        PlaintextEmbedding::Unsigned,
        &table,
        &mut rng,
    );
    let mut input = NtruCiphertext::<Vec<u64>>::zero(n);
    transformed.write_coeff_form(&mut input, &table);
    let mut output = NtruCiphertext::<Vec<u64>>::zero(n);
    let mut ntt_output = NttNtruCiphertext::<Vec<u64>>::zero(n);
    let mut generation = NttNtruGadgetEncryptWorkspace::new(poly_length);
    let mut switching = NttNtruExternalProductWorkspace::new(poly_length);
    let mut auto_workspace = NttNtruAutomorphismWorkspace::new(poly_length);
    let output_parameters = NlevParameters::with_ntru_params(
        &parameters,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    );
    for log_basis in [3, 10] {
        let parameters = NlevParameters::with_ntru_params(
            &parameters,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(log_basis),
                level_count: None,
            },
        );
        let ksk = NttNtruKeySwitchingKey::generate(
            &coeff_key,
            &key,
            &parameters,
            &table,
            &mut rng,
            &mut generation,
        );
        let auto = NttNtruAutomorphismKey::generate(
            3,
            &coeff_key,
            &key,
            &parameters,
            &table,
            &mut rng,
            &mut generation,
        );
        let trace = NttNtruTraceKey::generate(
            &coeff_key,
            &key,
            &parameters,
            &table,
            &mut rng,
            &mut generation,
        );
        let mut trace_workspace = NttNtruTraceWorkspace::new(poly_length);
        let mut expanded = vec![0u64; 8 * n];
        let ss = NttNtruSchemeSwitchKey::generate(
            &coeff_key,
            &key,
            output_parameters.basis(),
            &parameters,
            &table,
            &mut rng,
            &mut generation,
        );
        let mut nlev = NttNlevCiphertext::<Vec<u64>>::zero(output_parameters.nlev_len());
        key.encrypt_nlev_constant_to(
            1,
            &mut nlev,
            &output_parameters,
            &table,
            &mut rng,
            &mut generation,
        );
        let mut ss_input = NlevCiphertext::<Vec<u64>>::zero(output_parameters.nlev_len());
        for (input, mut output) in nlev.iter_ntt_ntru(n).zip(ss_input.iter_ntru_mut(n)) {
            input.write_coeff_form(&mut output, &table);
        }
        let mut ss_output = NttNgswCiphertext::<Vec<u64>>::zero(output_parameters.nlev_len());
        let mut group = c.benchmark_group(format!(
            "ntru/ntt/n{n}/logb{log_basis}/l{}",
            parameters.level_count().get()
        ));
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function("key_switch", |b| {
            b.iter(|| {
                ksk.key_switch_to(
                    black_box(&input),
                    &mut output,
                    modulus,
                    &table,
                    &mut switching,
                );
                black_box(output.as_ref());
            })
        });
        group.bench_function("automorphism_coeff", |b| {
            b.iter(|| {
                auto.apply_to(
                    black_box(&input),
                    &mut output,
                    modulus,
                    &table,
                    &mut auto_workspace,
                );
                black_box(output.as_ref());
            })
        });
        group.bench_function("automorphism_ntt", |b| {
            b.iter(|| {
                auto.apply_ntt_to(
                    black_box(&transformed),
                    &mut ntt_output,
                    modulus,
                    &table,
                    &mut auto_workspace,
                );
                black_box(ntt_output.as_ref());
            })
        });
        group.bench_function("trace", |b| {
            b.iter(|| {
                trace.apply_to(
                    black_box(&input),
                    &mut output,
                    modulus,
                    &table,
                    &mut trace_workspace,
                );
                black_box(output.as_ref());
            })
        });
        group.bench_function("reverse_trace", |b| {
            b.iter(|| {
                trace.apply_reverse_to(
                    black_box(&input),
                    &mut output,
                    modulus,
                    &table,
                    &mut trace_workspace,
                );
                black_box(output.as_ref());
            })
        });
        group.bench_function("project_3", |b| {
            b.iter(|| {
                trace.project_coefficients_to(
                    black_box(&input),
                    &[0, 3, 7],
                    &mut expanded[..3 * n],
                    modulus,
                    &table,
                    &mut trace_workspace,
                );
                black_box(&expanded[..3 * n]);
            })
        });
        group.bench_function("expand_prefix_8", |b| {
            b.iter(|| {
                trace.expand_partial_coefficients_to(
                    black_box(&input),
                    8,
                    &mut expanded,
                    modulus,
                    &table,
                    &mut trace_workspace,
                );
                black_box(&expanded);
            })
        });
        group.bench_function("scheme_switch/logb_out8/l_out3", |b| {
            b.iter(|| {
                ss.apply_to(
                    black_box(&ss_input),
                    &mut ss_output,
                    modulus,
                    &table,
                    &mut switching,
                );
                black_box(ss_output.as_ref());
            })
        });
        group.finish();
    }
}

fn fourier<Table: FftTable>(c: &mut Criterion, n: usize, backend: &str) {
    let mut rng = StdRng::seed_from_u64(42);
    let poly_length = PolyLength::new(n);
    let parameters = NtruParameters::new(
        poly_length,
        16u64,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        3.2,
    );
    let table = Table::new(poly_length);
    let mut fft = FftEngine::new(&table);
    let (coeff_key, key) =
        FourierNtruSecretKey::generate_pair(parameters.encryption_parameters(), &mut fft, &mut rng)
            .unwrap();
    let message = Polynomial::new(
        (0..n)
            .map(|i| if i < 8 { i as u64 } else { 0 })
            .collect::<Vec<_>>(),
    );
    let transformed = key.encrypt_message(
        &message,
        &parameters,
        PlaintextEmbedding::Unsigned,
        &mut fft,
        &mut rng,
        &mut FourierNtruEncryptWorkspace::new(poly_length),
    );
    let mut input = NtruCiphertext::<Vec<u64>>::zero(n);
    transformed.write_torus_form(&mut input, &mut fft);
    let mut output = NtruCiphertext::<Vec<u64>>::zero(n);
    let mut fourier_output = FourierNtruCiphertext::<Vec<Complex64>>::zero(n / 2);
    let mut generation = FourierNtruGadgetEncryptWorkspace::new(poly_length);
    let mut switching = FourierNtruExternalProductWorkspace::new(poly_length);
    let mut auto_workspace = FourierNtruAutomorphismWorkspace::new(poly_length);
    let output_parameters = NlevParameters::with_ntru_params(
        &parameters,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    );
    for log_basis in [3, 10] {
        let parameters = NlevParameters::with_ntru_params(
            &parameters,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(log_basis),
                level_count: None,
            },
        );
        let ksk = FourierNtruKeySwitchingKey::generate(
            &coeff_key,
            &key,
            &parameters,
            &mut fft,
            &mut rng,
            &mut generation,
        );
        let auto = FourierNtruAutomorphismKey::generate(
            3,
            &coeff_key,
            &key,
            &parameters,
            &mut fft,
            &mut rng,
            &mut generation,
        );
        let trace = FourierNtruTraceKey::generate(
            &coeff_key,
            &key,
            &parameters,
            &mut fft,
            &mut rng,
            &mut generation,
        );
        let mut trace_workspace = FourierNtruTraceWorkspace::new(poly_length);
        let mut expanded = vec![0u64; 8 * n];
        let ss = FourierNtruSchemeSwitchKey::generate(
            &coeff_key,
            &key,
            output_parameters.basis(),
            &parameters,
            &mut fft,
            &mut rng,
            &mut generation,
        );
        let mut nlev =
            FourierNlevCiphertext::<Vec<Complex64>>::zero(output_parameters.fourier_nlev_len());
        key.encrypt_nlev_constant_to(
            1,
            &mut nlev,
            &output_parameters,
            &mut fft,
            &mut rng,
            &mut generation,
        );
        let mut ss_input = NlevCiphertext::<Vec<u64>>::zero(output_parameters.nlev_len());
        for (input, mut output) in nlev.iter_ntru(n / 2).zip(ss_input.iter_ntru_mut(n)) {
            input.write_torus_form(&mut output, &mut fft);
        }
        let mut ss_output =
            FourierNgswCiphertext::<Vec<Complex64>>::zero(output_parameters.fourier_nlev_len());
        let mut group = c.benchmark_group(format!(
            "ntru/fourier/{backend}/n{n}/logb{log_basis}/l{}",
            parameters.level_count().get()
        ));
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function("key_switch", |b| {
            b.iter(|| {
                ksk.key_switch_to(black_box(&input), &mut output, &mut fft, &mut switching);
                black_box(output.as_ref());
            })
        });
        group.bench_function("automorphism_coeff", |b| {
            b.iter(|| {
                auto.apply_to(
                    black_box(&input),
                    &mut output,
                    &mut fft,
                    &mut auto_workspace,
                );
                black_box(output.as_ref());
            })
        });
        group.bench_function("automorphism_fourier", |b| {
            b.iter(|| {
                auto.apply_fourier_to(
                    black_box(&transformed),
                    &mut fourier_output,
                    &mut fft,
                    &mut auto_workspace,
                );
                black_box(fourier_output.as_ref());
            })
        });
        group.bench_function("trace", |b| {
            b.iter(|| {
                trace.apply_to(
                    black_box(&input),
                    &mut output,
                    &mut fft,
                    &mut trace_workspace,
                );
                black_box(output.as_ref());
            })
        });
        group.bench_function("reverse_trace", |b| {
            b.iter(|| {
                trace.apply_reverse_to(
                    black_box(&input),
                    &mut output,
                    &mut fft,
                    &mut trace_workspace,
                );
                black_box(output.as_ref());
            })
        });
        group.bench_function("project_3", |b| {
            b.iter(|| {
                trace.project_coefficients_to(
                    black_box(&input),
                    &[0, 3, 7],
                    &mut expanded[..3 * n],
                    &mut fft,
                    &mut trace_workspace,
                );
                black_box(&expanded[..3 * n]);
            })
        });
        group.bench_function("expand_prefix_8", |b| {
            b.iter(|| {
                trace.expand_partial_coefficients_to(
                    black_box(&input),
                    8,
                    &mut expanded,
                    &mut fft,
                    &mut trace_workspace,
                );
                black_box(&expanded);
            })
        });
        group.bench_function("scheme_switch/logb_out8/l_out3", |b| {
            b.iter(|| {
                ss.apply_to(
                    black_box(&ss_input),
                    &mut ss_output,
                    &mut fft,
                    &mut switching,
                );
                black_box(ss_output.as_ref());
            })
        });
        group.finish();
    }
}

fn benchmarks(c: &mut Criterion) {
    for n in [1024, 4096, 8192] {
        ntt(c, n);
        fourier::<RustFftTable>(c, n, "rustfft");
        fourier::<TfheFftTable>(c, n, "tfhe");
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30)
        .warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(2));
    targets = benchmarks
}
criterion_main!(benches);
