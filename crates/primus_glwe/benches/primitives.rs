//! Complete trace, expansion, packing and Fourier automorphism latency.
//! Keys, outputs and scratch are constructed outside timing.
//! NTT q=1_125_899_906_826_241; Fourier native u64.
//! Both use base 2^10, three levels, binary secrets and sigma 3.2. These are
//! regression workloads, not matched-security comparisons. Ordinary trace and
//! reverse trace measure their public APIs, with their respective message scales.
//! Rank two retains full trace and reverse trace as larger-layout cases.
//! Direct Fourier automorphism compares the two FFT engines at rank one.
//!
//! cargo bench -p primus_glwe --bench primitives --features ntt,rustfft,tfhe-fft

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_encoding::PlaintextEmbedding;
use primus_fft::{FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{
    FourierGlweAutomorphismKey, FourierGlweAutomorphismWorkspace, FourierGlweEncryptor,
    FourierGlwePackingWorkspace, FourierGlweTraceKey, FourierGlweTraceWorkspace, GlevParameters,
    GlweParameters, GlweSecretKey, NttGlweGadgetEncryptWorkspace, NttGlwePackingWorkspace,
    NttGlweSecretKey, NttGlweTraceKey, NttGlweTraceWorkspace, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, glwe::Glwe, lwe::LweIterMut};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_reduce::RingContext;
use primus_shape::PolyLength;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use std::{hint::black_box, time::Duration};

const SIZES: [(usize, usize); 2] = [(1, 1024), (2, 4096)];
const NTT_MODULUS: u64 = 1_125_899_906_826_241;

fn parameters<M: RingContext<u64>>(
    dimension: usize,
    poly_length: PolyLength,
    modulus: M,
) -> (GlweParameters<u64, M>, GlevParameters<u64, M>) {
    let params = GlweParameters::new(
        GlweDimension::new(dimension),
        poly_length,
        64,
        modulus,
        SecretKeyDistr::UniformBinary,
        3.2,
    );
    let glev = GlevParameters::with_glwe_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(10),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    );
    (params, glev)
}

fn message(n: usize) -> Polynomial<Vec<u64>> {
    Polynomial::new((0..n).map(|i| (i % 16) as u64).collect())
}

/// Prepare noiseless LWEs under the flattened binary GLWE secret, with an
/// independently sampled mask for each input. Only packing is timed.
fn related_lwe_batch(
    encoded_message: &[u64],
    key: &GlweSecretKey<u64>,
    modulus: impl RingContext<u64>,
    mut sample: impl FnMut() -> u64,
) -> Vec<u64> {
    let lwe_len = key.glwe_size().mask_len() + 1;
    let mut batch = vec![0; encoded_message.len() * lwe_len];
    for (mut lwe, &encoded) in LweIterMut::new(&mut batch, lwe_len).zip(encoded_message) {
        let (mask, body) = lwe.a_b_mut();
        let mut value = encoded;
        for (coefficient, &secret) in mask.iter_mut().zip(key.as_slice()) {
            *coefficient = sample();
            if secret == 1 {
                value = modulus.reduce_add(value, *coefficient);
            }
        }
        *body = value;
    }
    batch
}

fn ntt_primitives(c: &mut Criterion) {
    for (k, n) in SIZES {
        let mut rng = StdRng::seed_from_u64(42);
        let modulus = BarrettModulus::new(NTT_MODULUS);
        let poly_length = PolyLength::new(n);
        let table = U64NttTable::new(poly_length, modulus).unwrap();
        let (params, glev) = parameters(k, poly_length, modulus);
        let size = params.size();
        let (coeff, sk) =
            NttGlweSecretKey::generate_pair(size, params.encryption_parameters(), &table, &mut rng);
        let mut gadget = NttGlweGadgetEncryptWorkspace::new(glev.size());
        let key = NttGlweTraceKey::generate(&coeff, &sk, &glev, &table, &mut rng, &mut gadget);
        let mut trace = NttGlweTraceWorkspace::new(size);
        let message = message(n);
        let input = sk
            .encrypt_message(
                &message,
                &params,
                PlaintextEmbedding::Unsigned,
                &table,
                &mut rng,
            )
            .into_coeff_form(&table);
        let mut output = Glwe::new(vec![0; size.glwe_len()]);
        let mut group = c.benchmark_group(format!("glwe/ntt/k{k}_n{n}"));
        group.throughput(Throughput::Elements(1));
        group.bench_function("trace", |b| {
            b.iter(|| {
                key.apply_to(black_box(&input), &mut output, modulus, &table, &mut trace);
                black_box(output.as_ref());
            })
        });
        group.bench_function("reverse_trace", |b| {
            b.iter(|| {
                key.apply_reverse_to(black_box(&input), &mut output, modulus, &table, &mut trace);
                black_box(output.as_ref());
            })
        });
        if k != 1 {
            group.finish();
            continue;
        }
        let count = 8;
        let mut partial_message = Polynomial::new(message.as_ref().to_vec());
        partial_message.as_mut()[count..].fill(0);
        let partial_input = sk
            .encrypt_message(
                &partial_message,
                &params,
                PlaintextEmbedding::Unsigned,
                &table,
                &mut rng,
            )
            .into_coeff_form(&table);
        let mut selected = vec![0; count * size.glwe_len()];
        group.throughput(Throughput::Elements(count as u64));
        group.bench_function(format!("project/{count}"), |b| {
            b.iter(|| {
                key.project_prefix_coefficients_to(
                    black_box(&partial_input),
                    count,
                    &mut selected,
                    modulus,
                    &table,
                    &mut trace,
                );
                black_box(&selected);
            })
        });
        group.bench_function(format!("expand_partial/{count}"), |b| {
            b.iter(|| {
                key.expand_partial_coefficients_to(
                    black_box(&partial_input),
                    count,
                    &mut selected,
                    modulus,
                    &table,
                    &mut trace,
                );
                black_box(&selected);
            })
        });
        let mut expanded = vec![0; n * size.glwe_len()];
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("expand/{n}"), |b| {
            b.iter(|| {
                key.expand_coefficients_to(
                    black_box(&input),
                    &mut expanded,
                    modulus,
                    &table,
                    &mut trace,
                );
                black_box(&expanded);
            })
        });
        drop(expanded);
        let mut encoded_message = vec![0u64; n];
        params.plaintext_codec().encode_slice_to(
            message.as_ref(),
            &mut encoded_message,
            PlaintextEmbedding::Unsigned,
        );
        for count in [1, 8, n] {
            let batch = related_lwe_batch(&encoded_message[..count], &coeff, modulus, || {
                rng.random_range(0..NTT_MODULUS)
            });
            let mut packing = NttGlwePackingWorkspace::new(size, count);
            group.throughput(Throughput::Elements(count as u64));
            group.bench_function(format!("pack/{count}"), |b| {
                b.iter(|| {
                    key.pack_lwes_to(
                        black_box(&batch),
                        &mut output,
                        modulus,
                        &table,
                        &mut packing,
                    );
                    black_box(output.as_ref());
                })
            });
        }
        group.finish();
    }
}

/// Measure the public trace and packing APIs with one prepared Fourier trace key.
fn fourier_trace<Table: FftTable>(
    c: &mut Criterion,
    coeff: &GlweSecretKey<u64>,
    sk: &mut FourierGlweEncryptor<'_, u64>,
    params: &GlweParameters<u64, NativeModulus<u64>>,
    glev: &GlevParameters<u64, NativeModulus<u64>>,
    fft: &mut FftEngine<'_, Table>,
    rng: &mut StdRng,
) {
    let size = params.size();
    let k = size.dimension().get();
    let n = size.poly_length().get();
    let key = FourierGlweTraceKey::generate(sk, glev, fft, rng);
    let mut trace = FourierGlweTraceWorkspace::new(size);
    let message = message(n);

    let encrypted = sk.encrypt_message(&message, params, PlaintextEmbedding::Unsigned, fft, rng);
    let mut input = Glwe::new(vec![0u64; size.glwe_len()]);
    encrypted.write_torus_form(&mut input, fft);
    let mut output = Glwe::new(vec![0; size.glwe_len()]);
    let mut group = c.benchmark_group(format!("glwe/fourier/k{k}_n{n}"));
    group.throughput(Throughput::Elements(1));
    group.bench_function("trace", |b| {
        b.iter(|| {
            key.apply_to(black_box(&input), &mut output, fft, &mut trace);
            black_box(output.as_ref());
        })
    });
    group.bench_function("reverse_trace", |b| {
        b.iter(|| {
            key.apply_reverse_to(black_box(&input), &mut output, fft, &mut trace);
            black_box(output.as_ref());
        })
    });
    if k != 1 {
        group.finish();
        return;
    }
    let count = 8;
    let mut partial_message = Polynomial::new(message.as_ref().to_vec());
    partial_message.as_mut()[count..].fill(0);
    let encrypted = sk.encrypt_message(
        &partial_message,
        params,
        PlaintextEmbedding::Unsigned,
        fft,
        rng,
    );
    let mut partial_input = Glwe::new(vec![0u64; size.glwe_len()]);
    encrypted.write_torus_form(&mut partial_input, fft);
    let mut selected = vec![0; count * size.glwe_len()];
    group.throughput(Throughput::Elements(count as u64));
    group.bench_function(format!("project/{count}"), |b| {
        b.iter(|| {
            key.project_prefix_coefficients_to(
                black_box(&partial_input),
                count,
                &mut selected,
                fft,
                &mut trace,
            );
            black_box(&selected);
        })
    });
    group.bench_function(format!("expand_partial/{count}"), |b| {
        b.iter(|| {
            key.expand_partial_coefficients_to(
                black_box(&partial_input),
                count,
                &mut selected,
                fft,
                &mut trace,
            );
            black_box(&selected);
        })
    });
    let mut expanded = vec![0; n * size.glwe_len()];
    group.throughput(Throughput::Elements(n as u64));
    group.bench_function(format!("expand/{n}"), |b| {
        b.iter(|| {
            key.expand_coefficients_to(black_box(&input), &mut expanded, fft, &mut trace);
            black_box(&expanded);
        })
    });
    drop(expanded);
    let mut encoded_message = vec![0; n];
    params.plaintext_codec().encode_slice_to(
        message.as_ref(),
        &mut encoded_message,
        PlaintextEmbedding::Unsigned,
    );
    for count in [1, 8, n] {
        let batch = related_lwe_batch(
            &encoded_message[..count],
            coeff,
            params.cipher_modulus(),
            || rng.random::<u64>(),
        );
        let mut packing = FourierGlwePackingWorkspace::new(size, count);
        group.throughput(Throughput::Elements(count as u64));
        group.bench_function(format!("pack/{count}"), |b| {
            b.iter(|| {
                key.pack_lwes_to(black_box(&batch), &mut output, fft, &mut packing);
                black_box(output.as_ref());
            })
        });
    }
    group.finish();
}

fn fourier_backend<Table: FftTable>(c: &mut Criterion, backend: &str, bench_trace: bool) {
    // Only the trace workload compares ranks.
    let sizes = if bench_trace { &SIZES[..] } else { &SIZES[..1] };
    for &(k, n) in sizes {
        let poly_length = PolyLength::new(n);
        let table = Table::new(poly_length);
        let mut fft = FftEngine::new(&table);
        let mut rng = StdRng::seed_from_u64(42);
        let (params, glev) = parameters(k, poly_length, NativeModulus::new());
        let coeff = GlweSecretKey::generate(
            params.size(),
            params.encryption_parameters().secret_key_sampler(),
            &mut rng,
        );
        let mut sk = FourierGlweEncryptor::try_new(&coeff, params.encryption_parameters()).unwrap();
        if bench_trace {
            fourier_trace(c, &coeff, &mut sk, &params, &glev, &mut fft, &mut rng);
        }
        if k != 1 {
            continue;
        }

        // Keep direct automorphism inputs matched between the two FFT engines,
        // independently of whether this backend also prepares a trace fixture.
        let mut rng = StdRng::seed_from_u64(43);
        let key = FourierGlweAutomorphismKey::generate(3, &mut sk, &glev, &mut fft, &mut rng);
        let mut workspace = FourierGlweAutomorphismWorkspace::new(params.size());
        let message = message(n);

        let input = sk.encrypt_message(
            &message,
            &params,
            PlaintextEmbedding::Unsigned,
            &mut fft,
            &mut rng,
        );
        let mut output = input.clone();
        let mut group = c.benchmark_group(format!("glwe/automorphism/{backend}/k{k}_n{n}"));
        group.bench_function("fourier_to", |b| {
            b.iter(|| {
                key.apply_fourier_to(black_box(&input), &mut output, &mut fft, &mut workspace);
                black_box(output.as_ref());
            })
        });
        group.finish();
    }
}

fn fourier_primitives(c: &mut Criterion) {
    fourier_backend::<RustFftTable>(c, "rustfft", true);
    fourier_backend::<TfheFftTable>(c, "tfhe_fft", false);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10)
        .warm_up_time(Duration::from_millis(300)).measurement_time(Duration::from_secs(1));
    targets = ntt_primitives, fourier_primitives
}
criterion_main!(benches);
