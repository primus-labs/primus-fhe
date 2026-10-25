//! Complete trace, expansion, packing and Fourier automorphism latency.
//! Keys, outputs and scratch are constructed outside timing.
//! NTT q=1_125_899_906_826_241; Fourier native u64.
//! Both use base 2^10, three levels, binary secrets and sigma 3.2. These are
//! regression workloads, not matched-security comparisons. Ordinary trace and
//! reverse trace measure their public APIs, with their respective message scales.
//!
//! cargo bench -p primus_glwe --bench primitives --features ntt,rustfft,tfhe-fft

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_encoding::PlaintextEmbedding;
use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGlweAutomorphismKey, FourierGlweAutomorphismWorkspace, FourierGlweEncryptWorkspace,
    FourierGlweGadgetEncryptWorkspace, FourierGlwePackingWorkspace, FourierGlweSecretKey,
    FourierGlweTraceKey, FourierGlweTraceWorkspace, GlevParameters, GlweParameters,
    NttGlweGadgetEncryptWorkspace, NttGlwePackingWorkspace, NttGlweSecretKey, NttGlweTraceKey,
    NttGlweTraceWorkspace, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_lattice::glwe::Glwe;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_reduce::ReduceAdd;
use primus_shape::PolyLength;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use std::{hint::black_box, time::Duration};

const SIZES: [(usize, usize); 2] = [(1, 1024), (2, 4096)];

fn ntt_primitives(c: &mut Criterion) {
    for (k, n) in SIZES {
        let mut rng = StdRng::seed_from_u64(42);
        let modulus = BarrettModulus::new(1_125_899_906_826_241u64);
        let poly_length = PolyLength::new(n);
        let table = U64NttTable::new(poly_length, modulus).unwrap();
        let params = GlweParameters::new(
            GlweDimension::new(k),
            poly_length,
            64,
            modulus,
            SecretKeyDistr::UniformBinary,
            3.2,
        );
        let size = params.size();
        let (coeff, sk) = NttGlweSecretKey::generate_pair(
            params.size(),
            params.encryption_parameters(),
            &table,
            &mut rng,
        );
        let glev = GlevParameters::with_glwe_params(
            &params,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(10),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
        );
        let mut gadget = NttGlweGadgetEncryptWorkspace::new(glev.size());
        let key = NttGlweTraceKey::generate(&coeff, &sk, &glev, &table, &mut rng, &mut gadget);
        let mut trace = NttGlweTraceWorkspace::new(size);
        let message = Polynomial::new((0..n).map(|i| (i % 16) as u64).collect::<Vec<_>>());
        let input = sk
            .encrypt_message(
                &message,
                &params,
                PlaintextEmbedding::Unsigned,
                &table,
                &mut rng,
            )
            .into_coeff_form(&table);
        let mut encoded_message = vec![0u64; n];
        params.plaintext_codec().add_encode_slice_assign(
            &mut encoded_message,
            message.as_ref(),
            primus_encoding::PlaintextEmbedding::Unsigned,
        );
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
        for count in [8, n / 8] {
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
        }
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
        for count in [1, 8, n] {
            let mut batch = vec![0; count * (size.mask_len() + 1)];
            for (i, lwe) in batch.chunks_exact_mut(size.mask_len() + 1).enumerate() {
                let (mask, body) = lwe.split_at_mut(size.mask_len());
                let mut b = encoded_message[i];
                // Noiseless LWE fixture with an independent mask under the
                // flattened binary key; only packing is timed below.
                for (a, &secret) in mask.iter_mut().zip(coeff.as_slice()) {
                    *a = rng.random_range(0..1_125_899_906_826_241u64);
                    if secret == 1 {
                        b = modulus.reduce_add(b, *a);
                    }
                }
                body[0] = b;
            }
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

fn fourier_primitives(c: &mut Criterion) {
    for (k, n) in SIZES {
        let mut rng = StdRng::seed_from_u64(42);
        let modulus = NativeModulus::<u64>::new();
        let poly_length = PolyLength::new(n);
        let table = RustFftTable::new(poly_length);
        let mut fft = FftEngine::new(&table);
        let params = GlweParameters::new(
            GlweDimension::new(k),
            poly_length,
            64,
            modulus,
            SecretKeyDistr::UniformBinary,
            3.2,
        );
        let size = params.size();
        let (coeff, sk) = FourierGlweSecretKey::generate_pair(
            params.size(),
            params.encryption_parameters(),
            &mut fft,
            &mut rng,
        );
        let glev = GlevParameters::with_glwe_params(
            &params,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(10),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
        );
        let mut gadget = FourierGlweGadgetEncryptWorkspace::new(glev.size());
        let key =
            FourierGlweTraceKey::generate(&coeff, &sk, &glev, &mut fft, &mut rng, &mut gadget);
        let mut trace = FourierGlweTraceWorkspace::new(size);
        let message = Polynomial::new((0..n).map(|i| (i % 16) as u64).collect::<Vec<_>>());
        let mut encryption = FourierGlweEncryptWorkspace::new(poly_length);
        let encrypted = sk.encrypt_message(
            &message,
            &params,
            PlaintextEmbedding::Unsigned,
            &mut fft,
            &mut rng,
            &mut encryption,
        );
        let mut input = Glwe::new(vec![0u64; size.glwe_len()]);
        encrypted.write_torus_form(&mut input, &mut fft);
        let mut encoded_message = vec![0u64; n];
        params.plaintext_codec().add_encode_slice_assign(
            &mut encoded_message,
            message.as_ref(),
            primus_encoding::PlaintextEmbedding::Unsigned,
        );
        let mut output = Glwe::new(vec![0; size.glwe_len()]);
        let mut group = c.benchmark_group(format!("glwe/fourier/k{k}_n{n}"));
        group.throughput(Throughput::Elements(1));
        group.bench_function("trace", |b| {
            b.iter(|| {
                key.apply_to(black_box(&input), &mut output, &mut fft, &mut trace);
                black_box(output.as_ref());
            })
        });
        group.bench_function("reverse_trace", |b| {
            b.iter(|| {
                key.apply_reverse_to(black_box(&input), &mut output, &mut fft, &mut trace);
                black_box(output.as_ref());
            })
        });
        for count in [8, n / 8] {
            let mut partial_message = Polynomial::new(message.as_ref().to_vec());
            partial_message.as_mut()[count..].fill(0);
            let encrypted = sk.encrypt_message(
                &partial_message,
                &params,
                PlaintextEmbedding::Unsigned,
                &mut fft,
                &mut rng,
                &mut encryption,
            );
            let mut partial_input = Glwe::new(vec![0u64; size.glwe_len()]);
            encrypted.write_torus_form(&mut partial_input, &mut fft);
            let mut selected = vec![0; count * size.glwe_len()];
            group.throughput(Throughput::Elements(count as u64));
            group.bench_function(format!("project/{count}"), |b| {
                b.iter(|| {
                    key.project_prefix_coefficients_to(
                        black_box(&partial_input),
                        count,
                        &mut selected,
                        &mut fft,
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
                        &mut fft,
                        &mut trace,
                    );
                    black_box(&selected);
                })
            });
        }
        let mut expanded = vec![0; n * size.glwe_len()];
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("expand/{n}"), |b| {
            b.iter(|| {
                key.expand_coefficients_to(black_box(&input), &mut expanded, &mut fft, &mut trace);
                black_box(&expanded);
            })
        });
        drop(expanded);
        for count in [1, 8, n] {
            let mut batch = vec![0; count * (size.mask_len() + 1)];
            for (i, lwe) in batch.chunks_exact_mut(size.mask_len() + 1).enumerate() {
                let (mask, body) = lwe.split_at_mut(size.mask_len());
                let mut b = encoded_message[i];
                // Noiseless LWE fixture with an independent mask under the
                // flattened binary key; only packing is timed below.
                for (a, &secret) in mask.iter_mut().zip(coeff.as_slice()) {
                    *a = rng.random::<u64>();
                    if secret == 1 {
                        b = modulus.reduce_add(b, *a);
                    }
                }
                body[0] = b;
            }
            let mut packing = FourierGlwePackingWorkspace::new(size, count);
            group.throughput(Throughput::Elements(count as u64));
            group.bench_function(format!("pack/{count}"), |b| {
                b.iter(|| {
                    key.pack_lwes_to(black_box(&batch), &mut output, &mut fft, &mut packing);
                    black_box(output.as_ref());
                })
            });
        }
        group.finish();
    }
}

fn fourier_automorphism_backend<Table: FftTable>(c: &mut Criterion, backend: &str) {
    for (k, n) in SIZES {
        let poly_length = PolyLength::new(n);
        let table = Table::new(poly_length);
        let mut fft = FftEngine::new(&table);
        let mut rng = StdRng::seed_from_u64(42);
        let params = GlweParameters::new(
            GlweDimension::new(k),
            poly_length,
            64u64,
            NativeModulus::new(),
            SecretKeyDistr::UniformBinary,
            3.2,
        );
        let (coeff, sk) = FourierGlweSecretKey::generate_pair(
            params.size(),
            params.encryption_parameters(),
            &mut fft,
            &mut rng,
        );
        let glev = GlevParameters::with_glwe_params(
            &params,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(10),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
        );
        let mut gadget = FourierGlweGadgetEncryptWorkspace::new(glev.size());
        let key = FourierGlweAutomorphismKey::generate(
            3,
            &coeff,
            &sk,
            &glev,
            &mut fft,
            &mut rng,
            &mut gadget,
        );
        let mut workspace = FourierGlweAutomorphismWorkspace::new(params.size());
        let message = Polynomial::new((0..n).map(|i| (i % 16) as u64).collect::<Vec<_>>());
        let mut encryption = FourierGlweEncryptWorkspace::new(poly_length);
        let input = sk.encrypt_message(
            &message,
            &params,
            PlaintextEmbedding::Unsigned,
            &mut fft,
            &mut rng,
            &mut encryption,
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

fn fourier_automorphism(c: &mut Criterion) {
    fourier_automorphism_backend::<RustFftTable>(c, "rustfft");
    fourier_automorphism_backend::<primus_fft::TfheFftTable>(c, "tfhe_fft");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10)
        .warm_up_time(Duration::from_millis(300)).measurement_time(Duration::from_secs(1));
    targets = ntt_primitives, fourier_primitives, fourier_automorphism
}
criterion_main!(benches);
