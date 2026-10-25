//! Complete-operation latency with reusable outputs, keys, tables and workspaces.
//! Sampling, encoding/decoding and required transforms remain inside timing.
//! Codec variants are measured in primus_encoding/benches/plaintext_codec.rs.
//!
//! Cases use u64, binary keys, noise sigma 3.2 and plaintext modulus 16;
//! NTT uses q = 1_125_899_906_826_241, Fourier uses the native torus.
//! These are regression workloads, not matched-security backend comparisons.
//!
//! cargo bench -p primus_glwe --bench encryption --features ntt,rustfft
//! cargo bench -p primus_glwe --bench encryption --features ntt,rustfft -- encrypt_ggsw_to

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_encoding::PlaintextEmbedding;
use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGgswCiphertext, FourierGlevCiphertext, FourierGlweDecryptWorkspace,
    FourierGlweEncryptWorkspace, FourierGlweGadgetEncryptWorkspace, FourierGlweSecretKey,
    GlevParameters, GlweCiphertext, GlweParameters, NttGgswCiphertext, NttGlevCiphertext,
    NttGlweGadgetEncryptWorkspace, NttGlwePublicEncryptWorkspace, NttGlwePublicKey,
    NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::{hint::black_box, time::Duration};
use zeroize::Zeroizing;

const SIZES: [(usize, usize); 2] = [(1, 1024), (2, 4096)];
const LOG_BASE: u32 = 10;
const LEVELS: usize = 3;

fn ntt_encryption(c: &mut Criterion) {
    for (dimension, n) in SIZES {
        let mut rng = StdRng::seed_from_u64(42);
        let message = Polynomial::new((0..n).map(|i| (i % 16) as u64).collect::<Vec<_>>());
        let mut plaintext = Polynomial::new(vec![0u64; n]);
        let modulus = BarrettModulus::new(1_125_899_906_826_241u64);
        let poly_length = PolyLength::new(n);
        let params = GlweParameters::new(
            GlweDimension::new(dimension),
            poly_length,
            16,
            modulus,
            SecretKeyDistr::UniformBinary,
            3.2,
        );
        let ntt = UintNttTable::new(poly_length, modulus).unwrap();
        let (_, sk) = NttGlweSecretKey::generate_pair(
            params.size(),
            params.encryption_parameters(),
            &ntt,
            &mut rng,
        );
        let pk = NttGlwePublicKey::generate(&sk, params.encryption_parameters(), &ntt, &mut rng);
        let mut public_workspace = NttGlwePublicEncryptWorkspace::new(poly_length);
        let mut ciphertext = sk.encrypt_message(
            &message,
            &params,
            PlaintextEmbedding::Unsigned,
            &ntt,
            &mut rng,
        );
        sk.decrypt_message_to(&ciphertext, &mut plaintext, &params, &ntt);
        assert_eq!(plaintext.as_ref(), message.as_ref());
        let decrypt_input = ciphertext.clone();
        let gadget = GlevParameters::with_glwe_params(
            &params,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(LOG_BASE),
                level_count: Some(DecompositionLevelCount::new(LEVELS)),
            },
        );
        let mut gadget_workspace = NttGlweGadgetEncryptWorkspace::new(gadget.size());
        let mut glev = NttGlevCiphertext::<Vec<u64>>::zero(gadget.glev_len());
        let mut ggsw = NttGgswCiphertext::<Vec<u64>>::zero(gadget.ggsw_len());
        let mut group = c.benchmark_group(format!("glwe/ntt/k{dimension}_n{n}"));
        group.bench_function("encrypt_sk_to", |b| {
            b.iter(|| {
                sk.encrypt_message_to(
                    black_box(&message),
                    &mut ciphertext,
                    black_box(&params),
                    PlaintextEmbedding::Unsigned,
                    &ntt,
                    &mut rng,
                );
                black_box(ciphertext.as_ref());
            })
        });
        group.bench_function("encrypt_pk_to", |b| {
            b.iter(|| {
                pk.encrypt_message_to(
                    black_box(&message),
                    &mut ciphertext,
                    black_box(&params),
                    PlaintextEmbedding::Unsigned,
                    &ntt,
                    &mut rng,
                    &mut public_workspace,
                );
                black_box(ciphertext.as_ref());
            })
        });
        group.bench_function("decrypt_to", |b| {
            b.iter(|| {
                sk.decrypt_message_to(
                    black_box(&decrypt_input),
                    &mut plaintext,
                    black_box(&params),
                    &ntt,
                );
                black_box(plaintext.as_ref());
            })
        });
        let mut coefficients = GlweCiphertext::<Vec<u64>>::zero(params.glwe_len());
        let mut coefficient_scratch = Zeroizing::new(vec![0; n]);
        sk.encrypt_message_coeff_to(
            &message,
            &mut coefficients,
            &params,
            PlaintextEmbedding::Unsigned,
            &ntt,
            &mut rng,
            &mut coefficient_scratch,
        );
        sk.decrypt_message_coeff_to(
            &coefficients,
            &mut plaintext,
            &params,
            &ntt,
            &mut coefficient_scratch,
        );
        assert_eq!(plaintext.as_ref(), message.as_ref());
        let coefficient_decrypt_input = coefficients.clone();
        group.bench_function("encrypt_coeff_to", |b| {
            b.iter(|| {
                sk.encrypt_message_coeff_to(
                    black_box(&message),
                    &mut coefficients,
                    black_box(&params),
                    PlaintextEmbedding::Unsigned,
                    &ntt,
                    &mut rng,
                    &mut coefficient_scratch,
                );
                black_box(coefficients.as_ref());
            })
        });
        group.bench_function("decrypt_coeff_to", |b| {
            b.iter(|| {
                sk.decrypt_message_coeff_to(
                    black_box(&coefficient_decrypt_input),
                    &mut plaintext,
                    black_box(&params),
                    &ntt,
                    &mut coefficient_scratch,
                );
                black_box(plaintext.as_ref());
            })
        });
        group.bench_function(
            format!("encrypt_glev_to/log_base{LOG_BASE}_levels{LEVELS}"),
            |b| {
                b.iter(|| {
                    sk.encrypt_glev_to(
                        black_box(&message),
                        &mut glev,
                        &gadget,
                        &ntt,
                        &mut rng,
                        &mut gadget_workspace,
                    );
                    black_box(glev.as_ref());
                })
            },
        );
        group.bench_function(
            format!("encrypt_ggsw_to/log_base{LOG_BASE}_levels{LEVELS}"),
            |b| {
                b.iter(|| {
                    sk.encrypt_ggsw_to(
                        black_box(&message),
                        &mut ggsw,
                        &gadget,
                        &ntt,
                        &mut rng,
                        &mut gadget_workspace,
                    );
                    black_box(ggsw.as_ref());
                })
            },
        );

        // One batch iteration models a short stream of BSK control entries.
        let constants = [0u64, 1, 0, 1, 1, 0, 1, 0];
        let mut batch = vec![0; constants.len() * gadget.ggsw_len()];
        group.throughput(criterion::Throughput::Elements(constants.len() as u64));
        group.bench_function("encrypt_ggsw_constant_batch_to/count8", |b| {
            b.iter(|| {
                sk.encrypt_ggsw_constant_batch_to(
                    black_box(&constants),
                    &mut batch,
                    &gadget,
                    &ntt,
                    &mut rng,
                    &mut gadget_workspace,
                );
                black_box(&batch);
            })
        });
        group.finish();
    }
}

fn fourier_encryption(c: &mut Criterion) {
    for (dimension, n) in SIZES {
        let mut rng = StdRng::seed_from_u64(42);
        let message = Polynomial::new((0..n).map(|i| (i % 16) as u64).collect::<Vec<_>>());
        let mut plaintext = Polynomial::new(vec![0u64; n]);
        let poly_length = PolyLength::new(n);
        let params = GlweParameters::new(
            GlweDimension::new(dimension),
            poly_length,
            16,
            NativeModulus::<u64>::new(),
            SecretKeyDistr::UniformBinary,
            3.2,
        );
        let table = RustFftTable::new(poly_length);
        let mut fft = FftEngine::new(&table);
        let (_, sk) = FourierGlweSecretKey::generate_pair(
            params.size(),
            params.encryption_parameters(),
            &mut fft,
            &mut rng,
        );
        let mut encrypt_workspace = FourierGlweEncryptWorkspace::new(poly_length);
        let mut decrypt_workspace = FourierGlweDecryptWorkspace::new(poly_length);
        let mut ciphertext = sk.encrypt_message(
            &message,
            &params,
            PlaintextEmbedding::Unsigned,
            &mut fft,
            &mut rng,
            &mut encrypt_workspace,
        );
        sk.decrypt_message_to(
            &ciphertext,
            &mut plaintext,
            &params,
            &mut fft,
            &mut decrypt_workspace,
        );
        assert_eq!(plaintext.as_ref(), message.as_ref());
        let decrypt_input = ciphertext.clone();
        let gadget = GlevParameters::with_glwe_params(
            &params,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(LOG_BASE),
                level_count: Some(DecompositionLevelCount::new(LEVELS)),
            },
        );
        let mut gadget_workspace = FourierGlweGadgetEncryptWorkspace::new(gadget.size());
        let mut glev = FourierGlevCiphertext::<Vec<_>>::zero(gadget.fourier_glev_len());
        let mut ggsw = FourierGgswCiphertext::<Vec<_>>::zero(gadget.fourier_ggsw_len());
        let mut group = c.benchmark_group(format!("glwe/fourier/k{dimension}_n{n}"));
        group.bench_function("encrypt_sk_to", |b| {
            b.iter(|| {
                sk.encrypt_message_to(
                    black_box(&message),
                    &mut ciphertext,
                    black_box(&params),
                    PlaintextEmbedding::Unsigned,
                    &mut fft,
                    &mut rng,
                    &mut encrypt_workspace,
                );
                black_box(ciphertext.as_ref());
            })
        });
        group.bench_function("decrypt_to", |b| {
            b.iter(|| {
                sk.decrypt_message_to(
                    black_box(&decrypt_input),
                    &mut plaintext,
                    black_box(&params),
                    &mut fft,
                    &mut decrypt_workspace,
                );
                black_box(plaintext.as_ref());
            })
        });
        group.bench_function(
            format!("encrypt_glev_to/log_base{LOG_BASE}_levels{LEVELS}"),
            |b| {
                b.iter(|| {
                    sk.encrypt_glev_to(
                        black_box(&message),
                        &mut glev,
                        &gadget,
                        &mut fft,
                        &mut rng,
                        &mut gadget_workspace,
                    );
                    black_box(glev.as_ref());
                })
            },
        );
        group.bench_function(
            format!("encrypt_ggsw_to/log_base{LOG_BASE}_levels{LEVELS}"),
            |b| {
                b.iter(|| {
                    sk.encrypt_ggsw_to(
                        black_box(&message),
                        &mut ggsw,
                        &gadget,
                        &mut fft,
                        &mut rng,
                        &mut gadget_workspace,
                    );
                    black_box(ggsw.as_ref());
                })
            },
        );

        // One batch iteration models a short stream of BSK control entries.
        let constants = [0u64, 1, 0, 1, 1, 0, 1, 0];
        let mut batch =
            vec![primus_fft::Complex64::default(); constants.len() * gadget.fourier_ggsw_len()];
        group.throughput(criterion::Throughput::Elements(constants.len() as u64));
        group.bench_function("encrypt_ggsw_constant_batch_to/count8", |b| {
            b.iter(|| {
                sk.encrypt_ggsw_constant_batch_to(
                    black_box(&constants),
                    &mut batch,
                    &gadget,
                    &mut fft,
                    &mut rng,
                    &mut gadget_workspace,
                );
                black_box(&batch);
            })
        });
        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(50)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    targets = ntt_encryption, fourier_encryption
}
criterion_main!(benches);
