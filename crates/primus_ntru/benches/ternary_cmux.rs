//! One encrypted ternary NTRU rotation: fused versus two binary CMUXes.
//! Keys, monomial exponent, output and scratch allocation are outside timing.
//! cargo bench -p primus_ntru --bench ternary_cmux --features ntt,rustfft,tfhe-fft
//! SIMD comparison: cargo +nightly bench -p primus_ntru --bench ternary_cmux --features ntt,simd,rustfft,tfhe-fft

use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_encoding::PlaintextEmbedding;
use primus_shape::PolyLength;
use std::{hint::black_box, time::Duration};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use num_traits::{ConstOne, ConstZero};
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_integer::{FheUint, SignedInteger};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNgswCiphertext, FourierNtruCmuxWorkspace, FourierNtruEncryptWorkspace,
    FourierNtruExternalProductWorkspace, FourierNtruGadgetEncryptWorkspace, FourierNtruSecretKey,
    NlevParameters, NtruCiphertext, NtruParameters, NttNgswCiphertext, NttNtruCmuxWorkspace,
    NttNtruExternalProductWorkspace, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

fn ntt<T: FheUint>(c: &mut Criterion, q: T, levels: usize) {
    const N: usize = 1024;
    let modulus = BarrettModulus::new(q);
    let poly_length = PolyLength::new(N);
    let table = UintNttTable::new(poly_length, modulus).unwrap();
    let params = NtruParameters::new(
        poly_length,
        T::try_from(16).unwrap(),
        modulus,
        SecretKeyDistr::SparseTernary,
        3.2,
    );
    let gadget = NlevParameters::with_ntru_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(levels)),
        },
    );
    let mut rng = StdRng::seed_from_u64(0xB702);
    let key = NttNtruSecretKey::generate(params.encryption_parameters(), &table, &mut rng).unwrap();
    let message = Polynomial::new(
        (0..N)
            .map(|i| T::try_from(i % 16).unwrap())
            .collect::<Vec<_>>(),
    );
    let input = key
        .encrypt_message(
            &message,
            &params,
            PlaintextEmbedding::Unsigned,
            &table,
            &mut rng,
        )
        .into_coeff_form(&table);
    let mut controls = vec![T::ZERO; 2 * gadget.nlev_len()];
    // Independent encryptions of (0,1); both algorithms read the same controls.
    key.encrypt_ngsw_signed_constant_batch_to(
        &[T::SignedInteger::ZERO, T::SignedInteger::ONE],
        &mut controls,
        &gadget,
        &table,
        &mut rng,
    );
    let (positive, negative) = controls.split_at(gadget.nlev_len());
    let positive = NttNgswCiphertext::new(positive);
    let negative = NttNgswCiphertext::new(negative);
    let exponent = N / 3;
    let mut output = NtruCiphertext::<Vec<T>>::zero(N);
    let mut fused =
        NttNtruCmuxWorkspace::<T>::new(poly_length, DecompositionLevelCount::new(levels));
    let (mut binary, mut intermediate) = (
        NttNtruExternalProductWorkspace::<T>::new(poly_length),
        NtruCiphertext::<Vec<T>>::zero(N),
    );

    let mut group = c.benchmark_group(format!(
        "ntru/ternary/ntt/u{}/n{N}/logb8/l{levels}",
        T::BITS
    ));
    group.throughput(Throughput::Elements(1));
    group.bench_function("fused", |b| {
        b.iter(|| {
            black_box(&positive).cmux_ternary_monomial_to(
                black_box(&negative),
                black_box(&input),
                black_box(exponent),
                &mut output,
                gadget.basis(),
                modulus,
                &table,
                &mut fused,
            );
            black_box(output.as_ref());
        })
    });
    group.bench_function("two_binary", |b| {
        b.iter(|| {
            black_box(&positive).cmux_monomial_to(
                black_box(&input),
                black_box(exponent),
                &mut intermediate,
                gadget.basis(),
                modulus,
                &table,
                &mut binary,
            );
            black_box(&negative).cmux_monomial_to(
                &intermediate,
                black_box(2 * N - exponent),
                &mut output,
                gadget.basis(),
                modulus,
                &table,
                &mut binary,
            );
            black_box(output.as_ref());
        })
    });
    group.finish();
}

// Exact coefficient-domain phase for the numerical diagnostic outside timing.
fn native_phase<T: TorusFftValue>(cipher: &[T], secret: &[T::SignedInteger]) -> Vec<T> {
    let n = cipher.len();
    let mut output = vec![T::ZERO; n];
    for (i, &value) in cipher.iter().enumerate() {
        for (j, &secret) in secret.iter().enumerate() {
            let product = value.wrapping_mul(secret.cast_to_unsigned());
            if i + j < n {
                output[i + j] = output[i + j].wrapping_add(product);
            } else {
                output[i + j - n] = output[i + j - n].wrapping_sub(product);
            }
        }
    }
    output
}

fn fourier<T: TorusFftValue, Table: FftTable>(c: &mut Criterion, backend: &str, levels: usize) {
    const N: usize = 1024;
    let poly_length = PolyLength::new(N);
    let table = Table::new(poly_length);
    let mut fft = FftEngine::new(&table);
    let params = NtruParameters::new(
        poly_length,
        T::try_from(16).unwrap(),
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        3.2,
    );
    let gadget = NlevParameters::with_ntru_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(levels)),
        },
    );
    let mut rng = StdRng::seed_from_u64(0xB703);
    let (coeff, key) =
        FourierNtruSecretKey::generate_pair(params.encryption_parameters(), &mut fft, &mut rng)
            .unwrap();
    let message = Polynomial::new(
        (0..N)
            .map(|i| T::try_from(i % 16).unwrap())
            .collect::<Vec<_>>(),
    );
    let mut input = NtruCiphertext::<Vec<T>>::zero(N);
    key.encrypt_message(
        &message,
        &params,
        PlaintextEmbedding::Unsigned,
        &mut fft,
        &mut rng,
        &mut FourierNtruEncryptWorkspace::new(poly_length),
    )
    .write_torus_form(&mut input, &mut fft);
    let mut controls = vec![Complex64::default(); 2 * gadget.fourier_nlev_len()];
    key.encrypt_ngsw_signed_constant_batch_to(
        &[T::SignedInteger::ZERO, T::SignedInteger::ONE],
        &mut controls,
        &gadget,
        &mut fft,
        &mut rng,
        &mut FourierNtruGadgetEncryptWorkspace::new(poly_length),
    );
    let (positive, negative) = controls.split_at(gadget.fourier_nlev_len());
    let positive = FourierNgswCiphertext::new(positive);
    let negative = FourierNgswCiphertext::new(negative);
    let exponent = N / 3;
    let mut output = NtruCiphertext::<Vec<T>>::zero(N);
    let mut fused =
        FourierNtruCmuxWorkspace::<T>::new(poly_length, DecompositionLevelCount::new(levels));
    let (mut binary, mut intermediate) = (
        FourierNtruExternalProductWorkspace::<T>::new(poly_length),
        NtruCiphertext::<Vec<T>>::zero(N),
    );
    let input_phase = native_phase(input.as_ref(), coeff.as_slice());
    let max_rotation_error = |output: &NtruCiphertext<Vec<T>>| {
        let actual = native_phase(output.as_ref(), coeff.as_slice());
        input_phase
            .iter()
            .enumerate()
            .map(|(i, &value)| {
                let index = (i + 2 * N - exponent) % (2 * N);
                let expected = if index < N {
                    value
                } else {
                    value.wrapping_neg()
                };
                let error = actual[index % N]
                    .wrapping_sub(expected)
                    .min(expected.wrapping_sub(actual[index % N]));
                error.into_torus_f64()
            })
            .fold(0.0, f64::max)
    };
    positive.cmux_ternary_monomial_to(
        &negative,
        &input,
        exponent,
        &mut output,
        gadget.basis(),
        &mut fft,
        &mut fused,
    );
    let fused_error = max_rotation_error(&output);
    positive.cmux_monomial_to(
        &input,
        exponent,
        &mut intermediate,
        gadget.basis(),
        &mut fft,
        &mut binary,
    );
    negative.cmux_monomial_to(
        &intermediate,
        2 * N - exponent,
        &mut output,
        gadget.basis(),
        &mut fft,
        &mut binary,
    );
    let binary_error = max_rotation_error(&output);
    eprintln!(
        "{backend}/u{}: controls={} B; max phase error/q fused={fused_error:.3e}, two-CMUX={binary_error:.3e}",
        T::BITS,
        std::mem::size_of_val(controls.as_slice()),
    );
    let mut group = c.benchmark_group(format!(
        "ntru/ternary/fourier/{backend}/u{}/n{N}/logb8/l{levels}",
        T::BITS
    ));
    group.throughput(Throughput::Elements(1));
    group.bench_function("fused", |b| {
        b.iter(|| {
            black_box(&positive).cmux_ternary_monomial_to(
                black_box(&negative),
                black_box(&input),
                black_box(exponent),
                &mut output,
                gadget.basis(),
                &mut fft,
                &mut fused,
            );
            black_box(output.as_ref());
        })
    });
    group.bench_function("two_binary", |b| {
        b.iter(|| {
            black_box(&positive).cmux_monomial_to(
                black_box(&input),
                black_box(exponent),
                &mut intermediate,
                gadget.basis(),
                &mut fft,
                &mut binary,
            );
            black_box(&negative).cmux_monomial_to(
                &intermediate,
                black_box(2 * N - exponent),
                &mut output,
                gadget.basis(),
                &mut fft,
                &mut binary,
            );
            black_box(output.as_ref());
        })
    });
    group.finish();
}

fn benchmarks(c: &mut Criterion) {
    ntt(c, 132_120_577u32, 3);
    ntt(c, 1_125_899_906_826_241u64, 6);
    fourier::<u32, RustFftTable>(c, "rustfft", 3);
    fourier::<u64, RustFftTable>(c, "rustfft", 6);
    fourier::<u32, TfheFftTable>(c, "tfhefft", 3);
    fourier::<u64, TfheFftTable>(c, "tfhefft", 6);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30)
        .warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(2));
    targets = benchmarks
}
criterion_main!(benches);
