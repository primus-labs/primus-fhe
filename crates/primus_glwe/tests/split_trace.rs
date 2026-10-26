//! Small public projection contract; exact phases use an independent integer oracle.
#![cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_glwe::{
    FourierGlweEncryptor, GlevParameters, GlweDimension, GlweSecretKey, GlweSize, SecretKeyDistr,
    SplitFourierGlweTraceKey,
};
use primus_lattice::glwe::{Glwe, GlweIter};
use primus_modulus::NativeModulus;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};

fn parameters<T: TorusFftValue>(size: GlweSize) -> GlevParameters<T, NativeModulus<T>> {
    GlevParameters::try_new(
        size,
        NativeModulus::new(),
        SecretKeyDistr::UniformTernary,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(4),
            level_count: None,
        },
        0.7,
    )
    .unwrap()
}

/// Public split keygen must reject unsupported domains before drawing a key row.
fn rejects_before_sampling<T: TorusFftValue, Table: FftTable>(
    key: &GlweSecretKey<T>,
    fft: &mut FftEngine<'_, Table>,
) {
    let params = parameters(key.glwe_size());
    // A declared Gaussian bound permits coefficient 2 during exact setup, so
    // the split boundary itself must still enforce its narrower precision domain.
    let setup_params =
        primus_glwe::GlweEncryptionParameters::new(NativeModulus::new(), key.distr(), 0.7);
    let mut encryptor = FourierGlweEncryptor::try_new(key, &setup_params).unwrap();
    let mut rng = StdRng::seed_from_u64(104);
    let mut untouched = StdRng::seed_from_u64(104);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            SplitFourierGlweTraceKey::generate(&mut encryptor, &params, fft, &mut rng)
        }))
        .is_err()
    );
    assert_eq!(rng.next_u64(), untouched.next_u64());
}

fn product(mask: &[u64], secret: &[i64]) -> Vec<u64> {
    let n = secret.len();
    let mut out = vec![0u64; n];
    for (i, &a) in mask.iter().enumerate() {
        for (j, &s) in secret.iter().enumerate() {
            let p = a.wrapping_mul(s as u64);
            let k = (i + j) % n;
            out[k] = if i + j < n {
                out[k].wrapping_add(p)
            } else {
                out[k].wrapping_sub(p)
            };
        }
    }
    out
}
fn check<Table: FftTable>() {
    let n = 32;
    let length = PolyLength::new(n);
    let size = GlweSize::new(GlweDimension::new(1), length);
    let params = parameters::<u64>(size);
    let secret: Vec<_> = (0..n).map(|i| [-1, 0, 1][i % 3]).collect();
    let key = GlweSecretKey::new(secret.clone(), size, SecretKeyDistr::UniformTernary);
    let table = Table::new(length);
    let mut fft = FftEngine::new(&table);
    let mut rng = StdRng::seed_from_u64(103);
    let mut encryptor =
        FourierGlweEncryptor::try_new(&key, params.encryption_parameters()).unwrap();
    let trace = SplitFourierGlweTraceKey::generate(&mut encryptor, &params, &mut fft, &mut rng);
    let mut workspace = trace.new_workspace();
    let mut input = Glwe::<Vec<u64>>::zero(2 * n);
    for (i, a) in input.as_mut()[..n].iter_mut().enumerate() {
        *a = u64::MAX.wrapping_mul(i as u64 * 7919 + 137);
    }
    let as_product = product(&input.as_ref()[..n], &secret);
    for (i, (b, p)) in input.as_mut()[n..].iter_mut().zip(as_product).enumerate() {
        *b = p.wrapping_add(((i % 7) as u64) << 56);
    }
    for count in [0, 1, 3, n] {
        let mut output = vec![7; count * 2 * n];
        trace.project_prefix_coefficients_to(&input, count, &mut output, &mut fft, &mut workspace);
        for (index, row) in GlweIter::new(&output, 2 * n).enumerate() {
            let prod = product(&row.as_ref()[..n], &secret);
            for (i, (&b, p)) in row.as_ref()[n..].iter().zip(prod).enumerate() {
                let expected = if i == 0 {
                    ((index % 7) as u64) << 56
                } else {
                    0
                };
                // Fixed N32/full-decomposition fixture, not a statistical DFR claim.
                assert!(
                    b.wrapping_sub(p)
                        .wrapping_sub(expected)
                        .cast_signed()
                        .unsigned_abs()
                        < 1 << 24
                );
            }
        }
    }
    let mut output = vec![7; 2 * n];
    for count in [0, 2, n + 1] {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| trace
                .project_prefix_coefficients_to(
                    &input,
                    count,
                    &mut output,
                    &mut fft,
                    &mut workspace
                )))
            .is_err()
        );
        assert!(output.iter().all(|&x| x == 7));
    }
    let bad = GlweSecretKey::new(vec![2; n], size, SecretKeyDistr::gaussian(1.0));
    rejects_before_sampling::<u64, _>(&bad, &mut fft);
    let narrow = GlweSecretKey::new(vec![0; n], size, SecretKeyDistr::UniformTernary);
    rejects_before_sampling::<u32, _>(&narrow, &mut fft);
    let rank2 = GlweSecretKey::new(
        vec![0; 2 * n],
        GlweSize::new(GlweDimension::new(2), length),
        SecretKeyDistr::UniformTernary,
    );
    rejects_before_sampling::<u64, _>(&rank2, &mut fft);
}
#[test]
fn split_trace_projection_and_boundaries() {
    #[cfg(feature = "rustfft")]
    check::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check::<primus_fft::TfheFftTable>();
}
