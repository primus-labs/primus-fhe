use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGlweGadgetEncryptWorkspace, FourierGlwePackingWorkspace, FourierGlweSecretKey,
    FourierGlweTraceKey, FourierGlweTraceWorkspace, GlevParameters, GlweParameters, GlweSecretKey,
    GlweSize, NttGlweGadgetEncryptWorkspace, NttGlwePackingWorkspace, NttGlweSecretKey,
    NttGlweTraceKey, NttGlweTraceWorkspace, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_lattice::{glwe::Glwe, lwe::Lwe};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, U64NttTable};
use primus_shape::PolyLength;
use rand::{RngExt, SeedableRng, rngs::StdRng};

mod common;
use common::{K, N, assert_phase, encrypt, message, phase, secret};

const Q: u64 = 1_125_899_906_826_241;

// Prefix projection must preserve the general path's exact rounding, including
// count=1 with a nonzero message tail. It is not prefix-only expansion.
fn check_prefix_projection(reference: &[u64], mut project: impl FnMut(usize, &mut [u64])) {
    let glwe_len = GlweSize::new(GlweDimension::new(K), PolyLength::new(N)).glwe_len();
    for count in [0, 1, 3, N] {
        let mut output = vec![7; count * glwe_len];
        project(count, &mut output);
        assert_eq!(output, reference[..count * glwe_len]);
    }
    for (count, length) in [
        (N + 1, (N + 1) * glwe_len),
        (0, glwe_len),
        (3, 3 * glwe_len - 1),
    ] {
        let mut output = vec![7; length];
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                project(count, &mut output);
            }))
            .is_err()
        );
        assert!(output.iter().all(|&value| value == 7));
    }
}

// The input message has a zero tail, but its encrypted masks/body are dense.
// A schoolbook phase oracle checks every output coefficient after early stopping.
fn check_partial_expansion(
    input: &Glwe<Vec<u64>>,
    expanded: &[u64],
    secret: &[i64],
    q: u128,
    mut expand: impl FnMut(&Glwe<Vec<u64>>, usize, &mut [u64]),
) {
    let size = GlweSize::new(GlweDimension::new(K), PolyLength::new(N));
    let mut rng = StdRng::seed_from_u64(0x5041525449414c);
    for log_count in 0..=N.trailing_zeros() {
        let count = 1 << log_count;
        let mut m = message(q);
        m[count..].fill(0);
        let input = encrypt(&m, secret, q, &mut rng);
        let mut output = vec![u64::MAX; count * size.glwe_len()];
        expand(&input, count, &mut output);
        for (cipher, &value) in output.chunks_exact(size.glwe_len()).zip(&m[..count]) {
            let mut expected = vec![0; N];
            expected[0] = value;
            assert_phase(cipher, &expected, secret, q);
        }
        if count == 1 {
            assert_eq!(output, input.as_ref());
        }
    }
    let mut output = vec![7; expanded.len()];
    expand(input, N, &mut output);
    assert_eq!(output, expanded);
    // A nonzero message tail is retained in residue-class polynomials; it
    // cannot be silently treated as selected constant-coefficient projection.
    let count = 4;
    output.resize(count * size.glwe_len(), 7);
    expand(input, count, &mut output);
    let m = message(q);
    for (i, cipher) in output.chunks_exact(size.glwe_len()).enumerate() {
        let mut expected = vec![0; N];
        for j in (i..N).step_by(count) {
            expected[j - i] = m[j];
        }
        assert_phase(cipher, &expected, secret, q);
    }
    for (count, len) in [
        (0, 0),
        (3, 3 * size.glwe_len()),
        (2 * N, 0),
        (4, size.glwe_len()),
    ] {
        let mut output = vec![7; len];
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                expand(input, count, &mut output);
            }))
            .is_err()
        );
        assert!(output.iter().all(|&value| value == 7));
    }
}

fn lwe_batch(count: usize, secret: &[i64], q: u128, rng: &mut StdRng) -> Vec<u64> {
    let mut batch = vec![0; count * (K * N + 1)];
    for (i, lwe) in batch
        .as_chunks_mut::<{ K * N + 1 }>()
        .0
        .iter_mut()
        .enumerate()
    {
        let (mask, body) = lwe.split_at_mut(K * N);
        let mut b = (i as u128 + 1) * (q / 64);
        for (a, &s) in mask.iter_mut().zip(secret) {
            *a = (u128::from(rng.random::<u64>()) % q) as u64;
            let prod = u128::from(*a) * s.unsigned_abs() as u128 % q;
            b = (b + if s < 0 { (q - prod) % q } else { prod }) % q;
        }
        body[0] = b as u64;
    }
    batch
}

#[test]
fn ntt_trace_projection_and_packing() {
    let modulus = BarrettModulus::new(Q);
    let ntt = U64NttTable::new(PolyLength::new(N), modulus).unwrap();
    let size = GlweSize::new(GlweDimension::new(K), PolyLength::new(N));
    let params = GlweParameters::new(
        GlweDimension::new(K),
        PolyLength::new(N),
        64,
        modulus,
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    let glev = GlevParameters::with_glwe_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(10),
            level_count: Some(DecompositionLevelCount::new(5)),
        },
    );
    let s = secret();
    let coeff = GlweSecretKey::new(s.clone(), size, SecretKeyDistr::UniformTernary);
    let sk = NttGlweSecretKey::from_coeff_secret_key(&coeff, &ntt);
    let mut rng = StdRng::seed_from_u64(0x5452414345);
    let mut gadget = NttGlweGadgetEncryptWorkspace::new(glev.size());
    let key = NttGlweTraceKey::generate(&coeff, &sk, &glev, &ntt, &mut rng, &mut gadget);
    let mut workspace = NttGlweTraceWorkspace::new(size);
    let m = message(Q.into());
    let input = encrypt(&m, &s, Q.into(), &mut rng);
    let mut output = Glwe::<Vec<u64>>::zero(size.glwe_len());
    for r in [1, 4, N] {
        key.apply_reverse_partial_to(&input, r, &mut output, modulus, &ntt, &mut workspace);
        let expected: Vec<_> = m
            .iter()
            .enumerate()
            .map(|(i, &m)| if i % (N / r) == 0 { m } else { 0 })
            .collect();
        assert_phase(output.as_ref(), &expected, &s, Q.into());
        key.apply_partial_to(&input, r, &mut output, modulus, &ntt, &mut workspace);
        let scaled: Vec<_> = expected
            .iter()
            .map(|&v| (u128::from(v) * (N / r) as u128 % u128::from(Q)) as u64)
            .collect();
        assert_phase(output.as_ref(), &scaled, &s, Q.into());
    }
    let mut trivial = Glwe::new(vec![0; size.glwe_len()]);
    let (_, body) = trivial.a_b_mut_slices(N);
    for (i, v) in body.iter_mut().enumerate() {
        *v = match i % 4 {
            0 => 0,
            1 => 1,
            2 => Q - 1,
            _ => Q / 2,
        };
    }
    // Keep odd residues in the retained subring: integer floor division must
    // not accidentally pass as multiplication by the field inverse of two.
    body[0] = 1;
    body[N / 4] = Q - 1;
    body[N / 2] = Q / 2;
    body[3 * N / 4] = Q - 2;
    for r in [1, 4, N] {
        key.apply_reverse_partial_to(&trivial, r, &mut output, modulus, &ntt, &mut workspace);
        let expected: Vec<_> = trivial
            .a_b_slices(N)
            .1
            .iter()
            .enumerate()
            .map(|(i, &v)| if i % (N / r) == 0 { v } else { 0 })
            .collect();
        assert_eq!(phase(output.as_ref(), &s, Q.into()), expected);
    }
    let indices = [N - 1, 0, 7, 7];
    let mut selected = vec![0; indices.len() * size.glwe_len()];
    key.project_coefficients_to(
        &input,
        &indices,
        &mut selected,
        modulus,
        &ntt,
        &mut workspace,
    );
    for (c, &i) in selected.chunks_exact(size.glwe_len()).zip(&indices) {
        let mut expected = vec![0; N];
        expected[0] = m[i];
        assert_phase(c, &expected, &s, Q.into());
    }
    let mut projected = vec![0; N * size.glwe_len()];
    key.project_coefficients_to(
        &input,
        &(0..N).collect::<Vec<_>>(),
        &mut projected,
        modulus,
        &ntt,
        &mut workspace,
    );
    check_prefix_projection(&projected, |count, output| {
        key.project_prefix_coefficients_to(&input, count, output, modulus, &ntt, &mut workspace);
    });
    let mut expanded = vec![0; N * size.glwe_len()];
    key.expand_coefficients_to(&input, &mut expanded, modulus, &ntt, &mut workspace);
    check_partial_expansion(&input, &expanded, &s, Q.into(), |input, count, output| {
        key.expand_partial_coefficients_to(input, count, output, modulus, &ntt, &mut workspace);
    });
    for count in [1, 4, N] {
        let batch = lwe_batch(count, &s, Q.into(), &mut rng);
        let mut packing = NttGlwePackingWorkspace::new(size, count);
        key.pack_lwes_to(&batch, &mut output, modulus, &ntt, &mut packing);
        let mut expected = vec![0; N];
        for i in 0..count {
            expected[i * N / count] = (i as u64 + 1) * (Q / 64);
        }
        assert_phase(output.as_ref(), &expected, &s, Q.into());
        if count == 1 {
            let mut single = Glwe::<Vec<u64>>::zero(size.glwe_len());
            key.pack_lwe_to(
                &Lwe::new(batch.as_slice()),
                &mut single,
                modulus,
                &ntt,
                &mut workspace,
            );
            assert_eq!(output.as_ref(), single.as_ref());
        }
    }
    for invalid in [0, 3, N + 1] {
        output.as_mut().fill(7);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                key.apply_reverse_partial_to(
                    &input,
                    invalid,
                    &mut output,
                    modulus,
                    &ntt,
                    &mut workspace,
                );
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&v| v == 7));
    }
    let mut wrong_workspace =
        NttGlweTraceWorkspace::new(GlweSize::new(GlweDimension::new(5), PolyLength::new(N * 2)));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            key.apply_reverse_to(&input, &mut output, modulus, &ntt, &mut wrong_workspace);
        }))
        .is_err()
    );
    assert!(output.as_ref().iter().all(|&v| v == 7));
    let mut packing = NttGlwePackingWorkspace::new(size, 1);
    for len in [0, K * N, 3 * (K * N + 1), 2 * (K * N + 1)] {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                key.pack_lwes_to(&vec![0; len], &mut output, modulus, &ntt, &mut packing);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&v| v == 7));
    }
    let mut selected = vec![7; 2 * size.glwe_len()];
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            key.project_coefficients_to(
                &input,
                &[0, N],
                &mut selected,
                modulus,
                &ntt,
                &mut workspace,
            );
        }))
        .is_err()
    );
    assert!(selected.iter().all(|&v| v == 7));
}

#[test]
fn fourier_trace_projection_and_packing() {
    fourier_trace_projection_and_packing_backend::<RustFftTable>();
    fourier_trace_projection_and_packing_backend::<primus_fft::TfheFftTable>();
}

fn fourier_trace_projection_and_packing_backend<Table: FftTable>() {
    let q = 1u128 << 64;
    let modulus = NativeModulus::<u64>::new();
    let table = Table::new(PolyLength::new(N));
    let mut fft = FftEngine::new(&table);
    let size = GlweSize::new(GlweDimension::new(K), PolyLength::new(N));
    let params = GlweParameters::new(
        GlweDimension::new(K),
        PolyLength::new(N),
        64,
        modulus,
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    let glev = GlevParameters::with_glwe_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(7)),
        },
    );
    let s = secret();
    let coeff = GlweSecretKey::<u64>::new(s.clone(), size, SecretKeyDistr::UniformTernary);
    let sk = FourierGlweSecretKey::from_coeff_secret_key(&coeff, &mut fft);
    let mut rng = StdRng::seed_from_u64(0x5452414345);
    let mut gadget = FourierGlweGadgetEncryptWorkspace::new(glev.size());
    let key = FourierGlweTraceKey::generate(&coeff, &sk, &glev, &mut fft, &mut rng, &mut gadget);
    let mut workspace = FourierGlweTraceWorkspace::new(size);
    let m = message(q);
    let input = encrypt(&m, &s, q, &mut rng);
    let mut output = Glwe::<Vec<u64>>::zero(size.glwe_len());
    for r in [1, 4, N] {
        key.apply_reverse_partial_to(&input, r, &mut output, &mut fft, &mut workspace);
        let expected: Vec<_> = m
            .iter()
            .enumerate()
            .map(|(i, &m)| if i % (N / r) == 0 { m } else { 0 })
            .collect();
        assert_phase(output.as_ref(), &expected, &s, q);
        key.apply_partial_to(&input, r, &mut output, &mut fft, &mut workspace);
        let scaled: Vec<_> = expected
            .iter()
            .map(|&v| v.wrapping_mul((N / r) as u64))
            .collect();
        assert_phase(output.as_ref(), &scaled, &s, q);
    }
    // A one-level reverse trace on a trivial ciphertext exposes unsigned floor
    // division for 1 and the wrapped representative -1 without FFT error.
    let mut trivial = Glwe::new(vec![0; size.glwe_len()]);
    trivial.as_mut()[K * N] = 1;
    trivial.as_mut()[K * N + 2] = u64::MAX;
    key.apply_reverse_partial_to(&trivial, N / 2, &mut output, &mut fft, &mut workspace);
    let mut expected = vec![0; N];
    expected[2] = u64::MAX - 1;
    assert_eq!(phase(output.as_ref(), &s, q), expected);
    let indices = [N - 1, 0, 7, 7];
    let mut selected = vec![0; indices.len() * size.glwe_len()];
    key.project_coefficients_to(&input, &indices, &mut selected, &mut fft, &mut workspace);
    for (c, &i) in selected.chunks_exact(size.glwe_len()).zip(&indices) {
        let mut expected = vec![0; N];
        expected[0] = m[i];
        assert_phase(c, &expected, &s, q);
    }
    let mut projected = vec![0; N * size.glwe_len()];
    key.project_coefficients_to(
        &input,
        &(0..N).collect::<Vec<_>>(),
        &mut projected,
        &mut fft,
        &mut workspace,
    );
    check_prefix_projection(&projected, |count, output| {
        key.project_prefix_coefficients_to(&input, count, output, &mut fft, &mut workspace);
    });
    let mut expanded = vec![0; N * size.glwe_len()];
    key.expand_coefficients_to(&input, &mut expanded, &mut fft, &mut workspace);
    check_partial_expansion(&input, &expanded, &s, q, |input, count, output| {
        key.expand_partial_coefficients_to(input, count, output, &mut fft, &mut workspace);
    });
    for count in [1, 4, N] {
        let batch = lwe_batch(count, &s, q, &mut rng);
        let mut packing = FourierGlwePackingWorkspace::new(size, count);
        key.pack_lwes_to(&batch, &mut output, &mut fft, &mut packing);
        let mut expected = vec![0; N];
        for i in 0..count {
            expected[i * N / count] = ((i as u128 + 1) * (q / 64)) as u64;
        }
        assert_phase(output.as_ref(), &expected, &s, q);
        if count == 1 {
            let mut single = Glwe::<Vec<u64>>::zero(size.glwe_len());
            key.pack_lwe_to(
                &Lwe::new(batch.as_slice()),
                &mut single,
                &mut fft,
                &mut workspace,
            );
            assert_eq!(output.as_ref(), single.as_ref());
        }
    }
    for invalid in [0, 3, N + 1] {
        output.as_mut().fill(7);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                key.apply_reverse_partial_to(
                    &input,
                    invalid,
                    &mut output,
                    &mut fft,
                    &mut workspace,
                );
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&v| v == 7));
    }
    let mut wrong_workspace = FourierGlweTraceWorkspace::new(GlweSize::new(
        GlweDimension::new(5),
        PolyLength::new(N * 2),
    ));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            key.apply_reverse_to(&input, &mut output, &mut fft, &mut wrong_workspace);
        }))
        .is_err()
    );
    assert!(output.as_ref().iter().all(|&v| v == 7));
    let mut packing = FourierGlwePackingWorkspace::new(size, 1);
    for len in [0, K * N, 3 * (K * N + 1), 2 * (K * N + 1)] {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                key.pack_lwes_to(&vec![0; len], &mut output, &mut fft, &mut packing);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&v| v == 7));
    }
    let mut selected = vec![7; 2 * size.glwe_len()];
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            key.project_coefficients_to(&input, &[0, N], &mut selected, &mut fft, &mut workspace);
        }))
        .is_err()
    );
    assert!(selected.iter().all(|&v| v == 7));
}
