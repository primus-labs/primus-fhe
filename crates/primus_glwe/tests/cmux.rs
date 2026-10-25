//! Encrypted CMux controls checked against selected messages and signed phase rotations.

use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_encoding::PlaintextEmbedding;
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{
    FourierGlweDecryptWorkspace, FourierGlweEncryptWorkspace, FourierGlweGadgetEncryptWorkspace,
    FourierGlweSecretKey, GlevParameters, GlweParameters, NttGlweGadgetEncryptWorkspace,
    NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_lattice::{
    ggsw::{FourierGgsw, FourierGgswIter, NttGgsw, NttGgswIter},
    glwe::{FourierGlweOwned, Glwe, GlweIter, NttGlwe, TorusGlwe},
    workspace::{FourierGlweExternalProductWorkspace, NttGlweExternalProductWorkspace},
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

mod common;

const DIMENSION: usize = 1;
// Functional ring size; keep the original word widths, moduli and decomposition.
const POLY_LENGTH: usize = 32;
const PLAINTEXT_MODULUS: u32 = 16;

fn plaintext(offset: u32) -> Vec<u32> {
    (0..POLY_LENGTH)
        .map(|index| (index as u32 + offset) % PLAINTEXT_MODULUS)
        .collect()
}

// Both FFT engines consume packed ciphertext views and encrypted selectors.
fn check_fourier_cmux<Table: FftTable>() {
    let table = Table::new(PolyLength::new(POLY_LENGTH));
    let mut fft = FftEngine::new(&table);
    let mut rng = StdRng::seed_from_u64(42);
    let glwe_params = GlweParameters::new(
        GlweDimension::new(DIMENSION),
        PolyLength::new(POLY_LENGTH),
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let params = GlevParameters::with_glwe_params(
        &glwe_params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        },
    );
    let (_, secret_key) = FourierGlweSecretKey::generate_pair(
        glwe_params.size(),
        glwe_params.encryption_parameters(),
        &mut fft,
        &mut rng,
    );
    let mut encrypt_workspace = FourierGlweEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    let mut decrypt_workspace = FourierGlweDecryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    let mut gadget_workspace = FourierGlweGadgetEncryptWorkspace::new(params.size());
    let mut cmux_workspace = FourierGlweExternalProductWorkspace::new(params.size());

    let messages = [plaintext(1), plaintext(7), plaintext(12)];
    let mut ciphertexts: [TorusGlwe<Vec<u32>>; 3] =
        core::array::from_fn(|_| TorusGlwe::zero(params.glwe_len()));
    for (message, ciphertext) in messages.iter().zip(&mut ciphertexts) {
        let mut fourier = FourierGlweOwned::zero(params.fourier_glwe_len());
        secret_key.encrypt_message_to(
            &Polynomial::new(message.as_slice()),
            &mut fourier,
            &glwe_params,
            PlaintextEmbedding::Unsigned,
            &mut fft,
            &mut rng,
            &mut encrypt_workspace,
        );
        fourier.write_torus_form(ciphertext, &mut fft);
    }

    let packed_candidates = [ciphertexts[1].as_ref(), ciphertexts[2].as_ref()].concat();
    let mut output = TorusGlwe::new(vec![u32::MAX; params.glwe_len()]);
    let ggsw_len = params.fourier_ggsw_len();
    let mut controls = vec![Complex64::default(); 2 * ggsw_len];
    // Counts are checked before any write; the subsequent valid calls reuse scratch.
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            FourierGgsw::cmux_k_to(
                FourierGgswIter::new(&controls[..ggsw_len], ggsw_len),
                ciphertexts[0].as_view(),
                GlweIter::new(&packed_candidates, params.glwe_len()),
                output.as_mut_view(),
                params.basis(),
                &mut fft,
                &mut cmux_workspace,
            );
        }))
        .is_err()
    );
    assert!(output.as_ref().iter().all(|&value| value == u32::MAX));

    // Empty k-CMux copies the default exactly; nonempty calls also cover
    // ordinary two-way CMux and every selector with reused output/workspace.
    for (control_count, selected) in [(0, 0), (1, 0), (1, 1), (2, 0), (2, 1), (2, 2)] {
        let selectors = [u32::from(selected == 1), u32::from(selected == 2)];
        secret_key.encrypt_ggsw_constant_batch_to(
            &selectors[..control_count],
            &mut controls[..control_count * ggsw_len],
            &params,
            &mut fft,
            &mut rng,
            &mut gadget_workspace,
        );

        if control_count == 1 {
            FourierGgsw::new(&controls[..ggsw_len]).cmux_to(
                &ciphertexts[0],
                &ciphertexts[1],
                &mut output,
                params.basis(),
                &mut fft,
                &mut cmux_workspace,
            );
        } else {
            FourierGgsw::cmux_k_to(
                FourierGgswIter::new(&controls[..control_count * ggsw_len], ggsw_len),
                ciphertexts[0].as_view(),
                GlweIter::new(
                    &packed_candidates[..control_count * params.glwe_len()],
                    params.glwe_len(),
                ),
                output.as_mut_view(),
                params.basis(),
                &mut fft,
                &mut cmux_workspace,
            );
        }

        if control_count == 0 {
            assert_eq!(output.as_ref(), ciphertexts[0].as_ref());
        }
        let mut output_fourier = FourierGlweOwned::zero(params.fourier_glwe_len());
        output.write_fourier_form(&mut output_fourier, &mut fft);
        assert_eq!(
            secret_key
                .decrypt_message(
                    &output_fourier,
                    &glwe_params,
                    &mut fft,
                    &mut decrypt_workspace,
                )
                .as_ref(),
            messages[selected].as_slice()
        );
    }
}

#[test]
fn fourier_cmux_selects_requested_glwe() {
    check_fourier_cmux::<RustFftTable>();
    check_fourier_cmux::<TfheFftTable>();
}

#[test]
fn ntt_cmux_selects_requested_glwe() {
    const MODULUS: u32 = 132_120_577;

    let modulus = BarrettModulus::new(MODULUS);
    let ntt = UintNttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let glwe_params = GlweParameters::new(
        GlweDimension::new(DIMENSION),
        PolyLength::new(POLY_LENGTH),
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let params = GlevParameters::with_glwe_params(
        &glwe_params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        },
    );
    let (_, secret_key) = NttGlweSecretKey::generate_pair(
        glwe_params.size(),
        glwe_params.encryption_parameters(),
        &ntt,
        &mut rng,
    );
    let mut gadget_workspace = NttGlweGadgetEncryptWorkspace::new(params.size());
    let mut cmux_workspace = NttGlweExternalProductWorkspace::new(params.size());

    let messages = [plaintext(2), plaintext(7), plaintext(11)];
    let mut ciphertexts: [Glwe<Vec<u32>>; 3] =
        core::array::from_fn(|_| Glwe::zero(params.glwe_len()));
    for (message, ciphertext) in messages.iter().zip(&mut ciphertexts) {
        let mut ntt_ciphertext: NttGlwe<Vec<u32>> = NttGlwe::zero(params.glwe_len());
        secret_key.encrypt_message_to(
            &Polynomial::new(message.as_slice()),
            &mut ntt_ciphertext,
            &glwe_params,
            PlaintextEmbedding::Unsigned,
            &ntt,
            &mut rng,
        );
        ntt_ciphertext.write_coeff_form(ciphertext, &ntt);
    }

    let mut output = Glwe::new(vec![u32::MAX; params.glwe_len()]);
    let ggsw_len = params.ggsw_len();
    let mut controls = vec![0u32; 2 * ggsw_len];
    // Borrowed candidates need no intermediate collection of views.
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            NttGgsw::cmux_k_to(
                NttGgswIter::new(&controls[..ggsw_len], ggsw_len),
                ciphertexts[0].as_view(),
                ciphertexts[1..].iter(),
                output.as_mut_view(),
                params.basis(),
                modulus,
                &ntt,
                &mut cmux_workspace,
            );
        }))
        .is_err()
    );
    assert!(output.as_ref().iter().all(|&value| value == u32::MAX));

    for (control_count, selected) in [(0, 0), (1, 0), (1, 1), (2, 0), (2, 1), (2, 2)] {
        let selectors = [u32::from(selected == 1), u32::from(selected == 2)];
        secret_key.encrypt_ggsw_constant_batch_to(
            &selectors[..control_count],
            &mut controls[..control_count * ggsw_len],
            &params,
            &ntt,
            &mut rng,
            &mut gadget_workspace,
        );

        if control_count == 1 {
            NttGgsw::new(&controls[..ggsw_len]).cmux_to(
                &ciphertexts[0],
                &ciphertexts[1],
                &mut output,
                params.basis(),
                modulus,
                &ntt,
                &mut cmux_workspace,
            );
        } else {
            NttGgsw::cmux_k_to(
                NttGgswIter::new(&controls[..control_count * ggsw_len], ggsw_len),
                ciphertexts[0].as_view(),
                ciphertexts[1..1 + control_count].iter(),
                output.as_mut_view(),
                params.basis(),
                modulus,
                &ntt,
                &mut cmux_workspace,
            );
        }

        if control_count == 0 {
            assert_eq!(output.as_ref(), ciphertexts[0].as_ref());
        }
        let mut output_ntt: NttGlwe<Vec<u32>> = NttGlwe::zero(params.glwe_len());
        output.write_ntt_form(&mut output_ntt, &ntt);
        assert_eq!(
            secret_key
                .decrypt_message(&output_ntt, &glwe_params, &ntt)
                .as_ref(),
            messages[selected].as_slice()
        );
    }
}

#[test]
fn ntt_ternary_cmux_rotates_phase_with_encrypted_controls() {
    use common::{K, N, encrypt, message, phase, secret};
    use primus_glwe::GlweSecretKey;
    use primus_lattice::workspace::NttGlweTernaryCmuxWorkspace;

    const Q: u64 = 132_120_577;
    let modulus = BarrettModulus::new(Q);
    let ntt = UintNttTable::new(PolyLength::new(N), modulus).unwrap();
    let glwe = GlweParameters::new(
        GlweDimension::new(K),
        PolyLength::new(N),
        16,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let params = GlevParameters::with_glwe_params(
        &glwe,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    );
    let secret = secret();
    let coeff_key = GlweSecretKey::new(secret.clone(), glwe.size(), glwe.secret_key_distr());
    let key = NttGlweSecretKey::from_coeff_secret_key(&coeff_key, &ntt);
    let mut rng = StdRng::seed_from_u64(51);
    let input = encrypt(&message(u128::from(Q)), &secret, u128::from(Q), &mut rng);
    let input_phase = phase(input.as_ref(), &secret, u128::from(Q));
    let mut controls = vec![0; 2 * params.ggsw_len()];
    let mut encrypt_workspace = NttGlweGadgetEncryptWorkspace::new(params.size());
    let mut workspace = NttGlweTernaryCmuxWorkspace::new(params.size());
    let mut output = Glwe::new(vec![Q - 1; params.glwe_len()]);

    for selector in [1isize, -1, 0] {
        key.encrypt_ggsw_constant_batch_to(
            &[u64::from(selector == 1), u64::from(selector == -1)],
            &mut controls,
            &params,
            &ntt,
            &mut rng,
            &mut encrypt_workspace,
        );
        let (positive, negative) = controls.split_at(params.ggsw_len());
        // Sign/wrap boundaries and an interior shift; zero follows dirty scratch.
        // Exhaustive index arithmetic is covered by the polynomial rotation oracle.
        for exponent in [1, N / 2 - 1, N / 2, N - 1, N, N + 1, 2 * N - 1, 0] {
            NttGgsw::new(positive).cmux_ternary_monomial_to(
                &NttGgsw::new(negative),
                &input,
                exponent,
                &mut output,
                params.basis(),
                modulus,
                &ntt,
                &mut workspace,
            );
            assert_rotated_phase(
                &input_phase,
                output.as_ref(),
                &secret,
                u128::from(Q),
                exponent as isize * selector,
            );
            if exponent == 0 {
                assert_eq!(output.as_ref(), input.as_ref());
            }
        }
    }
}

// Independent signed-index rotation, followed by the shared schoolbook phase oracle.
fn assert_rotated_phase(input: &[u64], output: &[u64], secret: &[i64], q: u128, exponent: isize) {
    let n = input.len();
    let mut expected = vec![0; n];
    for (i, &value) in input.iter().enumerate() {
        let index = (i as isize + exponent).rem_euclid(2 * n as isize) as usize;
        expected[index % n] = if index < n || value == 0 {
            value
        } else {
            (q - u128::from(value)) as u64
        };
    }
    common::assert_phase(output, &expected, secret, q);
}

fn check_fourier_ternary_cmux<Table: FftTable>() {
    use common::{K, N, encrypt, message, phase, secret};
    use primus_glwe::GlweSecretKey;
    use primus_lattice::workspace::FourierGlweTernaryCmuxWorkspace;

    const Q: u128 = 1 << 64;
    let table = Table::new(PolyLength::new(N));
    let mut fft = FftEngine::new(&table);
    let glwe = GlweParameters::new(
        GlweDimension::new(K),
        PolyLength::new(N),
        16u64,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let params = GlevParameters::with_glwe_params(
        &glwe,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    );
    let secret = secret();
    let coeff_key = GlweSecretKey::<u64>::new(secret.clone(), glwe.size(), glwe.secret_key_distr());
    let key = FourierGlweSecretKey::from_coeff_secret_key(&coeff_key, &mut fft);
    let mut rng = StdRng::seed_from_u64(51);
    let input = encrypt(&message(Q), &secret, Q, &mut rng);
    let input_phase = phase(input.as_ref(), &secret, Q);
    let mut controls = vec![Complex64::default(); 2 * params.fourier_ggsw_len()];
    let mut encrypt_workspace = FourierGlweGadgetEncryptWorkspace::new(params.size());
    let mut workspace = FourierGlweTernaryCmuxWorkspace::new(params.size());
    let mut output = Glwe::new(vec![u64::MAX; params.glwe_len()]);
    for selector in [1isize, -1, 0] {
        key.encrypt_ggsw_constant_batch_to(
            &[u64::from(selector == 1), u64::from(selector == -1)],
            &mut controls,
            &params,
            &mut fft,
            &mut rng,
            &mut encrypt_workspace,
        );
        let (positive, negative) = controls.split_at(params.fourier_ggsw_len());
        // Sign/wrap boundaries and an interior shift; zero follows dirty scratch.
        // Exhaustive index arithmetic is covered by the polynomial rotation oracle.
        for exponent in [1, N / 2 - 1, N / 2, N - 1, N, N + 1, 2 * N - 1, 0] {
            FourierGgsw::new(positive).cmux_ternary_monomial_to(
                &FourierGgsw::new(negative),
                &input,
                exponent,
                &mut output,
                params.basis(),
                &mut fft,
                &mut workspace,
            );
            assert_rotated_phase(
                &input_phase,
                output.as_ref(),
                &secret,
                Q,
                exponent as isize * selector,
            );
            if exponent == 0 {
                assert_eq!(output.as_ref(), input.as_ref());
            }
        }
    }
}

#[test]
fn fourier_ternary_cmux_rotates_phase_with_encrypted_controls() {
    check_fourier_ternary_cmux::<RustFftTable>();
    check_fourier_ternary_cmux::<TfheFftTable>();
}
