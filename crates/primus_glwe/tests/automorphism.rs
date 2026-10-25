//! Original-secret phases after automorphism, including nonbinary Fourier keys.

use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_encoding::PlaintextEmbedding;
use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGlweAutomorphismKey, FourierGlweAutomorphismWorkspace,
    FourierGlweGadgetEncryptWorkspace, FourierGlweSecretKey, GlevParameters, GlweParameters,
    GlweSecretKey, GlweSize, NttGlweAutomorphismKey, NttGlweAutomorphismWorkspace,
    NttGlweGadgetEncryptWorkspace, NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_lattice::glwe::{Glwe, NttGlwe};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

mod common;
use common::{K, N, assert_phase, encrypt, message, secret};

// Functional ring size; keep the original word widths, moduli and decomposition.
const POLY_LENGTH: usize = 64;
const DIMENSION: usize = 2;
const PLAINTEXT_MODULUS: u64 = 16;
const MODULUS: u64 = 1_125_899_906_826_241;

fn automorphism_plaintext(input: &[u64], degree: usize) -> Vec<u64> {
    let mut output = vec![0; input.len()];
    for (source, &value) in input.iter().enumerate() {
        let mapped = source * degree % (2 * input.len());
        if mapped < input.len() {
            output[mapped] = value;
        } else {
            output[mapped - input.len()] = (PLAINTEXT_MODULUS - value) % PLAINTEXT_MODULUS;
        }
    }
    output
}

#[test]
fn ntt_and_coefficient_inputs_reuse_the_automorphism_key() {
    let modulus = BarrettModulus::new(MODULUS);
    let ntt = U64NttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let glwe_parameters = GlweParameters::new(
        GlweDimension::new(DIMENSION),
        PolyLength::new(POLY_LENGTH),
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let glev_parameters = GlevParameters::with_glwe_params(
        &glwe_parameters,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(10),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    );
    let mut rng = StdRng::seed_from_u64(0x0043_4253_5052_494d);
    let (coefficient_secret, secret) = NttGlweSecretKey::generate_pair(
        glwe_parameters.size(),
        glwe_parameters.encryption_parameters(),
        &ntt,
        &mut rng,
    );
    let mut gadget = NttGlweGadgetEncryptWorkspace::new(glev_parameters.size());

    let automorphism_key = NttGlweAutomorphismKey::generate(
        3,
        &coefficient_secret,
        &secret,
        &glev_parameters,
        &ntt,
        &mut rng,
        &mut gadget,
    );
    let message: Vec<u64> = (0..POLY_LENGTH)
        .map(|index| (3 * index as u64 + 1) % PLAINTEXT_MODULUS)
        .collect();
    let mut encrypted: NttGlwe<Vec<u64>> = NttGlwe::zero(glwe_parameters.glwe_len());
    secret.encrypt_message_to(
        &Polynomial::new(message.as_slice()),
        &mut encrypted,
        &glwe_parameters,
        PlaintextEmbedding::Unsigned,
        &ntt,
        &mut rng,
    );
    let coefficient_encrypted = encrypted.clone().into_coeff_form(&ntt);
    let mut automated: Glwe<Vec<u64>> = Glwe::zero(glwe_parameters.glwe_len());
    let mut automorphism_workspace = NttGlweAutomorphismWorkspace::new(glwe_parameters.size());
    automorphism_key.apply_to(
        &coefficient_encrypted,
        &mut automated,
        modulus,
        &ntt,
        &mut automorphism_workspace,
    );
    let automated = automated.into_ntt_form(&ntt);
    let expected_automorphism = automorphism_plaintext(&message, 3);
    assert_eq!(
        secret
            .decrypt_message(&automated, &glwe_parameters, &ntt)
            .as_ref(),
        expected_automorphism
    );

    let mut automated_ntt: NttGlwe<Vec<u64>> = NttGlwe::zero(glwe_parameters.glwe_len());
    // Coefficient evaluation above uses owned containers; transformed evaluation
    // borrows views of the same buffers through the public entry point.
    automorphism_key.apply_ntt_to(
        &encrypted.as_view(),
        &mut automated_ntt.as_mut_view(),
        modulus,
        &ntt,
        &mut automorphism_workspace,
    );
    assert_eq!(automated_ntt.as_ref(), automated.as_ref());

    // Layout validation includes a different N with the same total GLWE length.
    for size in [
        GlweSize::new(GlweDimension::new(5), PolyLength::new(POLY_LENGTH / 2)),
        GlweSize::new(GlweDimension::new(3), PolyLength::new(POLY_LENGTH)),
    ] {
        let mut workspace = NttGlweAutomorphismWorkspace::new(size);
        let mut output = Glwe::new(vec![7; glwe_parameters.glwe_len()]);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                automorphism_key.apply_to(
                    &coefficient_encrypted,
                    &mut output,
                    modulus,
                    &ntt,
                    &mut workspace,
                );
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 7));
    }
}

fn fourier_automorphism_input<Table: FftTable>() {
    use primus_fft::Complex64;
    use primus_lattice::glwe::FourierGlwe;
    let table = Table::new(PolyLength::new(N));
    let mut fft = FftEngine::new(&table);
    let size = GlweSize::new(GlweDimension::new(K), PolyLength::new(N));
    let params = GlweParameters::new(
        GlweDimension::new(K),
        PolyLength::new(N),
        64,
        NativeModulus::new(),
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
    let mut rng = StdRng::seed_from_u64(0x4646544155544f);
    let mut gadget = FourierGlweGadgetEncryptWorkspace::new(glev.size());
    let mut workspace = FourierGlweAutomorphismWorkspace::new(size);
    let q = 1u128 << 64;
    let m = message(q);
    let input = encrypt(&m, &s, q, &mut rng);
    let mut fourier_input = FourierGlwe::<Vec<Complex64>>::zero(size.fourier_glwe_len());
    input.write_fourier_form(&mut fourier_input, &mut fft);
    let mut fourier_output = fourier_input.clone();
    let mut output = Glwe::new(vec![0; size.glwe_len()]);
    for degree in [1, 3, N + 1, 2 * N - 1] {
        let key = FourierGlweAutomorphismKey::generate(
            degree,
            &coeff,
            &sk,
            &glev,
            &mut fft,
            &mut rng,
            &mut gadget,
        );
        let mut expected = vec![0; N];
        for (i, &value) in m.iter().enumerate() {
            let dest = i * degree % (2 * N);
            expected[dest % N] = if dest < N {
                value
            } else {
                value.wrapping_neg()
            };
        }
        key.apply_to(&input, &mut output, &mut fft, &mut workspace);
        assert_phase(output.as_ref(), &expected, &s, q);
        key.apply_fourier_to(
            &fourier_input.as_view(),
            &mut fourier_output.as_mut_view(),
            &mut fft,
            &mut workspace,
        );
        fourier_output.write_torus_form(&mut output, &mut fft);
        assert_phase(output.as_ref(), &expected, &s, q);
        // A different N with the same total storage must fail before output writes.
        let mut wrong_workspace = FourierGlweAutomorphismWorkspace::new(GlweSize::new(
            GlweDimension::new(5),
            PolyLength::new(N * 2),
        ));
        fourier_output.as_mut().fill(Complex64::new(7.0, 0.0));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                key.apply_fourier_to(
                    &fourier_input,
                    &mut fourier_output,
                    &mut fft,
                    &mut wrong_workspace,
                );
            }))
            .is_err()
        );
        assert!(
            fourier_output
                .as_ref()
                .iter()
                .all(|&v| v == Complex64::new(7.0, 0.0))
        );
    }
}

#[test]
fn fourier_and_coefficient_inputs_reuse_the_automorphism_key() {
    fourier_automorphism_input::<RustFftTable>();
    fourier_automorphism_input::<primus_fft::TfheFftTable>();
}
