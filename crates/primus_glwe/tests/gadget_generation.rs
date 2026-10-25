//! Encrypted GLev/GGSW rows and their external-product semantics.

use primus_decompose::{DecompositionBaseLog, primitive::ApproxSignedBasis};
use primus_encoding::PlaintextEmbedding;
use primus_encoding::ScaledCodec;
use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGlweDecryptWorkspace, FourierGlweEncryptWorkspace, FourierGlweGadgetEncryptWorkspace,
    FourierGlweSecretKey, GlevParameters, GlweEncryptionParameters, GlweParameters, GlweSecretKey,
    GlweSize, NttGlweGadgetEncryptWorkspace, NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_lattice::{
    ggsw::{FourierGgswOwned, NttGgsw},
    glev::{FourierGlevOwned, NttGlev},
    glwe::{FourierGlweOwned, Glwe, NttGlwe, TorusGlwe},
    workspace::{FourierGlweExternalProductWorkspace, NttGlweExternalProductWorkspace},
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::{Polynomial, PolynomialOwned};
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

const DIMENSION: usize = 2;
// Functional ring size; keep the original word widths, moduli and decomposition.
const POLY_LENGTH: usize = 32;

// Independent integer oracle for g_l * m (body row) or -g_l * m * s_r
// (mask row) in Z_q[X]/(X^N + 1). Test sizes and coefficients fit in i128.
fn expected_ggsw_phase(message: &[u32], secret: Option<&[i32]>, scalar: u32, q: u64) -> Vec<u32> {
    let mut phase: Vec<i128> = message.iter().map(|&value| i128::from(value)).collect();
    if let Some(secret) = secret {
        phase.fill(0);
        for (i, &m) in message.iter().enumerate() {
            for (j, &s) in secret.iter().enumerate() {
                let product = i128::from(m) * i128::from(s);
                if i + j < message.len() {
                    phase[i + j] -= product;
                } else {
                    phase[i + j - message.len()] += product;
                }
            }
        }
    }
    phase
        .into_iter()
        .map(|value| (value * i128::from(scalar)).rem_euclid(i128::from(q)) as u32)
        .collect()
}

fn native_distance(lhs: u32, rhs: u32) -> u32 {
    lhs.wrapping_sub(rhs).min(rhs.wrapping_sub(lhs))
}

fn explicit_distance(lhs: u32, rhs: u32, modulus: u32) -> u32 {
    let distance = lhs.abs_diff(rhs);
    distance.min(modulus - distance)
}

#[test]
fn fourier_gadget_phases_and_external_product() {
    let table = RustFftTable::new(PolyLength::new(POLY_LENGTH));
    let mut fft = FftEngine::new(&table);
    let mut rng = StdRng::seed_from_u64(42);
    // Gadget encryption and key generation need no ordinary message codec.
    let size = GlweSize::new(GlweDimension::new(DIMENSION), PolyLength::new(POLY_LENGTH));
    let inner = Arc::new(GlweEncryptionParameters::new(
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    ));
    let basis = ApproxSignedBasis::new(None, DecompositionBaseLog::new(8), None);
    let params = GlevParameters::try_from_parts(size, Arc::clone(&inner), basis).unwrap();
    let coeff_secret_key =
        GlweSecretKey::<u32>::generate(size, inner.secret_key_sampler(), &mut rng);
    let secret_key = FourierGlweSecretKey::from_coeff_secret_key(&coeff_secret_key, &mut fft);
    let mut gadget_workspace = FourierGlweGadgetEncryptWorkspace::new(params.size());
    let mut decrypt_workspace = FourierGlweDecryptWorkspace::new(PolyLength::new(POLY_LENGTH));

    let mut raw_message = vec![0u32; POLY_LENGTH];
    raw_message[0] = 1;
    let raw_message = Polynomial::new(raw_message);
    let mut glev = FourierGlevOwned::zero(params.fourier_glev_len());
    secret_key.encrypt_glev_to(
        &raw_message.as_view(),
        &mut glev.as_mut_view(),
        &params,
        &mut fft,
        &mut rng,
        &mut gadget_workspace,
    );

    for (scalar, glwe) in params
        .basis()
        .scalar_iter()
        .zip(glev.iter_glwe(params.fourier_glwe_len()))
    {
        let mut phase = PolynomialOwned::zero(POLY_LENGTH);
        secret_key.decrypt_phase_to(&glwe, &mut phase, &mut fft, &mut decrypt_workspace);
        assert!(native_distance(phase.as_ref()[0], scalar) <= 8);
        assert!(
            phase.as_ref()[1..]
                .iter()
                .all(|&value| native_distance(value, 0) <= 8)
        );
    }

    let mut ggsw = FourierGgswOwned::zero(params.fourier_ggsw_len());
    let ring_message = Polynomial::new(
        (0..POLY_LENGTH)
            .map(|i| (i as u32).wrapping_mul(0x9e37_79b9))
            .collect::<Vec<_>>(),
    );
    secret_key.encrypt_ggsw_to(
        &ring_message.as_view(),
        &mut ggsw.as_mut_view(),
        &params,
        &mut fft,
        &mut rng,
        &mut gadget_workspace,
    );
    for (row, glev) in ggsw.iter_glev(params.fourier_glev_len()).enumerate() {
        for (scalar, glwe) in params
            .basis()
            .scalar_iter()
            .zip(glev.iter_glwe(params.fourier_glwe_len()))
        {
            let mut phase = PolynomialOwned::zero(POLY_LENGTH);
            secret_key.decrypt_phase_to(&glwe, &mut phase, &mut fft, &mut decrypt_workspace);
            let expected = expected_ggsw_phase(
                ring_message.as_ref(),
                coeff_secret_key.iter().nth(row),
                scalar,
                1u64 << 32,
            );
            assert!(
                phase
                    .iter()
                    .zip(expected)
                    .all(|(&actual, expected)| native_distance(actual, expected) <= 8),
                "GGSW row {row}, scalar {scalar}"
            );
        }
    }

    let plaintext_values: Vec<u32> = (0..POLY_LENGTH).map(|index| (index % 16) as u32).collect();
    let plaintext = Polynomial::new(plaintext_values.clone());

    let mut monomial_message = vec![0u32; POLY_LENGTH];
    monomial_message[1] = 1;
    secret_key.encrypt_ggsw_to(
        &Polynomial::new(monomial_message),
        &mut ggsw,
        &params,
        &mut fft,
        &mut rng,
        &mut gadget_workspace,
    );

    let mut input_fourier = FourierGlweOwned::zero(params.fourier_glwe_len());
    let mut glwe_workspace = FourierGlweEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    // Only the ordinary ciphertext in the external product needs t = 16.
    let glwe_params =
        GlweParameters::try_from_parts(size, inner, ScaledCodec::new(16u32, NativeModulus::new()))
            .unwrap();
    secret_key.encrypt_message_to(
        &plaintext,
        &mut input_fourier,
        &glwe_params,
        PlaintextEmbedding::Unsigned,
        &mut fft,
        &mut rng,
        &mut glwe_workspace,
    );
    let mut input: TorusGlwe<Vec<u32>> = TorusGlwe::zero(params.glwe_len());
    input_fourier.write_torus_form(&mut input, &mut fft);

    let mut output: TorusGlwe<Vec<u32>> = TorusGlwe::zero(params.glwe_len());
    let mut external_product_workspace = FourierGlweExternalProductWorkspace::new(params.size());
    ggsw.external_product_to(
        &input,
        &mut output,
        params.basis(),
        &mut fft,
        &mut external_product_workspace,
    );

    let mut output_fourier = FourierGlweOwned::zero(params.fourier_glwe_len());
    output.write_fourier_form(&mut output_fourier, &mut fft);
    let mut expected = vec![0u32; POLY_LENGTH];
    expected[0] = (16 - plaintext_values[POLY_LENGTH - 1]) % 16;
    expected[1..].copy_from_slice(&plaintext_values[..POLY_LENGTH - 1]);
    assert_eq!(
        secret_key
            .decrypt_message(
                &output_fourier,
                &glwe_params,
                &mut fft,
                &mut decrypt_workspace,
            )
            .as_ref(),
        expected
    );
}

#[test]
fn ntt_gadget_phases_and_external_product() {
    const MODULUS: u32 = 132_120_577;

    let modulus = BarrettModulus::new(MODULUS);
    let ntt = UintNttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    // Gadget encryption and key generation need no ordinary message codec.
    let size = GlweSize::new(GlweDimension::new(DIMENSION), PolyLength::new(POLY_LENGTH));
    let inner = Arc::new(GlweEncryptionParameters::new(
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    ));
    let basis = ApproxSignedBasis::new(Some(MODULUS), DecompositionBaseLog::new(8), None);
    let params = GlevParameters::try_from_parts(size, Arc::clone(&inner), basis).unwrap();
    let coeff_secret_key =
        GlweSecretKey::<u32>::generate(size, inner.secret_key_sampler(), &mut rng);
    let secret_key = NttGlweSecretKey::from_coeff_secret_key(&coeff_secret_key, &ntt);
    let mut workspace = NttGlweGadgetEncryptWorkspace::new(params.size());

    let mut raw_message = vec![0u32; POLY_LENGTH];
    raw_message[0] = 1;
    let raw_message = Polynomial::new(raw_message);
    let mut glev: NttGlev<Vec<u32>> = NttGlev::zero(params.glev_len());
    secret_key.encrypt_glev_to(
        &raw_message.as_view(),
        &mut glev.as_mut_view(),
        &params,
        &ntt,
        &mut rng,
        &mut workspace,
    );

    for (scalar, glwe) in params
        .basis()
        .scalar_iter()
        .zip(glev.iter_ntt_glwe(params.glwe_len()))
    {
        let mut phase = PolynomialOwned::zero(POLY_LENGTH);
        secret_key.decrypt_phase_to(&glwe, &mut phase, modulus, &ntt);
        assert!(explicit_distance(phase.as_ref()[0], scalar, MODULUS) <= 8);
        assert!(
            phase.as_ref()[1..]
                .iter()
                .all(|&value| explicit_distance(value, 0, MODULUS) <= 8)
        );
    }

    let mut ggsw: NttGgsw<Vec<u32>> = NttGgsw::zero(params.ggsw_len());
    let ring_message = Polynomial::new(
        (0..POLY_LENGTH)
            .map(|i| (i as u32).wrapping_mul(0x9e37_79b9) % MODULUS)
            .collect::<Vec<_>>(),
    );
    secret_key.encrypt_ggsw_to(
        &ring_message.as_view(),
        &mut ggsw.as_mut_view(),
        &params,
        &ntt,
        &mut rng,
        &mut workspace,
    );

    for (row, glev) in ggsw.iter_ntt_glev(params.glev_len()).enumerate() {
        for (scalar, glwe) in params
            .basis()
            .scalar_iter()
            .zip(glev.iter_ntt_glwe(params.glwe_len()))
        {
            let mut phase = PolynomialOwned::zero(POLY_LENGTH);
            secret_key.decrypt_phase_to(&glwe, &mut phase, modulus, &ntt);
            let expected = expected_ggsw_phase(
                ring_message.as_ref(),
                coeff_secret_key.iter().nth(row),
                scalar,
                u64::from(MODULUS),
            );
            assert!(
                phase
                    .as_ref()
                    .iter()
                    .zip(expected)
                    .all(|(&actual, expected)| explicit_distance(actual, expected, MODULUS) <= 8),
                "GGSW row {row}, scalar {scalar}"
            );
        }
    }

    let plaintext_values: Vec<u32> = (0..POLY_LENGTH).map(|index| (index % 16) as u32).collect();
    let plaintext = Polynomial::new(plaintext_values.clone());

    let mut monomial_message = vec![0u32; POLY_LENGTH];
    monomial_message[1] = 1;
    secret_key.encrypt_ggsw_to(
        &Polynomial::new(monomial_message),
        &mut ggsw,
        &params,
        &ntt,
        &mut rng,
        &mut workspace,
    );

    let mut input_ntt: NttGlwe<Vec<u32>> = NttGlwe::zero(params.glwe_len());
    // Only the ordinary ciphertext in the external product needs t = 16.
    let glwe_params =
        GlweParameters::try_from_parts(size, inner, ScaledCodec::new(16u32, modulus)).unwrap();
    secret_key.encrypt_message_to(
        &plaintext,
        &mut input_ntt,
        &glwe_params,
        PlaintextEmbedding::Unsigned,
        &ntt,
        &mut rng,
    );
    let input = input_ntt.into_coeff_form(&ntt);
    let mut output: Glwe<Vec<u32>> = Glwe::zero(params.glwe_len());
    let mut external_product_workspace = NttGlweExternalProductWorkspace::new(params.size());
    ggsw.external_product_to(
        &input,
        &mut output,
        params.basis(),
        modulus,
        &ntt,
        &mut external_product_workspace,
    );
    let output_ntt = output.into_ntt_form(&ntt);
    let mut expected = vec![0u32; POLY_LENGTH];
    expected[0] = (16 - plaintext_values[POLY_LENGTH - 1]) % 16;
    expected[1..].copy_from_slice(&plaintext_values[..POLY_LENGTH - 1]);
    assert_eq!(
        secret_key
            .decrypt_message(&output_ntt, &glwe_params, &ntt)
            .as_ref(),
        expected
    );
}
