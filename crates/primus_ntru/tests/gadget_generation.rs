//! NLev/NGSW gadget encryption checked through row phases and encrypted selection.

use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_encoding::PlaintextEmbedding;
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};
use primus_lattice::{
    ngsw::{FourierNgswIter, NttNgswIter},
    ntru::{FourierNtruOwned, Ntru, NttNtru},
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNgswCiphertext, FourierNlevCiphertext, FourierNtruDecryptWorkspace,
    FourierNtruEncryptWorkspace, FourierNtruExternalProductWorkspace,
    FourierNtruGadgetEncryptWorkspace, FourierNtruSecretKey, NlevParameters, NtruParameters,
    NttNgswCiphertext, NttNlevCiphertext, NttNtruExternalProductWorkspace,
    NttNtruGadgetEncryptWorkspace, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::{Polynomial, PolynomialOwned};
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

// Functional ring size; keep the original word widths, moduli and decomposition.
const POLY_LENGTH: usize = 32;
const PLAINTEXT_MODULUS: u32 = 16;
const EXPLICIT_MODULUS: u32 = 132_120_577;

fn plaintext(offset: u32) -> Vec<u32> {
    (0..POLY_LENGTH)
        .map(|index| (index as u32 + offset) % (PLAINTEXT_MODULUS / 2))
        .collect()
}

fn shifted_plaintext(input: &[u32]) -> Vec<u32> {
    let mut output = vec![0; input.len()];
    output[0] = (PLAINTEXT_MODULUS - input[input.len() - 1]) % PLAINTEXT_MODULUS;
    output[1..].copy_from_slice(&input[..input.len() - 1]);
    output
}

fn explicit_distance(lhs: u32, rhs: u32) -> u32 {
    let distance = lhs.abs_diff(rhs);
    distance.min(EXPLICIT_MODULUS - distance)
}

fn native_distance(lhs: u32, rhs: u32) -> u32 {
    lhs.wrapping_sub(rhs).min(rhs.wrapping_sub(lhs))
}

fn decrypt_ntt_output(
    secret_key: &NttNtruSecretKey<u32>,
    cipher: &Ntru<Vec<u32>>,
    params: &NtruParameters<u32, BarrettModulus<u32>>,
    ntt: &UintNttTable<u32>,
) -> Vec<u32> {
    let mut transformed: NttNtru<Vec<u32>> = NttNtru::zero(POLY_LENGTH);
    cipher.write_ntt_form(&mut transformed, ntt);
    secret_key
        .decrypt_message(&transformed, params, ntt)
        .as_ref()
        .to_vec()
}

fn decrypt_fourier_output(
    secret_key: &FourierNtruSecretKey,
    cipher: &Ntru<Vec<u32>>,
    params: &NtruParameters<u32, NativeModulus<u32>>,
    fft: &mut FftEngine<'_, RustFftTable>,
    workspace: &mut FourierNtruDecryptWorkspace,
) -> Vec<u32> {
    let mut transformed = FourierNtruOwned::zero(fft.fourier_length());
    cipher.write_fourier_form(&mut transformed, fft);
    secret_key
        .decrypt_message(&transformed, params, fft, workspace)
        .as_ref()
        .to_vec()
}

#[test]
fn ntt_nlev_generation_and_ngsw_cmux() {
    let modulus = BarrettModulus::new(EXPLICIT_MODULUS);
    let ntt = UintNttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let params = NtruParameters::new(
        PolyLength::new(POLY_LENGTH),
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget_params = NlevParameters::with_ntru_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(9),
            level_count: None,
        },
    );
    let basis = gadget_params.basis();
    let mut rng = StdRng::seed_from_u64(42);
    let secret_key =
        NttNtruSecretKey::generate(params.encryption_parameters(), &ntt, &mut rng).unwrap();
    let mut gadget_workspace = NttNtruGadgetEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));

    let mut nlev: NttNlevCiphertext<Vec<u32>> = NttNlevCiphertext::zero(gadget_params.nlev_len());
    secret_key.encrypt_nlev_constant_to(
        1,
        &mut nlev,
        &gadget_params,
        &ntt,
        &mut rng,
        &mut gadget_workspace,
    );

    for (scalar, level) in basis.scalar_iter().zip(nlev.iter_ntt_ntru(POLY_LENGTH)) {
        let mut phase = PolynomialOwned::zero(POLY_LENGTH);
        secret_key.decrypt_phase_to(&level, &mut phase, modulus, &ntt);
        assert!(explicit_distance(phase.as_ref()[0], scalar) <= 8);
        assert!(
            phase.as_ref()[1..]
                .iter()
                .all(|&value| explicit_distance(value, 0) <= 8)
        );
    }

    let mut control: NttNgswCiphertext<Vec<u32>> =
        NttNgswCiphertext::zero(gadget_params.nlev_len());
    secret_key.encrypt_ngsw_signed_constant_batch_to(
        &[1],
        control.as_mut(),
        &gadget_params,
        &ntt,
        &mut rng,
    );

    let messages = [plaintext(0), plaintext(2), plaintext(5)];
    let candidates: Vec<Ntru<Vec<u32>>> = messages
        .iter()
        .map(|message| {
            secret_key
                .encrypt_message(
                    &Polynomial::new(message.as_slice()),
                    &params,
                    PlaintextEmbedding::Unsigned,
                    &ntt,
                    &mut rng,
                )
                .into_coeff_form(&ntt)
        })
        .collect();
    let mut output: Ntru<Vec<u32>> = Ntru::zero(POLY_LENGTH);
    let mut external_product_workspace =
        NttNtruExternalProductWorkspace::new(PolyLength::new(POLY_LENGTH));

    control.cmux_to(
        &candidates[0],
        &candidates[1],
        &mut output,
        basis,
        modulus,
        &ntt,
        &mut external_product_workspace,
    );
    assert_eq!(
        decrypt_ntt_output(&secret_key, &output, &params, &ntt),
        messages[1]
    );

    control.cmux_monomial_to(
        &candidates[0],
        1,
        &mut output,
        basis,
        modulus,
        &ntt,
        &mut external_product_workspace,
    );
    assert_eq!(
        decrypt_ntt_output(&secret_key, &output, &params, &ntt),
        shifted_plaintext(&messages[0])
    );

    let mut controls = vec![0; 2 * gadget_params.nlev_len()];
    for (selected, expected) in messages.iter().enumerate() {
        let selectors = [i32::from(selected == 1), i32::from(selected == 2)];
        secret_key.encrypt_ngsw_signed_constant_batch_to(
            &selectors,
            &mut controls,
            &gadget_params,
            &ntt,
            &mut rng,
        );

        // Reference: separately invert each product, always subtracting the
        // original default. Real encryptions of zero still contribute noise.
        let mut reference = candidates[0].clone();
        let mut difference = Ntru::<Vec<u32>>::zero(POLY_LENGTH);
        let mut product = Ntru::<Vec<u32>>::zero(POLY_LENGTH);
        for (selector, candidate) in
            NttNgswIter::new(&controls, gadget_params.nlev_len()).zip(&candidates[1..])
        {
            candidate.sub_to(&candidates[0], &mut difference, modulus);
            selector.external_product_to(
                &difference,
                &mut product,
                basis,
                modulus,
                &ntt,
                &mut external_product_workspace,
            );
            reference.add_assign(&product, modulus);
        }

        NttNgswCiphertext::cmux_k_to(
            NttNgswIter::new(&controls, gadget_params.nlev_len()),
            candidates[0].as_view(),
            &candidates[1..],
            output.as_mut_view(),
            basis,
            modulus,
            &ntt,
            &mut external_product_workspace,
        );
        assert_eq!(output.as_ref(), reference.as_ref());
        assert_eq!(
            decrypt_ntt_output(&secret_key, &output, &params, &ntt),
            *expected
        );
    }
}

#[test]
fn fourier_nlev_generation_and_ngsw_cmux() {
    let table = RustFftTable::new(PolyLength::new(POLY_LENGTH));
    let mut fft = FftEngine::new(&table);
    let params = NtruParameters::new(
        PolyLength::new(POLY_LENGTH),
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget_params = NlevParameters::with_ntru_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        },
    );
    let basis = gadget_params.basis();
    let mut rng = StdRng::seed_from_u64(42);
    let secret_key =
        FourierNtruSecretKey::generate(params.encryption_parameters(), &mut fft, &mut rng).unwrap();
    let mut gadget_workspace = FourierNtruGadgetEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    let mut decrypt_workspace = FourierNtruDecryptWorkspace::new(PolyLength::new(POLY_LENGTH));

    let mut nlev: FourierNlevCiphertext<Vec<Complex64>> =
        FourierNlevCiphertext::zero(gadget_params.fourier_nlev_len());
    secret_key.encrypt_nlev_constant_to(
        1,
        &mut nlev,
        &gadget_params,
        &mut fft,
        &mut rng,
        &mut gadget_workspace,
    );

    for (scalar, level) in basis
        .scalar_iter()
        .zip(nlev.iter_ntru(fft.fourier_length()))
    {
        let mut phase = PolynomialOwned::zero(POLY_LENGTH);
        secret_key.decrypt_phase_to(&level, &mut phase, &mut fft, &mut decrypt_workspace);
        assert!(native_distance(phase.as_ref()[0], scalar) <= 8);
        assert!(
            phase.as_ref()[1..]
                .iter()
                .all(|&value| native_distance(value, 0) <= 8)
        );
    }

    let mut control: FourierNgswCiphertext<Vec<Complex64>> =
        FourierNgswCiphertext::zero(gadget_params.fourier_nlev_len());
    secret_key.encrypt_ngsw_signed_constant_batch_to(
        &[1],
        control.as_mut(),
        &gadget_params,
        &mut fft,
        &mut rng,
        &mut gadget_workspace,
    );

    let messages = [plaintext(0), plaintext(2), plaintext(5)];
    let mut encrypt_workspace = FourierNtruEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    let mut candidates = Vec::with_capacity(messages.len());
    for message in &messages {
        let input_fourier = secret_key.encrypt_message(
            &Polynomial::new(message.as_slice()),
            &params,
            PlaintextEmbedding::Unsigned,
            &mut fft,
            &mut rng,
            &mut encrypt_workspace,
        );
        let mut input: Ntru<Vec<u32>> = Ntru::zero(POLY_LENGTH);
        input_fourier.write_torus_form(&mut input, &mut fft);
        candidates.push(input);
    }
    let mut output: Ntru<Vec<u32>> = Ntru::zero(POLY_LENGTH);
    let mut external_product_workspace =
        FourierNtruExternalProductWorkspace::new(PolyLength::new(POLY_LENGTH));

    control.cmux_to(
        &candidates[0],
        &candidates[1],
        &mut output,
        basis,
        &mut fft,
        &mut external_product_workspace,
    );
    assert_eq!(
        decrypt_fourier_output(
            &secret_key,
            &output,
            &params,
            &mut fft,
            &mut decrypt_workspace,
        ),
        messages[1]
    );

    control.cmux_monomial_to(
        &candidates[0],
        1,
        &mut output,
        basis,
        &mut fft,
        &mut external_product_workspace,
    );
    assert_eq!(
        decrypt_fourier_output(
            &secret_key,
            &output,
            &params,
            &mut fft,
            &mut decrypt_workspace,
        ),
        shifted_plaintext(&messages[0])
    );

    let mut controls = vec![Complex64::default(); 2 * gadget_params.fourier_nlev_len()];
    for (selected, expected) in messages.iter().enumerate() {
        let selectors = [i32::from(selected == 1), i32::from(selected == 2)];
        secret_key.encrypt_ngsw_signed_constant_batch_to(
            &selectors,
            &mut controls,
            &gadget_params,
            &mut fft,
            &mut rng,
            &mut gadget_workspace,
        );

        // Reference: separately invert each product, always subtracting the
        // original default. Real encryptions of zero still contribute noise.
        let mut reference = candidates[0].clone();
        let mut difference = Ntru::<Vec<u32>>::zero(POLY_LENGTH);
        let mut product = Ntru::<Vec<u32>>::zero(POLY_LENGTH);
        for (selector, candidate) in
            FourierNgswIter::new(&controls, gadget_params.fourier_nlev_len()).zip(&candidates[1..])
        {
            candidate.sub_to(&candidates[0], &mut difference, NativeModulus::new());
            selector.external_product_to(
                &difference,
                &mut product,
                basis,
                &mut fft,
                &mut external_product_workspace,
            );
            reference.add_assign(&product, NativeModulus::new());
        }

        FourierNgswCiphertext::cmux_k_to(
            FourierNgswIter::new(&controls, gadget_params.fourier_nlev_len()),
            candidates[0].as_view(),
            &candidates[1..],
            output.as_mut_view(),
            basis,
            &mut fft,
            &mut external_product_workspace,
        );
        // u32 ciphertext coefficients differ by at most a few rounding units; checks
        // below independently verify selection rather than ciphertext equality.
        for (&actual, &expected) in output.as_ref().iter().zip(reference.as_ref()) {
            assert!(native_distance(actual, expected) <= 4);
        }
        assert_eq!(
            decrypt_fourier_output(
                &secret_key,
                &output,
                &params,
                &mut fft,
                &mut decrypt_workspace,
            ),
            *expected
        );
    }
}
