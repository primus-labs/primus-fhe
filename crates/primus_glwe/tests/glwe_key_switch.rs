//! Switch between independent keys, including a change in GLWE mask count.

use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_encoding::PlaintextEmbedding;
use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGlweDecryptWorkspace, FourierGlweEncryptWorkspace, FourierGlweGadgetEncryptWorkspace,
    FourierGlweKeySwitchingKey, FourierGlweKeySwitchingWorkspace, FourierGlweSecretKey,
    GlevParameters, GlweKeySwitchingParameters, GlweParameters, GlweSecretKey,
    NttGlweGadgetEncryptWorkspace, NttGlweKeySwitchingKey, NttGlweKeySwitchingWorkspace,
    NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_lattice::glwe::{FourierGlweOwned, Glwe, NttGlwe};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

const INPUT_DIMENSION: usize = 2;
// Functional ring size; keep the original word widths, moduli and decomposition.
const POLY_LENGTH: usize = 32;
const PLAINTEXT_MODULUS: u32 = 16;

fn plaintext() -> Vec<u32> {
    (0..POLY_LENGTH)
        .map(|index| (index as u32 * 7 + 3) % PLAINTEXT_MODULUS)
        .collect()
}

#[test]
fn ntt_glwe_key_switches_for_equal_and_smaller_output_dimensions() {
    const MODULUS: u32 = 132_120_577;

    let modulus = BarrettModulus::new(MODULUS);
    let ntt = UintNttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let input_params = GlweParameters::new(
        GlweDimension::new(INPUT_DIMENSION),
        PolyLength::new(POLY_LENGTH),
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let (input_coeff_key, input_key) = NttGlweSecretKey::generate_pair(
        input_params.size(),
        input_params.encryption_parameters(),
        &ntt,
        &mut rng,
    );
    let message_values = plaintext();
    let message = Polynomial::new(message_values.clone());
    let mut encrypted: NttGlwe<Vec<u32>> = NttGlwe::zero(input_params.glwe_len());
    input_key.encrypt_message_to(
        &message,
        &mut encrypted,
        &input_params,
        PlaintextEmbedding::Unsigned,
        &ntt,
        &mut rng,
    );
    let input = encrypted.into_coeff_form(&ntt);

    for output_dimension in [INPUT_DIMENSION, 1] {
        let output_params = GlweParameters::new(
            GlweDimension::new(output_dimension),
            PolyLength::new(POLY_LENGTH),
            PLAINTEXT_MODULUS,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let generated_output_key = GlweSecretKey::generate(
            output_params.size(),
            output_params.secret_key_sampler(),
            &mut rng,
        );
        let output_coeff_key = if output_dimension == 1 {
            // The target key has an active LWE-key prefix followed by zeros,
            // as used by the KeyswitchBootstrap pipeline.
            let active_key_len = POLY_LENGTH - 13;
            let mut padded = vec![0; POLY_LENGTH];
            padded[..active_key_len]
                .copy_from_slice(&generated_output_key.as_slice()[..active_key_len]);
            GlweSecretKey::new(padded, output_params.size(), SecretKeyDistr::UniformBinary)
        } else {
            generated_output_key
        };
        let output_key = NttGlweSecretKey::from_coeff_secret_key(&output_coeff_key, &ntt);
        let glev = GlevParameters::with_glwe_params(
            &output_params,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
        );
        let parameters = GlweKeySwitchingParameters::new(GlweDimension::new(INPUT_DIMENSION), glev);
        let mut encrypt_workspace = NttGlweGadgetEncryptWorkspace::new(parameters.output().size());
        let key = NttGlweKeySwitchingKey::generate(
            &input_coeff_key,
            &output_key,
            &parameters,
            &ntt,
            &mut rng,
            &mut encrypt_workspace,
        );

        let mut workspace =
            NttGlweKeySwitchingWorkspace::new(parameters.output().size().glwe_size());
        // Borrow a ciphertext inside a larger buffer; adjacent values must stay untouched.
        let output_len = output_params.glwe_len();
        let mut storage = vec![7; output_len + 2];
        let mut switched = Glwe::new(&mut storage[1..=output_len]);
        key.key_switch_to(
            &input.as_view(),
            &mut switched,
            modulus,
            &ntt,
            &mut workspace,
        );
        let switched_ntt = switched.into_ntt_form(&ntt);
        assert_eq!(
            output_key
                .decrypt_message(&switched_ntt, &output_params, &ntt)
                .as_ref(),
            message_values
        );
        assert_eq!((storage[0], storage[output_len + 1]), (7, 7));
    }
}

#[test]
fn fourier_glwe_key_switches_for_equal_and_smaller_output_dimensions() {
    let table = RustFftTable::new(PolyLength::new(POLY_LENGTH));
    let mut fft = FftEngine::new(&table);
    let mut rng = StdRng::seed_from_u64(42);
    let input_params = GlweParameters::new(
        GlweDimension::new(INPUT_DIMENSION),
        PolyLength::new(POLY_LENGTH),
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let (input_coeff_key, input_key) = FourierGlweSecretKey::generate_pair(
        input_params.size(),
        input_params.encryption_parameters(),
        &mut fft,
        &mut rng,
    );
    let message_values = plaintext();
    let message = Polynomial::new(message_values.clone());
    let mut encrypted = FourierGlweOwned::zero(input_params.fourier_glwe_len());
    let mut glwe_encrypt_workspace = FourierGlweEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    input_key.encrypt_message_to(
        &message,
        &mut encrypted,
        &input_params,
        PlaintextEmbedding::Unsigned,
        &mut fft,
        &mut rng,
        &mut glwe_encrypt_workspace,
    );
    let mut input: Glwe<Vec<u32>> = Glwe::zero(input_params.glwe_len());
    encrypted.write_torus_form(&mut input, &mut fft);

    for output_dimension in [INPUT_DIMENSION, 1] {
        let output_params = GlweParameters::new(
            GlweDimension::new(output_dimension),
            PolyLength::new(POLY_LENGTH),
            PLAINTEXT_MODULUS,
            NativeModulus::new(),
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let generated_output_key = GlweSecretKey::<u32>::generate(
            output_params.size(),
            output_params.secret_key_sampler(),
            &mut rng,
        );
        let output_coeff_key = if output_dimension == 1 {
            let active_key_len = POLY_LENGTH - 13;
            let mut padded = vec![0; POLY_LENGTH];
            padded[..active_key_len]
                .copy_from_slice(&generated_output_key.as_slice()[..active_key_len]);
            GlweSecretKey::new(padded, output_params.size(), SecretKeyDistr::UniformBinary)
        } else {
            generated_output_key
        };
        let output_key = FourierGlweSecretKey::from_coeff_secret_key(&output_coeff_key, &mut fft);
        let glev = GlevParameters::with_glwe_params(
            &output_params,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
        );
        let parameters = GlweKeySwitchingParameters::new(GlweDimension::new(INPUT_DIMENSION), glev);
        let mut encrypt_workspace =
            FourierGlweGadgetEncryptWorkspace::new(parameters.output().size());
        let key = FourierGlweKeySwitchingKey::generate(
            &input_coeff_key,
            &output_key,
            &parameters,
            &mut fft,
            &mut rng,
            &mut encrypt_workspace,
        );

        let mut workspace = FourierGlweKeySwitchingWorkspace::new(parameters.output().glwe_size());
        // Use the same borrowed-output boundary as the NTT case.
        let output_len = output_params.glwe_len();
        let mut storage = vec![7; output_len + 2];
        let mut switched = Glwe::new(&mut storage[1..=output_len]);
        key.key_switch_to(&input.as_view(), &mut switched, &mut fft, &mut workspace);
        let mut switched_fourier = FourierGlweOwned::zero(output_params.fourier_glwe_len());
        switched.write_fourier_form(&mut switched_fourier, &mut fft);
        let mut decrypt_workspace = FourierGlweDecryptWorkspace::new(PolyLength::new(POLY_LENGTH));
        assert_eq!(
            output_key
                .decrypt_message(
                    &switched_fourier,
                    &output_params,
                    &mut fft,
                    &mut decrypt_workspace,
                )
                .as_ref(),
            message_values
        );
        assert_eq!((storage[0], storage[output_len + 1]), (7, 7));
    }
}
