//! Coefficient/NTT encryption equivalence, encoding paths and exact noise diagnostics.
use primus_encoding::{PlaintextEmbedding, phase_error_magnitude_slice_to};
use primus_glwe::{
    GlweCiphertext, GlweParameters, GlweSecretKey, NttGlweCiphertext, NttGlweSecretKey,
    SecretKeyDistr,
};
use primus_integer::FheUint;
use primus_lattice::GlweDimension;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::{Polynomial, PolynomialOwned};
use primus_reduce::ReduceAdd;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};
use zeroize::Zeroizing;

const DIMENSION: usize = 2;
// Functional ring size; keep the original word widths, moduli and decomposition.
const POLY_LENGTH: usize = 32;
const PLAIN_MODULUS: usize = 16;

fn assert_roundtrip<T>(cipher_modulus: T)
where
    T: FheUint,
{
    let modulus = BarrettModulus::new(cipher_modulus);
    let ntt = UintNttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let messages: Vec<T> = (0..POLY_LENGTH)
        .map(|index| T::try_from(index % PLAIN_MODULUS).unwrap())
        .collect();
    let message = Polynomial::new(messages.clone());

    for secret_key_distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::gaussian(3.2),
        // A weight greater than N must be sampled over all k*N coefficients.
        SecretKeyDistr::fixed_hamming_weight_ternary(DIMENSION * POLY_LENGTH, POLY_LENGTH + 7),
    ] {
        let params = GlweParameters::new(
            GlweDimension::new(DIMENSION),
            PolyLength::new(POLY_LENGTH),
            T::try_from(PLAIN_MODULUS).unwrap(),
            modulus,
            secret_key_distr,
            0.7,
        );
        // Splitting layout from sampling state must preserve all k*N samples
        // and the RNG stream before transformation.
        let seed = rng.next_u64();
        rng = StdRng::seed_from_u64(seed);
        let mut expected_rng = StdRng::seed_from_u64(seed);
        let expected_coefficients = GlweSecretKey::generate(
            params.size(),
            params.secret_key_sampler(),
            &mut expected_rng,
        );
        let (coefficients, secret_key) = NttGlweSecretKey::generate_pair(
            params.size(),
            params.encryption_parameters(),
            &ntt,
            &mut rng,
        );
        assert_eq!(coefficients.as_slice(), expected_coefficients.as_slice());
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
        assert_eq!(secret_key.cipher_modulus(), cipher_modulus);
        let mut cipher = NttGlweCiphertext::<Vec<T>>::zero(params.glwe_len());
        let mut coefficients = GlweCiphertext::<Vec<T>>::zero(params.glwe_len());
        let mut expected_coefficients = GlweCiphertext::<Vec<T>>::zero(params.glwe_len());
        let mut phase = PolynomialOwned::zero(POLY_LENGTH);
        let mut expected_phase = PolynomialOwned::zero(POLY_LENGTH);
        let mut scratch = Zeroizing::new(vec![T::MAX; POLY_LENGTH]);
        let mut direct_rng = StdRng::seed_from_u64(17);
        let mut reference_rng = StdRng::seed_from_u64(17);
        // Exact ciphertext/phase equality also checks noise and mask sampling order.
        // Reuse dirty output and scratch for a zero message after a nonzero one.
        for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
            for input in [&message, &PolynomialOwned::zero(POLY_LENGTH)] {
                secret_key.encrypt_message_to(
                    input,
                    &mut cipher,
                    &params,
                    embedding,
                    &ntt,
                    &mut reference_rng,
                );
                cipher.write_coeff_form(&mut expected_coefficients, &ntt);
                secret_key.encrypt_message_coeff_to(
                    input,
                    &mut coefficients,
                    &params,
                    embedding,
                    &ntt,
                    &mut direct_rng,
                    &mut scratch,
                );
                assert_eq!(coefficients.as_ref(), expected_coefficients.as_ref());
                secret_key.decrypt_phase_to(&cipher, &mut expected_phase, modulus, &ntt);
                secret_key.decrypt_phase_coeff_to(
                    &coefficients,
                    &mut phase,
                    modulus,
                    &ntt,
                    &mut scratch,
                );
                assert_eq!(phase.as_ref(), expected_phase.as_ref());
                secret_key.decrypt_message_coeff_to(
                    &coefficients,
                    &mut phase,
                    &params,
                    &ntt,
                    &mut scratch,
                );
                assert_eq!(phase.as_ref(), input.as_ref());
            }
        }
        assert_eq!(direct_rng.next_u64(), reference_rng.next_u64());

        secret_key.encrypt_zeros_to(&mut cipher, params.encryption_parameters(), &ntt, &mut rng);
        assert_eq!(
            secret_key.decrypt_message(&cipher, &params, &ntt).as_ref(),
            vec![T::ZERO; POLY_LENGTH]
        );

        for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
            let mut encoded = vec![T::ZERO; POLY_LENGTH];
            params
                .plaintext_codec()
                .add_encode_slice_assign(&mut encoded, &messages, embedding);
            // Raw encoded encryption must equal ordinary encryption with the same
            // coins; this also checks that the codec is applied exactly once.
            let seed = rng.next_u64();
            rng = StdRng::seed_from_u64(seed);
            let mut expected_rng = StdRng::seed_from_u64(seed);
            let expected =
                secret_key.encrypt_message(&message, &params, embedding, &ntt, &mut expected_rng);
            secret_key.encrypt_encoded_to(
                &Polynomial::new(encoded),
                &mut cipher,
                params.encryption_parameters(),
                &ntt,
                &mut rng,
            );
            assert_eq!(cipher.as_ref(), expected.as_ref());
            assert_eq!(rng.next_u64(), expected_rng.next_u64());

            let mut reused_output = PolynomialOwned::new(vec![T::MAX; POLY_LENGTH]);
            secret_key.decrypt_message_to(&cipher, &mut reused_output, &params, &ntt);
            assert_eq!(reused_output.as_ref(), messages);
        }
    }
}

#[test]
fn ntt_glwe_secret_key_roundtrip_u32() {
    assert_roundtrip(132_120_577u32);
}

#[test]
fn ntt_glwe_secret_key_roundtrip_u64() {
    assert_roundtrip(1_125_899_906_826_241u64);
}

#[test]
fn phase_error_uses_the_expected_message_embedding() {
    let modulus = BarrettModulus::new(1_125_899_906_826_241u64);
    let params = GlweParameters::new(
        GlweDimension::new(DIMENSION),
        PolyLength::new(POLY_LENGTH),
        PLAIN_MODULUS as u64,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let table = UintNttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let secret_key = NttGlweSecretKey::new(
        vec![0; params.size().mask_len()],
        params.size(),
        SecretKeyDistr::UniformBinary,
        modulus,
    );
    let message: Vec<u64> = (0..POLY_LENGTH)
        .map(|i| (i % PLAIN_MODULUS) as u64)
        .collect();
    let step = params
        .plaintext_codec()
        .encode_value(1, PlaintextEmbedding::Unsigned);
    let mut expected_noise: Vec<u64> = (0..POLY_LENGTH).map(|i| [0, 3, 5][i % 3]).collect();
    expected_noise[0] = step;
    let mut expected_decoded = message.clone();
    expected_decoded[0] = 1; // The original message at this coefficient was zero.
    let mut reference = vec![0; POLY_LENGTH];
    let mut phase = PolynomialOwned::zero(POLY_LENGTH);
    let mut noise = vec![0; POLY_LENGTH];
    let mut ciphertext = NttGlweCiphertext::<Vec<u64>>::zero(params.glwe_len());
    for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
        // A zero mask lets us specify exact positive/negative phase errors.
        let (_, body) = ciphertext.a_b_mut_slices(POLY_LENGTH);
        params
            .plaintext_codec()
            .encode_slice_to(&message, &mut reference, embedding);
        body.copy_from_slice(&reference);
        for (index, value) in body.iter_mut().enumerate() {
            let error = [0, 3, 1_125_899_906_826_241 - 5][index % 3];
            *value = modulus.reduce_add(*value, error);
        }
        body[0] = modulus.reduce_add(body[0], step);
        table.transform_slice(body);
        secret_key.decrypt_phase_to(&ciphertext, &mut phase, modulus, &table);
        phase_error_magnitude_slice_to(phase.as_ref(), &reference, &mut noise, modulus);
        assert_eq!(noise, expected_noise);
        // Wrong decoding must not erase the error against the original message.
        params.plaintext_codec().decode_slice_assign(phase.as_mut());
        assert_eq!(phase.as_ref(), expected_decoded);
    }
}
