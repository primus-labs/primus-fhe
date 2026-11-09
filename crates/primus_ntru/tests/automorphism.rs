//! Automorphism under the original NTRU secret in NTT and Fourier representations.

use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_encoding::PlaintextEmbedding;
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_modulus::BarrettModulus;
use primus_modulus::NativeModulus;
use primus_ntru::{
    FourierNtruAutomorphismKey, FourierNtruAutomorphismWorkspace, FourierNtruCiphertext,
    FourierNtruDecryptWorkspace, FourierNtruEncryptWorkspace, FourierNtruGadgetEncryptWorkspace,
    FourierNtruSecretKey, NlevParameters, NtruCiphertext, NtruParameters, NttNtruAutomorphismKey,
    NttNtruAutomorphismWorkspace, NttNtruCiphertext, NttNtruGadgetEncryptWorkspace,
    NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use rand::{Rng, SeedableRng, rngs::StdRng};

const N: usize = 64;
const Q: u32 = 132_120_577;
const P: u32 = 16;

fn substitute(input: &[u32], degree: usize) -> Vec<u32> {
    let mut output = vec![0; input.len()];
    for (i, &value) in input.iter().enumerate() {
        let power = i * degree;
        output[power % input.len()] = if (power / input.len()).is_multiple_of(2) {
            value
        } else {
            (P - value) % P
        };
    }
    output
}

fn fourier_automorphism<Table: FftTable>() {
    let table = Table::new(PolyLength::new(N));
    let mut fft = FftEngine::new(&table);
    let parameters = NtruParameters::new(
        PolyLength::new(N),
        P,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x6175_746f_464f_5552);
    let (secret, key) =
        FourierNtruSecretKey::generate_pair(parameters.encryption_parameters(), &mut fft, &mut rng)
            .unwrap();
    assert!(secret.as_slice().contains(&-1));
    let message: Vec<u32> = (0..N).map(|i| (3 * i as u32 + 1) % P).collect();
    let input = key.encrypt_message(
        &Polynomial(message.as_slice()),
        &parameters,
        PlaintextEmbedding::Unsigned,
        &mut fft,
        &mut rng,
        &mut FourierNtruEncryptWorkspace::new(PolyLength::new(N)),
    );
    let mut coefficients = NtruCiphertext::<Vec<u32>>::zero(N);
    input.write_torus_form(&mut coefficients, &mut fft);
    let mut generation = FourierNtruGadgetEncryptWorkspace::new(PolyLength::new(N));
    let mut workspace = FourierNtruAutomorphismWorkspace::new(PolyLength::new(N));
    let mut decrypt = FourierNtruDecryptWorkspace::new(PolyLength::new(N));
    let mut output = NtruCiphertext::new(vec![7u32; N]);
    let mut transformed_output = FourierNtruCiphertext::<Vec<Complex64>>::zero(N / 2);
    let mut transformed_coeff_output = FourierNtruCiphertext::<Vec<Complex64>>::zero(N / 2);
    for log_basis in [3, 10] {
        let gadget = NlevParameters::with_ntru_params(
            &parameters,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(log_basis),
                level_count: None,
            },
        );
        for degree in [1, 3, N + 1, 2 * N - 1] {
            let auto = FourierNtruAutomorphismKey::generate(
                degree,
                &secret,
                &key,
                &gadget,
                &mut fft,
                &mut rng,
                &mut generation,
            );
            assert_eq!(auto.degree(), degree);
            assert_eq!(auto.poly_length(), N);
            assert_eq!(auto.basis(), gadget.basis());
            auto.apply_to(&coefficients, &mut output, &mut fft, &mut workspace);
            // Exercise borrowed transformed operands alongside the owned
            // coefficient buffers, using the same key and phase oracle.
            auto.apply_fourier_to(
                &input.as_view(),
                &mut transformed_output.as_mut_view(),
                &mut fft,
                &mut workspace,
            );
            output.write_fourier_form(&mut transformed_coeff_output, &mut fft);
            // Different representative/rounding paths need not be bit-identical.
            // Both must decrypt the independently substituted target message.
            for output in [&transformed_output, &transformed_coeff_output] {
                assert_eq!(
                    key.decrypt_message(output, &parameters, &mut fft, &mut decrypt)
                        .as_ref(),
                    substitute(&message, degree),
                    "degree={degree}, log_basis={log_basis}",
                );
            }
        }
    }
}

#[test]
fn fourier_automorphism_preserves_the_original_nonbinary_secret() {
    fourier_automorphism::<RustFftTable>();
    fourier_automorphism::<TfheFftTable>();
}

#[test]
fn fourier_automorphism_rejects_incompatible_resources_before_writes() {
    // Boundary checks run before any backend work; both FFT layouts are covered above.
    let table = RustFftTable::new(PolyLength::new(N));
    let short_table = RustFftTable::new(PolyLength::new(N / 2));
    let mut fft = FftEngine::new(&table);
    let parameters = NtruParameters::new(
        PolyLength::new(N),
        P,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget = NlevParameters::with_ntru_params(
        &parameters,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(3),
            level_count: None,
        },
    );
    let mut rng = StdRng::seed_from_u64(0x6175_746f_4642_4e44);
    let (secret, key) =
        FourierNtruSecretKey::generate_pair(parameters.encryption_parameters(), &mut fft, &mut rng)
            .unwrap();
    let mut generation = FourierNtruGadgetEncryptWorkspace::new(PolyLength::new(N));
    let auto = FourierNtruAutomorphismKey::generate(
        3,
        &secret,
        &key,
        &gadget,
        &mut fft,
        &mut rng,
        &mut generation,
    );
    for (input_len, output_len, scratch_len, table) in [
        (N / 2, N, N, &table),
        (N, N / 2, N, &table),
        (N, N, N / 2, &table),
        (N, N, N, &short_table),
    ] {
        let mut fft = FftEngine::new(table);
        let input = NtruCiphertext::<Vec<u32>>::zero(input_len);
        let mut output = NtruCiphertext::new(vec![7; output_len]);
        let mut workspace = FourierNtruAutomorphismWorkspace::new(PolyLength::new(scratch_len));
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                auto.apply_to(&input, &mut output, &mut fft, &mut workspace);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 7));
        let input = FourierNtruCiphertext::<Vec<Complex64>>::zero(input_len / 2);
        let mut output = FourierNtruCiphertext::new(vec![Complex64::new(7.0, 0.0); output_len / 2]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                auto.apply_fourier_to(&input, &mut output, &mut fft, &mut workspace);
            }))
            .is_err()
        );
        assert!(
            output
                .as_ref()
                .iter()
                .all(|&value| value == Complex64::new(7.0, 0.0))
        );
    }
    for (degree, table) in [
        (0, &table),
        (2, &table),
        (2 * N + 1, &table),
        (3, &short_table),
    ] {
        let mut fft = FftEngine::new(table);
        let mut rng = StdRng::seed_from_u64(37);
        let mut expected_rng = StdRng::seed_from_u64(37);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = FourierNtruAutomorphismKey::generate(
                    degree,
                    &secret,
                    &key,
                    &gadget,
                    &mut fft,
                    &mut rng,
                    &mut generation,
                );
            }))
            .is_err()
        );
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}

#[test]
fn ntt_automorphism_preserves_the_original_nonbinary_secret() {
    let modulus = BarrettModulus::new(Q);
    let table = UintNttTable::new(PolyLength::new(N), modulus).unwrap();
    let parameters = NtruParameters::new(
        PolyLength::new(N),
        P,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x6175_746f_4e54_5452);
    let (secret, key) =
        NttNtruSecretKey::generate_pair(parameters.encryption_parameters(), &table, &mut rng)
            .unwrap();
    assert!(secret.as_slice().contains(&-1));
    let message: Vec<u32> = (0..N).map(|i| (3 * i as u32 + 1) % P).collect();
    let input = key.encrypt_message(
        &Polynomial(message.as_slice()),
        &parameters,
        PlaintextEmbedding::Unsigned,
        &table,
        &mut rng,
    );
    let mut coefficients = NtruCiphertext::<Vec<u32>>::zero(N);
    input.write_coeff_form(&mut coefficients, &table);
    let mut generation = NttNtruGadgetEncryptWorkspace::new(PolyLength::new(N));
    let mut workspace = NttNtruAutomorphismWorkspace::new(PolyLength::new(N));
    let mut output = NtruCiphertext::new(vec![7u32; N]);
    let mut transformed_output = NttNtruCiphertext::<Vec<u32>>::zero(N);
    let mut transformed_coeff_output = NttNtruCiphertext::<Vec<u32>>::zero(N);
    for log_basis in [3, 10] {
        let gadget = NlevParameters::with_ntru_params(
            &parameters,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(log_basis),
                level_count: None,
            },
        );
        for degree in [1, 3, N + 1, 2 * N - 1] {
            let auto = NttNtruAutomorphismKey::generate(
                degree,
                &secret,
                &key,
                &gadget,
                &table,
                &mut rng,
                &mut generation,
            );
            assert_eq!(auto.degree(), degree);
            assert_eq!(auto.poly_length(), N);
            assert_eq!(auto.basis(), gadget.basis());
            auto.apply_to(&coefficients, &mut output, modulus, &table, &mut workspace);
            auto.apply_ntt_to(
                &input,
                &mut transformed_output,
                modulus,
                &table,
                &mut workspace,
            );
            output.write_ntt_form(&mut transformed_coeff_output, &table);
            assert_eq!(
                transformed_output.as_ref(),
                transformed_coeff_output.as_ref()
            );
            assert_eq!(
                key.decrypt_message(&transformed_output, &parameters, &table)
                    .as_ref(),
                substitute(&message, degree),
                "degree={degree}, log_basis={log_basis}",
            );
        }
    }
}

#[test]
fn ntt_automorphism_rejects_incompatible_resources_before_writes() {
    let modulus = BarrettModulus::new(Q);
    let other_modulus = BarrettModulus::new(998_244_353);
    let table = UintNttTable::new(PolyLength::new(N), modulus).unwrap();
    let short_table = UintNttTable::new(PolyLength::new(N / 2), modulus).unwrap();
    let other_table = UintNttTable::new(PolyLength::new(N), other_modulus).unwrap();
    let parameters = NtruParameters::new(
        PolyLength::new(N),
        P,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget = NlevParameters::with_ntru_params(
        &parameters,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(3),
            level_count: None,
        },
    );
    let mut rng = StdRng::seed_from_u64(0x6175_746f_626f_756e);
    let (secret, key) =
        NttNtruSecretKey::generate_pair(parameters.encryption_parameters(), &table, &mut rng)
            .unwrap();
    let mut generation = NttNtruGadgetEncryptWorkspace::new(PolyLength::new(N));
    let auto = NttNtruAutomorphismKey::generate(
        3,
        &secret,
        &key,
        &gadget,
        &table,
        &mut rng,
        &mut generation,
    );
    for (input_len, output_len, scratch_len, modulus, table) in [
        (N / 2, N, N, modulus, &table),
        (N, N / 2, N, modulus, &table),
        (N, N, N / 2, modulus, &table),
        (N, N, N, modulus, &short_table),
        (N, N, N, other_modulus, &table),
        (N, N, N, modulus, &other_table),
    ] {
        let input = NtruCiphertext::<Vec<u32>>::zero(input_len);
        let mut output = NtruCiphertext::new(vec![7; output_len]);
        let mut workspace = NttNtruAutomorphismWorkspace::new(PolyLength::new(scratch_len));
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                auto.apply_to(&input, &mut output, modulus, table, &mut workspace);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 7));
        let input = NttNtruCiphertext::new(input.as_ref());
        let mut output = NttNtruCiphertext::new(output.as_mut());
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                auto.apply_ntt_to(&input, &mut output, modulus, table, &mut workspace);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 7));
    }
    // Construction must reject a bad degree or domain before consuming randomness.
    let foreign_key =
        NttNtruSecretKey::try_from_coeff_secret_key(&secret, other_modulus, &other_table).unwrap();
    for (degree, key, table) in [
        (0, &key, &table),
        (2, &key, &table),
        (2 * N + 1, &key, &table),
        (3, &key, &short_table),
        (3, &key, &other_table),
        (3, &foreign_key, &table),
    ] {
        let mut rng = StdRng::seed_from_u64(37);
        let mut expected_rng = StdRng::seed_from_u64(37);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = NttNtruAutomorphismKey::generate(
                    degree,
                    &secret,
                    key,
                    &gadget,
                    table,
                    &mut rng,
                    &mut generation,
                );
            }))
            .is_err()
        );
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}
