use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_modulus::BarrettModulus;
use primus_ntru::{
    NlevCiphertext, NlevParameters, NtruCiphertext, NtruParameters, NtruSecretKey,
    NttNgswCiphertext, NttNlevCiphertext, NttNtruExternalProductWorkspace,
    NttNtruGadgetEncryptWorkspace, NttNtruSchemeSwitchKey, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 32;
const Q: u64 = 1_125_899_906_826_241;

fn secret() -> NtruSecretKey<u64> {
    let mut coefficients = vec![0; N];
    coefficients[0] = 1;
    coefficients[1] = 1;
    coefficients[3] = -1;
    NtruSecretKey::new(coefficients, SecretKeyDistr::SparseTernary)
}

// Independent negacyclic convolution by the fixed nonbinary secret 1+X-X³.
fn assert_phase(cipher: &[u64], expected: &[u64], q: u128, tolerance: u128) {
    let n = cipher.len();
    assert_eq!(expected.len(), n);
    let mut actual = vec![0u128; n];
    for (i, &value) in cipher.iter().enumerate() {
        for (shift, sign) in [(0, false), (1, false), (3, true)] {
            let negative = (i + shift >= n) ^ sign;
            let term = if negative {
                (q - u128::from(value)) % q
            } else {
                value.into()
            };
            actual[(i + shift) % n] = (actual[(i + shift) % n] + term) % q;
        }
    }
    for (i, (actual, &expected)) in actual.into_iter().zip(expected).enumerate() {
        let difference = (actual + q - u128::from(expected)) % q;
        assert!(
            difference.min(q - difference) < tolerance,
            "phase mismatch at {i}: {actual} vs {expected}"
        );
    }
}

fn expected_level(scalar: u64, bit: u64, q: u128) -> [u64; N] {
    let mut expected = [0; N];
    let value = u128::from(scalar) * u128::from(bit) % q;
    expected[0] = value as u64;
    expected[1] = value as u64;
    expected[3] = ((q - value) % q) as u64;
    expected
}

fn messages(q: u128) -> [Polynomial<Vec<u64>>; 2] {
    [1, 5].map(|offset| {
        Polynomial::new(
            (0..N)
                .map(|i| (((i + offset) % 8) as u128 * (q / 16)) as u64)
                .collect(),
        )
    })
}

#[test]
fn ntt_scheme_switch_has_independent_bases_and_produces_cmux_controls() {
    let modulus = BarrettModulus::new(Q);
    let table = U64NttTable::new(PolyLength::new(N), modulus).unwrap();
    let parameters = NtruParameters::new(
        PolyLength::new(N),
        16,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let secret = secret();
    let key = NttNtruSecretKey::try_from_coeff_secret_key(&secret, modulus, &table).unwrap();
    let mut rng = StdRng::seed_from_u64(117);
    let mut generation = NttNtruGadgetEncryptWorkspace::new(PolyLength::new(N));
    let mut scratch = NttNtruExternalProductWorkspace::new(PolyLength::new(N));
    let messages = messages(Q.into());
    let operands = messages.each_ref().map(|message| {
        let mut transformed = primus_ntru::NttNtruCiphertext::<Vec<u64>>::zero(N);
        key.encrypt_encoded_to(
            message,
            &mut transformed,
            parameters.encryption_parameters(),
            &table,
            &mut rng,
        );
        let mut output = NtruCiphertext::<Vec<u64>>::zero(N);
        transformed.write_coeff_form(&mut output, &table);
        output
    });
    for log_key_basis in [3, 10] {
        let key_parameters = NlevParameters::with_ntru_params(
            &parameters,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(log_key_basis),
                level_count: None,
            },
        );
        // L_output below and above L_key=5 for B_key=2^10.
        for output_levels in [2, 6] {
            let output_parameters = NlevParameters::with_ntru_params(
                &parameters,
                DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(8),
                    level_count: Some(DecompositionLevelCount::new(output_levels)),
                },
            );
            let ss = NttNtruSchemeSwitchKey::generate(
                &secret,
                &key,
                output_parameters.basis(),
                &key_parameters,
                &table,
                &mut rng,
                &mut generation,
            );
            assert_eq!(ss.key_basis(), key_parameters.basis());
            assert_eq!(ss.output_basis(), output_parameters.basis());
            let mut encrypted = NttNlevCiphertext::<Vec<u64>>::zero(output_parameters.nlev_len());
            let mut input = NlevCiphertext::<Vec<u64>>::zero(output_parameters.nlev_len());
            let mut output = NttNgswCiphertext::<Vec<u64>>::zero(output_parameters.nlev_len());
            let mut row = NtruCiphertext::<Vec<u64>>::zero(N);
            for bit in [0, 1] {
                key.encrypt_nlev_constant_to(
                    bit,
                    &mut encrypted,
                    &output_parameters,
                    &table,
                    &mut rng,
                    &mut generation,
                );
                for (transformed, mut input) in
                    encrypted.iter_ntt_ntru(N).zip(input.iter_ntru_mut(N))
                {
                    transformed.write_coeff_form(&mut input, &table);
                }
                ss.apply_to(&input, &mut output, modulus, &table, &mut scratch);
                for (scalar, level) in output_parameters
                    .basis()
                    .scalar_iter()
                    .zip(output.iter_ntt_ntru(N))
                {
                    level.write_coeff_form(&mut row, &table);
                    // Functional tolerance includes f/f² amplification; it is
                    // independent of the much larger high-layer gadget scales.
                    assert_phase(
                        row.as_ref(),
                        &expected_level(scalar, bit, Q.into()),
                        Q.into(),
                        1 << 24,
                    );
                }
                output.cmux_to(
                    &operands[0],
                    &operands[1],
                    &mut row,
                    output_parameters.basis(),
                    modulus,
                    &table,
                    &mut scratch,
                );
                // Even the deliberately short output basis retains 16 bits.
                assert_phase(
                    row.as_ref(),
                    messages[bit as usize].as_ref(),
                    Q.into(),
                    u128::from(Q) / 2048,
                );
            }
            output.as_mut().fill(7);
            let mut wrong = NttNtruExternalProductWorkspace::new(PolyLength::new(2 * N));
            assert!(
                catch_unwind(AssertUnwindSafe(|| ss.apply_to(
                    &input,
                    &mut output,
                    modulus,
                    &table,
                    &mut wrong
                )))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&value| value == 7));
            let short = NlevCiphertext::new(&input.as_ref()[..input.as_ref().len() - 1]);
            assert!(
                catch_unwind(AssertUnwindSafe(|| ss.apply_to(
                    &short,
                    &mut output,
                    modulus,
                    &table,
                    &mut scratch
                )))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&value| value == 7));
        }
    }
    let foreign = primus_decompose::primitive::ApproxSignedBasis::new(
        None,
        DecompositionBaseLog::new(8),
        Some(DecompositionLevelCount::new(2)),
    );
    let key_parameters = NlevParameters::with_ntru_params(
        &parameters,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(10),
            level_count: None,
        },
    );
    let mut untouched = StdRng::seed_from_u64(19);
    let mut invalid = StdRng::seed_from_u64(19);
    assert!(
        catch_unwind(AssertUnwindSafe(|| NttNtruSchemeSwitchKey::generate(
            &secret,
            &key,
            &foreign,
            &key_parameters,
            &table,
            &mut invalid,
            &mut generation
        )))
        .is_err()
    );
    assert_eq!(
        rand::Rng::next_u64(&mut invalid),
        rand::Rng::next_u64(&mut untouched)
    );
}

// Exercise the same complete algorithms with both word widths and odd/even log2(N).
fn projection_methods<T: primus_integer::FheUint, Table: NttTable<ValueT = T>>(
    modulus: BarrettModulus<T>,
    table: &Table,
) {
    use primus_integer::AsFrom;
    use primus_ntru::NtruProjectionMethod::*;
    let length = table.poly_length();
    let n = length.get();
    let q: u64 = modulus.value().as_into();
    for method in [Separate, FusedLastStage, FusedLastThreeStages, PairedTrace] {
        let parameters = NtruParameters::new(
            length,
            T::as_from(16u32),
            modulus,
            SecretKeyDistr::SparseTernary,
            0.7,
        );
        let mut coefficients = vec![T::SignedInteger::as_from(0i32); n];
        coefficients[0] = T::SignedInteger::as_from(1i32);
        coefficients[1] = T::SignedInteger::as_from(1i32);
        coefficients[3] = T::SignedInteger::as_from(-1i32);
        let secret = NtruSecretKey::new(coefficients, SecretKeyDistr::SparseTernary);
        let key = NttNtruSecretKey::try_from_coeff_secret_key(&secret, modulus, table).unwrap();
        let config = |log_basis, levels: Option<usize>| DecompositionConfig {
            log_basis: DecompositionBaseLog::new(log_basis),
            level_count: levels.map(DecompositionLevelCount::new),
        };
        let trace = NlevParameters::with_ntru_params(&parameters, config(3, None));
        let ss = NlevParameters::with_ntru_params(&parameters, config(4, None));
        let output = NlevParameters::with_ntru_params(&parameters, config(6, Some(2)));
        let mut generation = NttNtruGadgetEncryptWorkspace::new(length);
        let mut rng = StdRng::seed_from_u64(714);
        let projection = primus_ntru::NttNtruProjectionKey::generate(
            method,
            &secret,
            &key,
            output.basis(),
            &trace,
            &ss,
            table,
            &mut rng,
            &mut generation,
        );
        assert_eq!(projection.method(), method);
        let expected_scratch = match method {
            Separate | FusedLastStage => 2 * n,
            FusedLastThreeStages => 8 * n,
            PairedTrace => {
                if length.log_n() & 1 == 0 {
                    5 * n
                } else {
                    8 * n
                }
            }
        };
        assert_eq!(projection.scratch_len(), expected_scratch);
        let mut product = NttNtruExternalProductWorkspace::new(length);
        let mut scratch = vec![T::as_from(q - 1); projection.scratch_len()];
        let mut projected = vec![T::as_from(q - 1); output.nlev_len()];
        let mut control = NttNgswCiphertext::<Vec<T>>::zero(output.nlev_len());
        let mut transformed = primus_ntru::NttNtruCiphertext::<Vec<T>>::zero(n);
        let mut cipher = NtruCiphertext::<Vec<T>>::zero(n);
        let mut row = NtruCiphertext::<Vec<T>>::zero(n);
        for bit in [1, 0] {
            // Dense nonzero tail rules out the zero-tail prefix-expansion shortcut.
            let mut message = Polynomial::new(
                (0..n)
                    .map(|i| T::as_from(((i as u64 + 1) * (q / 64)) % q))
                    .collect::<Vec<_>>(),
            );
            for (coefficient, scalar) in message
                .as_mut()
                .iter_mut()
                .zip(output.basis().scalar_iter())
            {
                *coefficient = scalar * T::as_from(bit);
            }
            key.encrypt_encoded_to(
                &message,
                &mut transformed,
                parameters.encryption_parameters(),
                table,
                &mut rng,
            );
            transformed.write_coeff_form(&mut cipher, table);
            control.as_mut().fill(T::as_from(q - 1));
            projection.project_to(
                cipher.as_view(),
                control.as_mut_view(),
                &mut projected,
                &mut scratch,
                modulus,
                table,
                &mut product,
            );
            for (level, scalar) in control.iter_ntt_ntru(n).zip(output.basis().scalar_iter()) {
                level.write_coeff_form(&mut row, table);
                let mut expected = vec![0; n];
                expected[..N].copy_from_slice(&expected_level(scalar.as_into(), bit, q.into()));
                let actual: Vec<u64> = row.as_ref().iter().map(|&x| x.as_into()).collect();
                assert_phase(
                    &actual,
                    &expected,
                    q.into(),
                    (u128::from(q) / (1 << 14)).min(1 << 20),
                );
            }
        }
        // Reject an incomplete output before either the scratch or output is touched.
        control.as_mut().fill(T::as_from(7u32));
        projected.fill(T::as_from(11u32));
        let len = control.as_ref().len() - 1;
        assert!(
            catch_unwind(AssertUnwindSafe(|| projection.project_to(
                cipher.as_view(),
                NttNgswCiphertext::new(&mut control.as_mut()[..len]),
                &mut projected,
                &mut scratch,
                modulus,
                table,
                &mut product,
            )))
            .is_err()
        );
        assert!(control.as_ref().iter().all(|&x| x == T::as_from(7u32)));
        assert!(projected.iter().all(|&x| x == T::as_from(11u32)));
        // Scratch is exact-sized for the selected algorithm, not merely a minimum.
        for len in [projection.scratch_len() - 1, projection.scratch_len() + 1] {
            let mut invalid = vec![T::as_from(13u32); len];
            assert!(
                catch_unwind(AssertUnwindSafe(|| projection.project_to(
                    cipher.as_view(),
                    control.as_mut_view(),
                    &mut projected,
                    &mut invalid,
                    modulus,
                    table,
                    &mut product,
                )))
                .is_err()
            );
            assert!(control.as_ref().iter().all(|&x| x == T::as_from(7u32)));
            assert!(projected.iter().all(|&x| x == T::as_from(11u32)));
            assert!(invalid.iter().all(|&x| x == T::as_from(13u32)));
        }
    }
}

#[test]
fn projection_methods_remove_general_tails_and_preserve_output_levels() {
    for n in [32, 64] {
        let length = PolyLength::new(n);
        let q32 = BarrettModulus::new(998_244_353u32);
        projection_methods(q32, &primus_ntt::U32NttTable::new(length, q32).unwrap());
        let q64 = BarrettModulus::new(Q);
        projection_methods(q64, &U64NttTable::new(length, q64).unwrap());
    }
}
