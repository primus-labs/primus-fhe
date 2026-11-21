use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntru::{
    FourierNgswCiphertext, FourierNlevCiphertext, FourierNtruEncryptWorkspace,
    FourierNtruExternalProductWorkspace, FourierNtruGadgetEncryptWorkspace,
    FourierNtruSchemeSwitchKey, FourierNtruSecretKey, NlevCiphertext, NlevParameters,
    NtruCiphertext, NtruParameters, NtruProjectionMethod, NttNgswCiphertext, NttNlevCiphertext,
    NttNtruExternalProductWorkspace, NttNtruGadgetEncryptWorkspace, NttNtruProjectionKey,
    NttNtruSchemeSwitchKey, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_reduce::RingContext;
use rand::{Rng, SeedableRng, rngs::StdRng};

#[path = "support/trace_ring.rs"]
mod trace_ring;
use trace_ring::{LENGTH, N, Q, native_parameters, ntt_parameters, oracle_secret};

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

fn gadget_parameters<T: FheUint, M: RingContext<T>>(
    parameters: &NtruParameters<T, M>,
    log_basis: u32,
    levels: Option<usize>,
) -> NlevParameters<T, M> {
    NlevParameters::with_ntru_params(
        parameters,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(log_basis),
            level_count: levels.map(DecompositionLevelCount::new),
        },
    )
}

#[track_caller]
fn assert_rejected(operation: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(operation)).is_err());
}

#[test]
fn ntt_scheme_switch_has_independent_bases_and_produces_cmux_controls() {
    let (parameters, table) = ntt_parameters(16);
    let modulus = parameters.cipher_modulus();
    let secret = oracle_secret(LENGTH);
    let key = NttNtruSecretKey::try_from_coeff_secret_key(&secret, modulus, &table).unwrap();
    let mut rng = StdRng::seed_from_u64(117);
    let mut generation = NttNtruGadgetEncryptWorkspace::new(LENGTH);
    let mut scratch = NttNtruExternalProductWorkspace::new(LENGTH);
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
        let key_parameters = gadget_parameters(&parameters, log_key_basis, None);
        // L_output below and above L_key=5 for B_key=2^10.
        for output_levels in [2, 6] {
            let output_parameters = gadget_parameters(&parameters, 8, Some(output_levels));
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
        }
    }
}

fn fourier<Table: FftTable>() {
    let q = 1u128 << 64;
    let table = Table::new(LENGTH);
    let mut fft = FftEngine::new(&table);
    let parameters = native_parameters(16);
    let secret = oracle_secret(LENGTH);
    let key = FourierNtruSecretKey::try_from_coeff_secret_key(&secret, &mut fft).unwrap();
    let mut rng = StdRng::seed_from_u64(119);
    let mut generation = FourierNtruGadgetEncryptWorkspace::new(LENGTH);
    let mut encrypt = FourierNtruEncryptWorkspace::new(LENGTH);
    let mut scratch = FourierNtruExternalProductWorkspace::new(LENGTH);
    let messages = messages(q);
    let operands = messages.each_ref().map(|message| {
        let mut transformed = primus_ntru::FourierNtruCiphertext::<Vec<Complex64>>::zero(N / 2);
        key.encrypt_encoded_to(
            message,
            &mut transformed,
            parameters.encryption_parameters(),
            &mut fft,
            &mut rng,
            &mut encrypt,
        );
        let mut output = NtruCiphertext::<Vec<u64>>::zero(N);
        transformed.write_torus_form(&mut output, &mut fft);
        output
    });
    for log_key_basis in [3, 10] {
        let key_parameters = gadget_parameters(&parameters, log_key_basis, None);
        for output_levels in [2, 7] {
            let output_parameters = gadget_parameters(&parameters, 8, Some(output_levels));
            let ss = FourierNtruSchemeSwitchKey::generate(
                &secret,
                &key,
                output_parameters.basis(),
                &key_parameters,
                &mut fft,
                &mut rng,
                &mut generation,
            );
            assert_eq!(ss.key_basis(), key_parameters.basis());
            assert_eq!(ss.output_basis(), output_parameters.basis());
            let mut encrypted =
                FourierNlevCiphertext::<Vec<Complex64>>::zero(output_parameters.fourier_nlev_len());
            let mut input = NlevCiphertext::<Vec<u64>>::zero(output_parameters.nlev_len());
            let mut output =
                FourierNgswCiphertext::<Vec<Complex64>>::zero(output_parameters.fourier_nlev_len());
            let mut row = NtruCiphertext::<Vec<u64>>::zero(N);
            for bit in [0, 1] {
                key.encrypt_nlev_constant_to(
                    bit,
                    &mut encrypted,
                    &output_parameters,
                    &mut fft,
                    &mut rng,
                    &mut generation,
                );
                for (transformed, mut input) in
                    encrypted.iter_ntru(N / 2).zip(input.iter_ntru_mut(N))
                {
                    transformed.write_torus_form(&mut input, &mut fft);
                }
                ss.apply_to(&input, &mut output, &mut fft, &mut scratch);
                for (scalar, level) in output_parameters
                    .basis()
                    .scalar_iter()
                    .zip(output.iter_ntru(N / 2))
                {
                    level.write_torus_form(&mut row, &mut fft);
                    assert_phase(row.as_ref(), &expected_level(scalar, bit, q), q, 1 << 26);
                }
                output.cmux_to(
                    &operands[0],
                    &operands[1],
                    &mut row,
                    output_parameters.basis(),
                    &mut fft,
                    &mut scratch,
                );
                assert_phase(row.as_ref(), messages[bit as usize].as_ref(), q, q / 2048);
            }
        }
    }
}

#[test]
fn fourier_scheme_switch_has_independent_bases_and_produces_cmux_controls() {
    fourier::<RustFftTable>();
    fourier::<TfheFftTable>();
}

#[test]
fn ntt_scheme_switch_rejects_incompatible_resources_before_sampling_or_writing() {
    let (parameters, table) = ntt_parameters(16);
    let modulus = parameters.cipher_modulus();
    let secret = oracle_secret(LENGTH);
    let key = NttNtruSecretKey::try_from_coeff_secret_key(&secret, modulus, &table).unwrap();
    let key_parameters = gadget_parameters(&parameters, 10, None);
    let output_parameters = gadget_parameters(&parameters, 8, Some(2));
    let mut generation = NttNtruGadgetEncryptWorkspace::new(LENGTH);

    let foreign_basis = primus_decompose::primitive::ApproxSignedBasis::new(
        None,
        DecompositionBaseLog::new(8),
        Some(DecompositionLevelCount::new(2)),
    );
    let mut rng = StdRng::seed_from_u64(19);
    let mut untouched = StdRng::seed_from_u64(19);
    assert_rejected(|| {
        let _ = NttNtruSchemeSwitchKey::generate(
            &secret,
            &key,
            &foreign_basis,
            &key_parameters,
            &table,
            &mut rng,
            &mut generation,
        );
    });
    assert_eq!(rng.next_u64(), untouched.next_u64());

    let switch = NttNtruSchemeSwitchKey::generate(
        &secret,
        &key,
        output_parameters.basis(),
        &key_parameters,
        &table,
        &mut rng,
        &mut generation,
    );
    let len = output_parameters.nlev_len();
    let mut output = NttNgswCiphertext::new(vec![7; len]);
    for (input_len, workspace_length) in [(len - 1, LENGTH), (len, PolyLength::new(2 * N))] {
        let input = NlevCiphertext::new(vec![1; input_len]);
        let mut workspace = NttNtruExternalProductWorkspace::new(workspace_length);
        assert_rejected(|| switch.apply_to(&input, &mut output, modulus, &table, &mut workspace));
        assert!(output.as_ref().iter().all(|&x| x == 7));
    }
}

#[test]
fn fourier_scheme_switch_rejects_incompatible_resources_before_writing() {
    // Input and workspace validation precedes the FFT engine's arithmetic.
    let table = RustFftTable::new(LENGTH);
    let mut fft = FftEngine::new(&table);
    let parameters = native_parameters(16);
    let secret = oracle_secret(LENGTH);
    let key = FourierNtruSecretKey::try_from_coeff_secret_key(&secret, &mut fft).unwrap();
    let key_parameters = gadget_parameters(&parameters, 10, None);
    let output_parameters = gadget_parameters(&parameters, 8, Some(2));
    let switch = FourierNtruSchemeSwitchKey::generate(
        &secret,
        &key,
        output_parameters.basis(),
        &key_parameters,
        &mut fft,
        &mut StdRng::seed_from_u64(119),
        &mut FourierNtruGadgetEncryptWorkspace::new(LENGTH),
    );
    let len = output_parameters.nlev_len();
    let sentinel = Complex64::new(7.0, 0.0);
    let mut output =
        FourierNgswCiphertext::new(vec![sentinel; output_parameters.fourier_nlev_len()]);
    for (input_len, workspace_length) in [(len - 1, LENGTH), (len, PolyLength::new(2 * N))] {
        let input = NlevCiphertext::new(vec![1; input_len]);
        let mut workspace = FourierNtruExternalProductWorkspace::new(workspace_length);
        assert_rejected(|| switch.apply_to(&input, &mut output, &mut fft, &mut workspace));
        assert!(output.as_ref().iter().all(|&x| x == sentinel));
    }
}

// Exercise the same complete algorithms with both word widths and odd/even log2(N).
fn projection_methods<T: FheUint, Table: NttTable<ValueT = T>>(
    modulus: BarrettModulus<T>,
    table: &Table,
) {
    use NtruProjectionMethod::*;
    let length = table.poly_length();
    let n = length.get();
    let q: u64 = modulus.value().as_into();
    let parameters = NtruParameters::new(
        length,
        T::as_from(16u32),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let secret = oracle_secret(length);
    let key = NttNtruSecretKey::try_from_coeff_secret_key(&secret, modulus, table).unwrap();
    let trace = gadget_parameters(&parameters, 3, None);
    let ss = gadget_parameters(&parameters, 4, None);
    let output = gadget_parameters(&parameters, 6, Some(2));
    let mut generation = NttNtruGadgetEncryptWorkspace::new(length);
    for method in [Separate, FusedLastStage, FusedLastThreeStages, PairedTrace] {
        let mut rng = StdRng::seed_from_u64(714);
        let projection = NttNtruProjectionKey::generate(
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

#[test]
fn projection_rejects_inexact_buffers_before_writing() {
    let (parameters, table) = ntt_parameters(16);
    let modulus = parameters.cipher_modulus();
    let secret = oracle_secret(LENGTH);
    let key = NttNtruSecretKey::try_from_coeff_secret_key(&secret, modulus, &table).unwrap();
    let trace = gadget_parameters(&parameters, 3, None);
    let scheme_switch = gadget_parameters(&parameters, 4, None);
    let output = gadget_parameters(&parameters, 6, Some(2));
    // project_to validates lengths before dispatching to any projection method.
    let projection = NttNtruProjectionKey::generate(
        NtruProjectionMethod::FusedLastThreeStages,
        &secret,
        &key,
        output.basis(),
        &trace,
        &scheme_switch,
        &table,
        &mut StdRng::seed_from_u64(714),
        &mut NttNtruGadgetEncryptWorkspace::new(LENGTH),
    );
    let input = NtruCiphertext::new([1; N]);
    let output_len = output.nlev_len();
    let scratch_len = projection.scratch_len();
    let mut control = vec![7; output_len];
    let mut projected = vec![11; output_len];
    let mut scratch = vec![13; scratch_len + 1];
    let mut product = NttNtruExternalProductWorkspace::new(LENGTH);
    for (output_len, scratch_len) in [
        (output_len - 1, scratch_len),
        (output_len, scratch_len - 1),
        (output_len, scratch_len + 1),
    ] {
        assert_rejected(|| {
            projection.project_to(
                input.as_view(),
                NttNgswCiphertext::new(&mut control[..output_len]),
                &mut projected,
                &mut scratch[..scratch_len],
                modulus,
                &table,
                &mut product,
            );
        });
        assert!(control.iter().all(|&x| x == 7));
        assert!(projected.iter().all(|&x| x == 11));
        assert!(scratch.iter().all(|&x| x == 13));
    }
}
