use num_traits::{ConstOne, ConstZero};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_encoding::PlaintextEmbedding;
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_integer::SignedInteger;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNgswCiphertext, FourierNtruCmuxWorkspace, FourierNtruEncryptWorkspace,
    FourierNtruExternalProductWorkspace, FourierNtruGadgetEncryptWorkspace, FourierNtruSecretKey,
    NgswCiphertext, NlevParameters, NtruCiphertext, NtruParameters, NttNgswCiphertext,
    NttNtruCmuxWorkspace, NttNtruExternalProductWorkspace, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 32;
const Q: u64 = 1_125_899_906_826_241;

// Exact schoolbook phase, independent of cached transformed secrets and products.
fn phase(cipher: &[u64], secret: &[i64]) -> Vec<u64> {
    let mut output = vec![0i128; N];
    for (i, &value) in cipher.iter().enumerate() {
        for (j, &secret) in secret.iter().enumerate() {
            let product = i128::from(value) * i128::from(secret);
            if i + j < N {
                output[i + j] += product;
            } else {
                output[i + j - N] -= product;
            }
        }
    }
    output
        .into_iter()
        .map(|v| v.rem_euclid(Q.into()) as u64)
        .collect()
}

fn rotate(input: &[u64], exponent: isize) -> Vec<u64> {
    let mut output = vec![0; N];
    for (i, &value) in input.iter().enumerate() {
        let index = (i as isize + exponent).rem_euclid(2 * N as isize) as usize;
        output[index % N] = if index < N || value == 0 {
            value
        } else {
            Q - value
        };
    }
    output
}

fn distance(lhs: u64, rhs: u64) -> u64 {
    let difference = lhs.abs_diff(rhs);
    difference.min(Q - difference)
}

#[test]
fn encrypted_ternary_step_matches_phase_oracle_and_two_binary_cmuxes() {
    let modulus = BarrettModulus::new(Q);
    let ntt = UintNttTable::new(PolyLength::new(N), modulus).unwrap();
    let params = NtruParameters::new(
        PolyLength::new(N),
        16,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget = NlevParameters::with_ntru_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(6)),
        },
    );
    let basis = gadget.basis();
    let mut rng = StdRng::seed_from_u64(0xB702);
    let (coeff, key) =
        NttNtruSecretKey::generate_pair(params.encryption_parameters(), &ntt, &mut rng).unwrap();
    let message = Polynomial::new((0..N as u64).map(|i| i % 16).collect::<Vec<_>>());
    let input = key
        .encrypt_message(
            &message,
            &params,
            PlaintextEmbedding::Unsigned,
            &ntt,
            &mut rng,
        )
        .into_coeff_form(&ntt);
    let input_phase = phase(input.as_ref(), coeff.as_slice());
    let secret_norm: u64 = coeff.as_slice().iter().map(|v| v.unsigned_abs()).sum();
    let mut controls = vec![0; 2 * gadget.nlev_len()];
    let mut fused = NttNtruCmuxWorkspace::new(PolyLength::new(N), gadget.level_count());
    let mut binary = NttNtruExternalProductWorkspace::new(PolyLength::new(N));
    let mut output = NtruCiphertext::new(vec![Q - 1; N]);
    let mut intermediate = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut reference = NtruCiphertext::<Vec<u64>>::zero(N);

    for secret in [1isize, -1, 0] {
        key.encrypt_ngsw_signed_constant_batch_to(
            &[i64::from(secret == 1), i64::from(secret == -1)],
            &mut controls,
            &gadget,
            &ntt,
            &mut rng,
        );
        // Bound the actual control errors, not a probabilistic Gaussian cutoff.
        // Each digit is bounded by B/2. Convolution by f multiplies the
        // decomposition residual bound by ||f||_1.
        let mut control_error_sum = 0;
        for (control, bit) in controls
            .chunks_exact(gadget.nlev_len())
            .zip([u64::from(secret == 1), u64::from(secret == -1)])
        {
            for (level, scalar) in control.as_chunks::<N>().0.iter().zip(basis.scalar_iter()) {
                let mut coefficients = level.to_vec();
                ntt.inverse_transform_slice(&mut coefficients);
                let actual = phase(&coefficients, coeff.as_slice());
                let maximum_error = actual
                    .iter()
                    .zip(coeff.as_slice())
                    .map(|(&value, &f)| {
                        let target = (i128::from(f) * i128::from(scalar) * i128::from(bit))
                            .rem_euclid(Q.into()) as u64;
                        distance(value, target)
                    })
                    .max()
                    .unwrap();
                control_error_sum += maximum_error;
            }
        }
        let residual_bound = secret_norm * basis.approximate_error_bound();
        let noise_bound = N as u64 * (basis.basis_value() / 2) * control_error_sum;
        let fused_bound = residual_bound + noise_bound;
        let binary_bound = 2 * residual_bound + noise_bound;
        let (positive, negative) = controls.split_at(gadget.nlev_len());
        let positive = NttNgswCiphertext::new(positive);
        let negative = NttNgswCiphertext::new(negative);
        // Sign/wrap boundaries and an interior shift; zero follows dirty scratch.
        // Exhaustive index arithmetic is covered by the polynomial rotation oracle.
        for exponent in [1, N / 2 - 1, N / 2, N - 1, N, N + 1, 2 * N - 1, 0] {
            positive.cmux_ternary_monomial_to(
                &negative,
                &input,
                exponent,
                &mut output,
                basis,
                modulus,
                &ntt,
                &mut fused,
            );
            positive.cmux_monomial_to(
                &input,
                exponent,
                &mut intermediate,
                basis,
                modulus,
                &ntt,
                &mut binary,
            );
            negative.cmux_monomial_to(
                &intermediate,
                (2 * N - exponent) % (2 * N),
                &mut reference,
                basis,
                modulus,
                &ntt,
                &mut binary,
            );
            let expected = rotate(&input_phase, exponent as isize * secret);
            let actual = phase(output.as_ref(), coeff.as_slice());
            let reference_phase = phase(reference.as_ref(), coeff.as_slice());
            for ((&actual, &reference), &expected) in
                actual.iter().zip(&reference_phase).zip(&expected)
            {
                assert!(distance(actual, expected) <= fused_bound);
                assert!(distance(reference, expected) <= binary_bound);
            }
            if exponent == 0 {
                assert_eq!(output.as_ref(), input.as_ref());
            }
        }
    }
}

// Exact Native phase; signed secrets are embedded as wrapping bit patterns.
fn native_phase<T: TorusFftValue>(cipher: &[T], secret: &[T::SignedInteger]) -> Vec<T> {
    let mut output = vec![T::ZERO; N];
    for (i, &value) in cipher.iter().enumerate() {
        for (j, &secret) in secret.iter().enumerate() {
            let product = value.wrapping_mul(secret.cast_to_unsigned());
            if i + j < N {
                output[i + j] = output[i + j].wrapping_add(product);
            } else {
                output[i + j - N] = output[i + j - N].wrapping_sub(product);
            }
        }
    }
    output
}

fn native_distance<T: TorusFftValue>(lhs: T, rhs: T) -> T {
    lhs.wrapping_sub(rhs).min(rhs.wrapping_sub(lhs))
}

fn check_fourier_step<T: TorusFftValue, Table: FftTable>() {
    let table = Table::new(PolyLength::new(N));
    let mut fft = FftEngine::new(&table);
    let params = NtruParameters::new(
        PolyLength::new(N),
        T::try_from(16).unwrap(),
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget = NlevParameters::with_ntru_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new((T::BITS / 8 - 1) as usize)),
        },
    );
    let basis = gadget.basis();
    let mut rng = StdRng::seed_from_u64(0xB703);
    let (coeff, key) =
        FourierNtruSecretKey::generate_pair(params.encryption_parameters(), &mut fft, &mut rng)
            .unwrap();
    let message = Polynomial::new(
        (0..N)
            .map(|i| T::try_from(i % 16).unwrap())
            .collect::<Vec<_>>(),
    );
    let mut input = NtruCiphertext::<Vec<T>>::zero(N);
    key.encrypt_message(
        &message,
        &params,
        PlaintextEmbedding::Unsigned,
        &mut fft,
        &mut rng,
        &mut FourierNtruEncryptWorkspace::new(PolyLength::new(N)),
    )
    .write_torus_form(&mut input, &mut fft);
    let input_phase = native_phase(input.as_ref(), coeff.as_slice());
    let secret_norm = T::try_from(
        coeff
            .as_slice()
            .iter()
            .filter(|&&v| v != T::SignedInteger::ZERO)
            .count(),
    )
    .unwrap();
    let mut controls = vec![Complex64::default(); 2 * gadget.fourier_nlev_len()];
    let mut encrypt_workspace = FourierNtruGadgetEncryptWorkspace::new(PolyLength::new(N));
    let mut fused = FourierNtruCmuxWorkspace::new(PolyLength::new(N), gadget.level_count());
    let mut binary = FourierNtruExternalProductWorkspace::new(PolyLength::new(N));
    let mut output = NtruCiphertext::new(vec![T::MAX; N]);
    let mut intermediate = NtruCiphertext::<Vec<T>>::zero(N);
    let mut reference = NtruCiphertext::<Vec<T>>::zero(N);
    let mut control_coeff = NgswCiphertext::<Vec<T>>::zero(gadget.nlev_len());

    for secret in [1isize, -1, 0] {
        let bits = [secret == 1, secret == -1];
        key.encrypt_ngsw_signed_constant_batch_to(
            &bits.map(|bit| {
                if bit {
                    T::SignedInteger::ONE
                } else {
                    T::SignedInteger::ZERO
                }
            }),
            &mut controls,
            &gadget,
            &mut fft,
            &mut rng,
            &mut encrypt_workspace,
        );
        let mut control_error_sum = T::ZERO;
        for (control, bit) in controls.chunks_exact(gadget.fourier_nlev_len()).zip(bits) {
            FourierNgswCiphertext::new(control).write_torus_form(&mut control_coeff, &mut fft);
            for (row, scalar) in control_coeff
                .as_ref()
                .as_chunks::<N>()
                .0
                .iter()
                .zip(basis.scalar_iter())
            {
                let phase = native_phase(row, coeff.as_slice());
                control_error_sum += phase
                    .iter()
                    .zip(coeff.as_slice())
                    .map(|(&actual, &f)| {
                        let expected = if bit {
                            scalar.wrapping_mul(f.cast_to_unsigned())
                        } else {
                            T::ZERO
                        };
                        native_distance(actual, expected)
                    })
                    .max()
                    .unwrap();
            }
        }
        // Recovering each control row rounds its coefficients: account for
        // ||f||_1/2 per row as well as the measured control error. The separate
        // 2^-40 torus allowance (at least one integer unit) is a numerical
        // regression budget for this small ring, not a general FFT error proof.
        let floating_budget = T::ONE << T::BITS.saturating_sub(40);
        let residual_bound = secret_norm * basis.approximate_error_bound();
        let noise_bound = T::try_from(N).unwrap()
            * (basis.basis_value() / T::TWO)
            * (control_error_sum + secret_norm * T::try_from(gadget.level_count().get()).unwrap());
        let fused_bound = residual_bound + noise_bound + secret_norm * floating_budget;
        let binary_bound = T::TWO * (residual_bound + secret_norm * floating_budget) + noise_bound;
        let (positive, negative) = controls.split_at(gadget.fourier_nlev_len());
        let positive = FourierNgswCiphertext::new(positive);
        let negative = FourierNgswCiphertext::new(negative);
        // Sign/wrap boundaries and an interior shift; zero follows dirty scratch.
        // Exhaustive index arithmetic is covered by the polynomial rotation oracle.
        for exponent in [1, N / 2 - 1, N / 2, N - 1, N, N + 1, 2 * N - 1, 0] {
            positive.cmux_ternary_monomial_to(
                &negative,
                &input,
                exponent,
                &mut output,
                basis,
                &mut fft,
                &mut fused,
            );
            positive.cmux_monomial_to(
                &input,
                exponent,
                &mut intermediate,
                basis,
                &mut fft,
                &mut binary,
            );
            negative.cmux_monomial_to(
                &intermediate,
                (2 * N - exponent) % (2 * N),
                &mut reference,
                basis,
                &mut fft,
                &mut binary,
            );
            let mut expected = vec![T::ZERO; N];
            for (i, &value) in input_phase.iter().enumerate() {
                let index =
                    (i as isize + exponent as isize * secret).rem_euclid(2 * N as isize) as usize;
                expected[index % N] = if index < N {
                    value
                } else {
                    value.wrapping_neg()
                };
            }
            for (actual, bound) in [(&output, fused_bound), (&reference, binary_bound)] {
                let actual = native_phase(actual.as_ref(), coeff.as_slice());
                for (&value, &expected) in actual.iter().zip(&expected) {
                    let error = native_distance(value, expected);
                    assert!(
                        error <= bound,
                        "s={secret}, a={exponent}: {error:?} > {bound:?}"
                    );
                }
            }
            if exponent == 0 {
                assert_eq!(output.as_ref(), input.as_ref());
            }
        }
    }
}

#[test]
fn fourier_ternary_step_matches_independent_phase_and_two_cmuxes() {
    check_fourier_step::<u32, RustFftTable>();
    check_fourier_step::<u64, RustFftTable>();
    check_fourier_step::<u32, TfheFftTable>();
    check_fourier_step::<u64, TfheFftTable>();
}
