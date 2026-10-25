//! Small-ring oracles for key pairs, initialization and normalized trace. Expected values
//! use integer convolution, not the production polynomial/transform kernels.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_distr::sample_gaussian_values_to;
use primus_encoding::PlaintextEmbedding;
use primus_fft::{FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNtruGadgetEncryptWorkspace, FourierNtruSecretKey, FourierNtruTraceKey,
    FourierNtruTraceWorkspace, NlevCiphertext, NlevParameters, NtruCiphertext, NtruParameters,
    NtruSecretKey, NttNtruExternalProductWorkspace, NttNtruGadgetEncryptWorkspace,
    NttNtruSecretKey, NttNtruTraceKey, NttNtruTraceWorkspace, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;

use rand::{SeedableRng, TryCryptoRng, TryRng, rngs::StdRng};

const N: usize = 32;
type Poly = [i128; N];

// Embed the eight-coefficient oracle fixtures via X -> X^(N/8).
// This preserves their algebraic identities, including the rational inverse denominator.
const fn embedded_fixture(coefficients: &[i128; 8]) -> Poly {
    let mut result = [0; N];
    let mut i = 0;
    while i < coefficients.len() {
        result[i * (N / 8)] = coefficients[i];
        i += 1;
    }
    result
}
const ONE: Poly = embedded_fixture(&[1, 0, 0, 0, 0, 0, 0, 0]);
const SECRET: Poly = embedded_fixture(&[1, 1, 0, -1, 0, 0, 0, 0]);

#[derive(Clone, Copy)]
struct Ring(i128);

impl Ring {
    fn add(self, lhs: Poly, rhs: Poly) -> Poly {
        std::array::from_fn(|i| (lhs[i] + rhs[i]).rem_euclid(self.0))
    }

    fn scale(self, input: Poly, scalar: i128) -> Poly {
        input.map(|x| (x * scalar).rem_euclid(self.0))
    }

    fn sub(self, lhs: Poly, rhs: Poly) -> Poly {
        self.add(lhs, self.scale(rhs, -1))
    }

    fn mul(self, lhs: Poly, rhs: Poly) -> Poly {
        self.scale(integer_mul(lhs, rhs), 1)
    }

    fn auto(self, input: Poly, degree: usize) -> Poly {
        let mut out = [0; N];
        for (i, x) in input.into_iter().enumerate() {
            let power = i * degree % (2 * N);
            out[power % N] += if power < N { x } else { -x };
        }
        self.scale(out, 1)
    }

    fn rotate(self, input: Poly, exponent: usize) -> Poly {
        let mut monomial = [0; N];
        let power = exponent % (2 * N);
        monomial[power % N] = if power < N { 1 } else { -1 };
        self.mul(input, monomial)
    }

    // Gauss-Jordan elimination over the small prime / power-of-two fixture
    // rings. Unit pivots are selected explicitly; no NTT or key inverse is used.
    fn inverse(self, input: Poly) -> Poly {
        let mut matrix = [[0; N + 1]; N];
        for (row, entries) in matrix.iter_mut().enumerate() {
            for (col, entry) in entries[..N].iter_mut().enumerate() {
                let value = input[(row + N - col) % N];
                *entry = if row >= col { value } else { -value }.rem_euclid(self.0);
            }
        }
        matrix[0][N] = 1;
        for col in 0..N {
            let (pivot, inverse) = (col..N)
                .find_map(|row| inverse_scalar(matrix[row][col], self.0).map(|v| (row, v)))
                .expect("fixture secret must be invertible");
            matrix.swap(col, pivot);
            for value in &mut matrix[col] {
                *value = (*value * inverse).rem_euclid(self.0);
            }
            let pivot = matrix[col];
            for (row, entries) in matrix.iter_mut().enumerate() {
                if row != col {
                    let factor = entries[col];
                    for (value, pivot_value) in entries.iter_mut().zip(pivot) {
                        *value = (*value - factor * pivot_value).rem_euclid(self.0);
                    }
                }
            }
        }
        let inverse = std::array::from_fn(|i| matrix[i][N]);
        assert_eq!(self.mul(input, inverse), ONE);
        inverse
    }
}

fn integer_mul(lhs: Poly, rhs: Poly) -> Poly {
    let mut out = [0; N];
    for (i, a) in lhs.into_iter().enumerate() {
        for (j, b) in rhs.into_iter().enumerate() {
            out[(i + j) % N] += if i + j < N { a * b } else { -a * b };
        }
    }
    out
}

fn inverse_scalar(value: i128, modulus: i128) -> Option<i128> {
    let (mut a, mut b, mut x, mut y) = (value, modulus, 1, 0);
    while b != 0 {
        let quotient = a / b;
        (a, b) = (b, a - quotient * b);
        (x, y) = (y, x - quotient * y);
    }
    (a == 1).then(|| x.rem_euclid(modulus))
}

fn coefficients(input: Poly) -> Vec<u32> {
    input
        .into_iter()
        .map(|x| u32::try_from(x).unwrap())
        .collect()
}

fn polynomial(input: &[u32]) -> Poly {
    std::array::from_fn(|i| i128::from(input[i]))
}

fn project(input: Poly, retained: usize) -> Poly {
    std::array::from_fn(|i| if i % (N / retained) == 0 { input[i] } else { 0 })
}

// Independent arithmetic radix conversion: nearest retained integer, ties up,
// then balanced radix digits. The positive endpoint fixes the odd-q lift.
fn digits(ring: Ring, input: Poly, basis: &ApproxSignedBasis<u32>) -> Vec<Poly> {
    let radix = i128::from(basis.basis_value());
    let delta = 1i128 << basis.drop_bits();
    let levels = basis.level_count().get();
    let max_positive: i128 = (0..levels)
        .map(|i| (radix / 2 - 1) * radix.pow(i as u32) * delta)
        .sum();
    let threshold = max_positive + (delta / 2).max(1);
    let mut out = vec![[0; N]; levels];
    for (i, x) in input.into_iter().enumerate() {
        let representative = if x >= threshold { x - ring.0 } else { x };
        let mut value = (representative + delta / 2).div_euclid(delta);
        for row in &mut out {
            let digit = (value + radix / 2).rem_euclid(radix) - radix / 2;
            row[i] = digit;
            value = (value - digit) / radix;
        }
        assert_eq!(value, 0);
    }
    out
}

#[test]
fn fused_public_initialization_has_the_predicted_decomposition_residual() {
    let ring = Ring(257);
    let modulus = BarrettModulus::new(257u32);
    let ntt = UintNttTable::new(PolyLength::new(N), modulus).unwrap();
    let inverse = ring.inverse(SECRET);
    // These are deliberately small signed phase errors, not sampled security parameters.
    let e_init = embedded_fixture(&[1, -1, 0, 1, 0, 0, 0, 0]);
    let e_plus = embedded_fixture(&[0, 1, 0, -1, 0, 0, 0, 0]);
    let e_minus = embedded_fixture(&[-1, 0, 1, 0, 0, 0, 0, 0]);
    for levels in [2, 3] {
        let basis = ApproxSignedBasis::new(
            Some(257u32),
            DecompositionBaseLog::new(3),
            Some(DecompositionLevelCount::new(levels)),
        );
        let weights: Vec<_> = basis.scalar_iter().map(i128::from).collect();
        let mut workspace = primus_ntru::NttNtruCmuxWorkspace::new(
            PolyLength::new(N),
            DecompositionLevelCount::new(levels),
        );
        let mut output = NtruCiphertext::<Vec<u32>>::zero(N);
        for input in [
            embedded_fixture(&[0, 1, 3, 4, 7, 8, 219, 256]),
            embedded_fixture(&[8, 16, 24, 32, 0, 248, 249, 1]),
        ] {
            let decomposed = digits(ring, input, &basis);
            let reconstructed = decomposed
                .iter()
                .zip(&weights)
                .fold([0; N], |acc, (&d, &g)| ring.add(acc, ring.scale(d, g)));
            let residual = ring.sub(input, reconstructed);
            if levels == 3 {
                assert_eq!(residual, [0; N]);
            } else {
                assert_ne!(residual, [0; N]);
            }
            for exponent in 0..2 * N {
                let inverse_exponent = (2 * N - exponent) % (2 * N);
                for (ternary, secret_bit) in
                    [(false, 0), (false, 1), (true, -1), (true, 0), (true, 1)]
                {
                    let e_minus = if ternary { e_minus } else { [0; N] };
                    let mut initializers = Vec::new();
                    let mut positives = Vec::new();
                    let mut negatives = Vec::new();
                    let target_rotation = match secret_bit {
                        -1 => inverse_exponent,
                        0 => 0,
                        _ => exponent,
                    };
                    let h = ring.rotate(ONE, target_rotation);
                    let mut direct = Vec::new();
                    let mut paper = Vec::new();
                    let mut key_error = [0; N];
                    for ((&g, &d), level) in weights.iter().zip(&decomposed).zip(1i128..) {
                        let initializer = ring.mul(
                            inverse,
                            ring.add(ring.scale(ONE, g), ring.scale(e_init, level)),
                        );
                        let plus = ring.mul(
                            inverse,
                            ring.add(
                                ring.scale(ONE, g * i128::from(secret_bit == 1)),
                                ring.scale(e_plus, level),
                            ),
                        );
                        let minus = ring.mul(
                            inverse,
                            ring.add(
                                ring.scale(ONE, g * i128::from(secret_bit == -1)),
                                ring.scale(e_minus, level),
                            ),
                        );
                        initializers.extend(coefficients(initializer));
                        positives.extend(coefficients(plus));
                        negatives.extend(coefficients(minus));
                        let control = ring.add(
                            initializer,
                            ring.add(
                                ring.sub(ring.rotate(plus, exponent), plus),
                                ring.sub(ring.rotate(minus, inverse_exponent), minus),
                            ),
                        );
                        direct.extend(coefficients(control));
                        // CLK = I-G has exactly the initializer's phase error.
                        paper.extend(coefficients(ring.sub(control, ring.scale(ONE, g))));
                        let noise = ring.scale(
                            ring.add(
                                e_init,
                                ring.add(
                                    ring.sub(ring.rotate(e_plus, exponent), e_plus),
                                    ring.sub(ring.rotate(e_minus, inverse_exponent), e_minus),
                                ),
                            ),
                            level,
                        );
                        key_error = ring.add(key_error, ring.mul(d, noise));
                    }
                    let evaluate = |data| {
                        let key = NlevCiphertext::new(data).into_ntt_form(&ntt);
                        let mut output = NtruCiphertext::<Vec<u32>>::zero(N);
                        key.external_product_to(
                            &Polynomial::new(coefficients(input)),
                            &mut output,
                            &basis,
                            modulus,
                            &ntt,
                            &mut NttNtruExternalProductWorkspace::new(PolyLength::new(N)),
                        );
                        polynomial(output.as_ref())
                    };
                    let initializer = NlevCiphertext::new(initializers).into_ntt_form(&ntt);
                    let positive = NlevCiphertext::new(positives).into_ntt_form(&ntt);
                    let negative = NlevCiphertext::new(negatives).into_ntt_form(&ntt);
                    let public = Polynomial::new(coefficients(input));
                    initializer.lift_monomial_to(
                        &positive,
                        ternary.then_some(&negative),
                        &public,
                        exponent,
                        &mut output,
                        &basis,
                        modulus,
                        &ntt,
                        &mut workspace,
                    );
                    let direct = evaluate(direct);
                    assert_eq!(polynomial(output.as_ref()), direct);
                    let paper = ring.add(input, evaluate(paper));
                    let target = ring.mul(input, h);
                    assert_eq!(
                        ring.mul(SECRET, direct),
                        ring.add(ring.sub(target, ring.mul(residual, h)), key_error)
                    );
                    assert_eq!(
                        ring.mul(SECRET, paper),
                        ring.add(
                            target,
                            ring.add(ring.mul(residual, ring.sub(SECRET, h)), key_error)
                        )
                    );
                    assert_eq!(ring.sub(paper, direct), residual);
                }
            }
        }
    }
}

fn check_native_lift<Table: FftTable>() {
    let ring = Ring(1i128 << 32);
    let numerator = embedded_fixture(&[7, -2, 3, 4, -6, 9, -5, -1]);
    const DENOMINATOR: i128 = 17;
    assert_eq!(integer_mul(SECRET, numerator), ONE.map(|x| x * DENOMINATOR));
    let table = Table::new(PolyLength::new(N));
    let mut fft = FftEngine::new(&table);
    let secret = NtruSecretKey::<u32>::new(
        SECRET.map(|x| x as i32).to_vec(),
        SecretKeyDistr::SparseTernary,
    );
    let key = FourierNtruSecretKey::try_from_coeff_secret_key(&secret, &mut fft).unwrap();
    let params = NtruParameters::new(
        PolyLength::new(N),
        4u32,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut encryption = FourierNtruGadgetEncryptWorkspace::new(PolyLength::new(N));
    let mut output = NtruCiphertext::<Vec<u32>>::zero(N);
    for levels in [3, 4] {
        let gadget = NlevParameters::with_ntru_params(
            &params,
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(levels)),
            },
        );
        let basis = gadget.basis();
        let mut workspace = primus_ntru::FourierNtruCmuxWorkspace::new(
            PolyLength::new(N),
            DecompositionLevelCount::new(levels),
        );
        let mut initializer =
            primus_lattice::nlev::FourierNlev::<Vec<_>>::zero(gadget.fourier_nlev_len());
        let mut positive = initializer.clone();
        let mut negative = initializer.clone();
        key.encrypt_nlev_constant_to(
            1,
            &mut initializer,
            &gadget,
            &mut fft,
            &mut ZeroRng,
            &mut encryption,
        );
        for (ternary, bit) in [(false, 0), (false, 1), (true, -1), (true, 0), (true, 1)] {
            key.encrypt_nlev_constant_to(
                u32::from(bit == 1),
                &mut positive,
                &gadget,
                &mut fft,
                &mut ZeroRng,
                &mut encryption,
            );
            key.encrypt_nlev_constant_to(
                u32::from(bit == -1),
                &mut negative,
                &gadget,
                &mut fft,
                &mut ZeroRng,
                &mut encryption,
            );
            for input in [
                embedded_fixture(&[0, 1, 127, 128, 257, ring.0 - 1, ring.0 / 2, ring.0 / 2 + 1]),
                embedded_fixture(&[256, 512, 768, 1024, 0, ring.0 - 256, ring.0 - 512, 1]),
            ] {
                let decomposed = digits(ring, input, basis);
                let reconstructed: Poly = std::array::from_fn(|i| {
                    decomposed
                        .iter()
                        .zip(basis.scalar_iter())
                        .map(|(d, g)| d[i] * i128::from(g))
                        .sum()
                });
                if levels == 3 {
                    assert_ne!(ring.scale(reconstructed, 1), input);
                } else {
                    assert_eq!(ring.scale(reconstructed, 1), input);
                }
                let public = Polynomial::new(coefficients(input));
                for exponent in 0..2 * N {
                    let rotation = match bit {
                        -1 => (2 * N - exponent) % (2 * N),
                        0 => 0,
                        _ => exponent,
                    };
                    // Integer convolution preserves the signed reconstruction before
                    // the rational inverse and final torus rounding.
                    let mut monomial = [0; N];
                    monomial[rotation % N] = if rotation < N { 1 } else { -1 };
                    let rational = integer_mul(integer_mul(reconstructed, monomial), numerator);
                    let expected = rational.map(|x| {
                        (x.signum() * ((x.abs() + DENOMINATOR / 2) / DENOMINATOR))
                            .rem_euclid(ring.0)
                    });
                    initializer.lift_monomial_to(
                        &positive,
                        ternary.then_some(&negative),
                        &public,
                        exponent,
                        &mut output,
                        basis,
                        &mut fft,
                        &mut workspace,
                    );
                    assert_eq!(polynomial(output.as_ref()), expected);
                    let error = ring.sub(
                        ring.mul(SECRET, expected),
                        ring.rotate(reconstructed, rotation),
                    );
                    for coefficient in error {
                        // Only final coefficient rounding remains with these zero-noise keys.
                        assert!(2 * coefficient.min(ring.0 - coefficient) <= 3);
                    }
                }
            }
        }
    }
}

#[test]
fn native_fused_lift_matches_rational_inverse_and_decomposition_residual() {
    check_native_lift::<RustFftTable>();
    check_native_lift::<TfheFftTable>();
}

// Exact same-secret automorphism is f^-1 * sigma(f*c). This reference follows
// the algebra, not the production permutation/key-switch implementation.
fn modular_trace(ring: Ring, input: Poly, retained: usize) -> Poly {
    let inverse = ring.inverse(SECRET);
    let mut output = input;
    for k in retained.trailing_zeros() + 1..=N.trailing_zeros() {
        let half = ring.scale(output, inverse_scalar(2, ring.0).unwrap());
        let auto = ring.mul(inverse, ring.auto(ring.mul(SECRET, half), (1 << k) + 1));
        output = ring.add(half, auto);
    }
    output
}

// Fourier NLEV keys use the inverse in R[X]/(X^N+1), not the modular
// inverse. With zero sampled noise, model that inverse and final torus
// rounding as exact rationals, so an FFT error cannot hide in a loose bound.
fn native_trace(ring: Ring, input: Poly, retained: usize) -> Poly {
    let numerator = embedded_fixture(&[7, -2, 3, 4, -6, 9, -5, -1]);
    const DENOMINATOR: i128 = 17;
    assert_eq!(integer_mul(SECRET, numerator), ONE.map(|x| x * DENOMINATOR));
    let basis = ApproxSignedBasis::<u32>::new(None, DecompositionBaseLog::new(8), None);
    let mut output = input;
    let mut expected_phase = project(ring.mul(SECRET, input), retained);
    for k in retained.trailing_zeros() + 1..=N.trailing_zeros() {
        let parity = output.map(|x| x % 2);
        let half = output.map(|x| x / 2);
        let degree = (1 << k) + 1;
        let permuted = ring.auto(half, degree);
        let decomposed = digits(ring, permuted, &basis);
        let reconstructed: Poly = std::array::from_fn(|i| {
            decomposed
                .iter()
                .zip(basis.scalar_iter())
                .map(|(d, g)| d[i] * i128::from(g))
                .sum()
        });
        let permuted_secret = ring
            .auto(SECRET, degree)
            .map(|x| if x > ring.0 / 2 { x - ring.0 } else { x });
        // Every g_l*sigma(f) coefficient in this fixture lies inside the
        // signed torus interval; no per-key-row wrapping is omitted here.
        let rational = integer_mul(integer_mul(reconstructed, permuted_secret), numerator);
        let auto = rational.map(|x| {
            let rounded = x.signum() * ((x.abs() + DENOMINATOR / 2) / DENOMINATOR);
            rounded.rem_euclid(ring.0)
        });
        // Subsequent reverse steps are coefficient projectors. The Q/2 lift
        // ambiguity vanishes modulo Q. This closed-form phase oracle does
        // not repeat the ciphertext recurrence above.
        let auto_error = ring.sub(
            ring.mul(SECRET, auto),
            ring.auto(ring.mul(SECRET, half), degree),
        );
        expected_phase = ring.add(
            ring.sub(
                expected_phase,
                project(ring.mul(SECRET, parity), 1 << (k - 1)),
            ),
            project(auto_error, 1 << k),
        );
        output = ring.add(half, auto);
    }
    assert_eq!(ring.mul(SECRET, output), expected_phase);
    let projection = project(ring.mul(SECRET, input), retained);
    let levels = (N / retained).trailing_zeros();
    let norm: i128 = SECRET.iter().map(|x| x.abs()).sum();
    for error in ring.sub(expected_phase, projection) {
        let distance = error.min(ring.0 - error);
        // floor costs at most ||f||_1 per step; rational-to-integer rounding
        // costs at most ||f||_1/2. No sampled or decomposition noise here.
        assert!(2 * distance <= 3 * norm * i128::from(levels));
    }
    output
}

// ZeroRng is solely a deterministic zero-sampled-noise evaluation-key fixture.
struct ZeroRng;
impl TryRng for ZeroRng {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        output.fill(0);
        Ok(())
    }
}
impl TryCryptoRng for ZeroRng {}

fn trace_inputs(ring: Ring) -> [Poly; 3] {
    [
        embedded_fixture(&[
            0,
            1,
            2,
            3,
            ring.0 - 1,
            ring.0 - 2,
            ring.0 / 2,
            ring.0 / 2 + 1,
        ]),
        embedded_fixture(&[1, 3, 5, 7, 9, 11, 13, 15]),
        embedded_fixture(&[0, 2, 4, 6, 8, 10, 12, 14]),
    ]
}

#[test]
fn ntt_reverse_trace_matches_exact_same_secret_oracle() {
    let ring = Ring(257);
    let modulus = BarrettModulus::new(257u32);
    let table = UintNttTable::new(PolyLength::new(N), modulus).unwrap();
    let secret = NtruSecretKey::new(
        SECRET.map(|x| x as i32).to_vec(),
        SecretKeyDistr::SparseTernary,
    );
    let params = NtruParameters::new(
        PolyLength::new(N),
        4,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget = NlevParameters::with_ntru_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(3),
            level_count: None,
        },
    );
    let key = NttNtruSecretKey::try_from_coeff_secret_key(&secret, modulus, &table).unwrap();
    let trace = NttNtruTraceKey::generate(
        &secret,
        &key,
        &gadget,
        &table,
        &mut ZeroRng,
        &mut NttNtruGadgetEncryptWorkspace::new(PolyLength::new(N)),
    );
    let mut workspace = NttNtruTraceWorkspace::new(PolyLength::new(N));
    for input in trace_inputs(ring) {
        for retained in [1, 2, 4, N] {
            let expected = modular_trace(ring, input, retained);
            let phase = ring.mul(SECRET, input);
            let projection = project(phase, retained);
            assert_eq!(ring.mul(SECRET, expected), projection);
            let mut output = NtruCiphertext::<Vec<u32>>::zero(N);
            trace.apply_reverse_partial_to(
                &NtruCiphertext::new(coefficients(input)),
                retained,
                &mut output,
                modulus,
                &table,
                &mut workspace,
            );
            assert_eq!(polynomial(output.as_ref()), expected);
        }
    }
}

fn check_native_trace<Table: FftTable>() {
    let ring = Ring(1i128 << 32);
    let table = Table::new(PolyLength::new(N));
    let mut fft = FftEngine::new(&table);
    let secret = NtruSecretKey::new(
        SECRET.map(|x| x as i32).to_vec(),
        SecretKeyDistr::SparseTernary,
    );
    let params = NtruParameters::new(
        PolyLength::new(N),
        4u32,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget = NlevParameters::with_ntru_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        },
    );
    let key = FourierNtruSecretKey::try_from_coeff_secret_key(&secret, &mut fft).unwrap();
    let trace = FourierNtruTraceKey::generate(
        &secret,
        &key,
        &gadget,
        &mut fft,
        &mut ZeroRng,
        &mut FourierNtruGadgetEncryptWorkspace::new(PolyLength::new(N)),
    );
    let mut workspace = FourierNtruTraceWorkspace::new(PolyLength::new(N));
    // Repeat all eight-bit parity masks across the ring at three ranges.
    // The number of cases stays fixed when the supported ring length increases.
    let parity_inputs = [0, ring.0 / 2 - 2, ring.0 - 2]
        .into_iter()
        .flat_map(|base| {
            (0..1usize << 8)
                .map(move |bits| std::array::from_fn(|i| base + ((bits >> (i % 8)) & 1) as i128))
        });
    for input in trace_inputs(ring).into_iter().chain(parity_inputs) {
        for retained in [1, 2, 4, N] {
            let expected = native_trace(ring, input, retained);
            let mut output = NtruCiphertext::<Vec<u32>>::zero(N);
            trace.apply_reverse_partial_to(
                &NtruCiphertext::new(coefficients(input)),
                retained,
                &mut output,
                &mut fft,
                &mut workspace,
            );
            // Exact agreement with rational inverse + torus rounding for this
            // small fixture, not equality to a noiseless modular inverse.
            assert_eq!(polynomial(output.as_ref()), expected);
        }
    }
}

#[test]
fn native_reverse_trace_matches_rational_keys_and_projected_rounding_errors() {
    check_native_trace::<RustFftTable>();
    check_native_trace::<TfheFftTable>();
}

#[test]
fn generated_ntt_pair_has_exact_coefficient_phase() {
    let modulus = BarrettModulus::new(132_120_577u32);
    let table = UintNttTable::new(PolyLength::new(N), modulus).unwrap();
    let message = Polynomial::new((0..N as u32).map(|i| i % 16).collect::<Vec<_>>());
    let mut rng = StdRng::seed_from_u64(0xB701);
    // Even total weight is admissible over the NTT field; Native rejects it.
    let even = SecretKeyDistr::FixedCompositionTernary {
        negative_one_weight: 1,
        one_weight: 1,
    };
    for distribution in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::gaussian(3.2),
        SecretKeyDistr::Ternary {
            negative_one_probability: 0.125,
            one_probability: 0.375,
        },
        SecretKeyDistr::FixedHammingWeightTernary { hamming_weight: 7 },
        SecretKeyDistr::FixedCompositionTernary {
            negative_one_weight: 3,
            one_weight: 4,
        },
        even,
    ] {
        let params = NtruParameters::new(PolyLength::new(N), 16, modulus, distribution, 0.7);
        let (coeff, key) =
            NttNtruSecretKey::generate_pair(params.encryption_parameters(), &table, &mut rng)
                .unwrap();
        assert_eq!(coeff.distr(), distribution);

        // Replay only the encryption noise. Compute f*c directly in the
        // coefficient ring, independently of the key's cached NTT and inverse.
        let mut expected = vec![0; N];
        sample_gaussian_values_to(
            &mut expected,
            params.noise_distribution(),
            &mut StdRng::seed_from_u64(0xB711),
        );
        params.plaintext_codec().add_encode_slice_assign(
            &mut expected,
            message.as_ref(),
            PlaintextEmbedding::Unsigned,
        );
        let cipher = key.encrypt_message(
            &message,
            &params,
            PlaintextEmbedding::Unsigned,
            &table,
            &mut StdRng::seed_from_u64(0xB711),
        );
        let mut cipher_coeff = cipher.as_ref().to_vec();
        table.inverse_transform_slice(&mut cipher_coeff);
        let secret = std::array::from_fn(|i| i128::from(coeff.as_slice()[i]));
        let phase = Ring(132_120_577).mul(secret, polynomial(&cipher_coeff));
        assert_eq!(phase, polynomial(&expected));
    }
}
