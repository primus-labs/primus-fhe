use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_encoding::PlaintextEmbedding;
use primus_modulus::BarrettModulus;
use primus_ntru::{
    NlevParameters, NtruCiphertext, NtruParameters, NttNgswCiphertext, NttNtruCmuxWorkspace,
    NttNtruExternalProductWorkspace, NttNtruSecretKey, SecretKeyDistr,
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
