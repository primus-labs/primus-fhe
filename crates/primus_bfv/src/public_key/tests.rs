//! Scheme-boundary identities and independent integer/DFT recovery oracles.

use crate::{
    BfvCiphertext, BfvContext, BfvDecryptWorkspace, BfvParameters, BfvPublicKey,
    BfvPublicKeyEncryptor, BfvSecretKeyContext,
};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_poly::{CrtPolynomial, Polynomial};
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};
use zeroize::Zeroize;

const N: usize = 32;
const Q: [u64; 2] = [1_125_899_906_826_241, 1_125_899_906_629_633];
// Primitive 64th roots in the backend's smallest-root convention. These fixed
// witnesses are checked by field arithmetic rather than read from NTT tables.
const ROOTS: [u64; 2] = [18_105_782_770_620, 34_361_371_622_355];

fn parameters(count: usize, t: u64, error: ErrorDistribution) -> BfvParameters {
    BfvParameters::try_with_error_distribution(
        PolyLength::new(N),
        BarrettModulus::new(t),
        BarrettModulus::new(2_199_023_190_017),
        &Q[..count]
            .iter()
            .copied()
            .map(BarrettModulus::new)
            .collect::<Vec<_>>(),
        SecretKeyDistr::SparseTernary,
        error,
    )
    .unwrap()
}

fn mul(left: u64, right: u64, q: u64) -> u64 {
    (u128::from(left) * u128::from(right) % u128::from(q)) as u64
}

fn pow(mut value: u64, mut exponent: usize, q: u64) -> u64 {
    let mut output = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            output = mul(output, value, q);
        }
        value = mul(value, value, q);
        exponent >>= 1;
    }
    output
}

fn points(root: u64, q: u64) -> Vec<u64> {
    assert_eq!(pow(root, N, q), q - 1);
    (0usize..N)
        .map(|index| pow(root, 2 * (index.reverse_bits() >> (usize::BITS - 5)) + 1, q))
        .collect()
}

// Direct field evaluation/inversion, independent of production NTT and phase code.
fn phase_oracle(ciphertext: &[u64], secret: &[i64], count: usize) -> Vec<u64> {
    let length = N * count;
    let mut result = Vec::with_capacity(length);
    for limb in 0..count {
        let q = Q[limb];
        let points = points(ROOTS[limb], q);
        let phase: Vec<_> = points
            .iter()
            .enumerate()
            .map(|(index, &point)| {
                let s = secret.iter().rev().fold(0, |acc, &coefficient| {
                    (mul(acc, point, q) + i128::from(coefficient).rem_euclid(i128::from(q)) as u64)
                        % q
                });
                let c0 = ciphertext[limb * N + index];
                let c1 = ciphertext[length + limb * N + index];
                (c0 + mul(c1, s, q)) % q
            })
            .collect();
        let inverse_n = pow(N as u64, (q - 2) as usize, q);
        for degree in 0..N {
            let sum = points.iter().zip(&phase).fold(0, |acc, (&point, &value)| {
                (acc + mul(value, pow(point, (q - 1 - degree as u64) as usize, q), q)) % q
            });
            result.push(mul(sum, inverse_n, q));
        }
    }
    result
}

fn compose(residues: &[u64], degree: usize, count: usize) -> u128 {
    let first = residues[degree];
    if count == 1 {
        return u128::from(first);
    }
    let q1 = Q[1];
    let correction = mul(
        (residues[N + degree] + q1 - first % q1) % q1,
        pow(Q[0] % q1, (q1 - 2) as usize, q1),
        q1,
    );
    u128::from(first) + u128::from(Q[0]) * u128::from(correction)
}

fn independently_encoded(message: &[u64], count: usize, t: u64, centered: bool) -> Vec<u64> {
    let product: u128 = Q[..count].iter().map(|&q| u128::from(q)).product();
    let delta = product / u128::from(t);
    Q[..count]
        .iter()
        .flat_map(|&q| {
            message.iter().map(move |&m| {
                let phase = if centered && m >= t.div_ceil(2) {
                    product - delta * u128::from(t - m)
                } else {
                    delta * u128::from(m)
                };
                (phase % u128::from(q)) as u64
            })
        })
        .collect()
}

#[test]
fn public_coefficient_and_unscaled_crt_entries_reuse_the_same_kernel() {
    let mut rng = StdRng::seed_from_u64(0x4246_5602);
    for (count, t, secret_distribution) in [
        (1, 254, SecretKeyDistr::UniformBinary),
        (2, 257, SecretKeyDistr::gaussian(3.2)),
    ] {
        let parameters = BfvParameters::try_new(
            PolyLength::new(N),
            BarrettModulus::new(t),
            BarrettModulus::new(2_199_023_190_017),
            &Q[..count]
                .iter()
                .copied()
                .map(BarrettModulus::new)
                .collect::<Vec<_>>(),
            secret_distribution,
            3.2,
        )
        .unwrap();
        let owner = BfvContext::try_new(parameters).unwrap();
        let parameters = owner.parameters();
        let table = owner.table();
        let key = GlweSecretKey::generate(
            parameters.size().glwe_size(),
            parameters.encryption_parameters().secret_key_sampler(),
            &mut rng,
        );
        let signed_secret = key.iter().next().unwrap().to_vec();
        let key = DcrtGlweSecretKey::from_coeff_secret_key(&key, table);
        let public = BfvPublicKey::new(
            &BfvSecretKeyContext::try_new(&key, &owner).unwrap(),
            &mut rng,
        );
        let pk_phase = phase_oracle(public.ciphertext.as_ref(), &signed_secret, count);
        let product: u128 = Q[..count].iter().map(|&q| u128::from(q)).product();
        let error_bound = u128::from(
            parameters
                .encryption_parameters()
                .noise_distribution()
                .maximum_magnitude(),
        );
        for degree in 0..N {
            let error = compose(&pk_phase, degree, count);
            assert!(error.min(product - error) <= error_bound);
        }
        let mut encryptor = BfvPublicKeyEncryptor::try_new(&public, &owner).unwrap();
        let context = BfvSecretKeyContext::try_new(&key, &owner).unwrap();
        let mut workspace = BfvDecryptWorkspace::new(parameters);
        let message = Polynomial(
            (0..N)
                .map(|index| [0, 1, t / 2, (t / 2 + 1).min(t - 1), t - 1][index % 5])
                .collect::<Vec<_>>(),
        );
        let mut output = BfvCiphertext::<Vec<u64>>::zero(parameters.size().rns_glwe_len());
        for centered in [false, true] {
            let lifted = CrtPolynomial(
                Q[..count]
                    .iter()
                    .flat_map(|&q| {
                        message.as_ref().iter().map(move |&m| {
                            if centered && m >= t.div_ceil(2) {
                                q - (t - m)
                            } else {
                                m
                            }
                        })
                    })
                    .collect::<Vec<_>>(),
            );
            let mut coefficient_rng = StdRng::seed_from_u64(509);
            let mut crt_rng = StdRng::seed_from_u64(509);
            if centered {
                encryptor.encrypt_centered_to(&message, &mut output, &mut coefficient_rng);
            } else {
                encryptor.encrypt_to(&message, &mut output, &mut coefficient_rng);
            }
            let expected = if centered {
                encryptor.encrypt_centered(&message, &mut crt_rng)
            } else {
                encryptor.encrypt(&message, &mut crt_rng)
            };
            let mut lifted_ciphertext = BfvCiphertext::zero(parameters.size().rns_glwe_len());
            encryptor.encrypt_plaintext_lift_crt_to(
                &lifted,
                &mut lifted_ciphertext,
                &mut StdRng::seed_from_u64(509),
            );
            assert_eq!(output.as_ref(), lifted_ciphertext.as_ref());
            assert_eq!(output.as_ref(), expected.as_ref());
            assert_eq!(coefficient_rng.next_u64(), crt_rng.next_u64());
            let phase = phase_oracle(output.as_ref(), &signed_secret, count);
            let encoded = independently_encoded(message.as_ref(), count, t, centered);
            let secret_max = signed_secret
                .iter()
                .map(|v| v.unsigned_abs())
                .max()
                .unwrap();
            let complete_bound = error_bound * (N as u128 + 1 + N as u128 * u128::from(secret_max));
            for degree in 0..N {
                let residual = (compose(&phase, degree, count) + product
                    - compose(&encoded, degree, count))
                    % product;
                assert!(residual.min(product - residual) <= complete_bound);
            }
            assert_eq!(context.decrypt(&output, &mut workspace), message);
            let pointer = encryptor.workspace.as_mut_slice().as_ptr();
            encryptor.zeroize();
            assert_eq!(encryptor.workspace.as_mut_slice().as_ptr(), pointer);
            assert!(
                encryptor
                    .workspace
                    .as_mut_slice()
                    .iter()
                    .all(|&value| value == 0)
            );
        }
    }
}

#[test]
fn noncanonical_coefficients_preserve_randomness_output_and_public_scratch() {
    for count in [1, 2] {
        let parameters = parameters(count, 257, ErrorDistribution::CenteredBinomial { eta: 1 });
        let owner = BfvContext::try_new(parameters).unwrap();
        let parameters = owner.parameters();
        let table = owner.table();
        let mut setup_rng = StdRng::seed_from_u64(0x4246_5682);
        let coefficient_key = GlweSecretKey::generate(
            parameters.size().glwe_size(),
            parameters.encryption_parameters().secret_key_sampler(),
            &mut setup_rng,
        );
        let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, table);
        let public = BfvPublicKey::new(
            &BfvSecretKeyContext::try_new(&key, &owner).unwrap(),
            &mut setup_rng,
        );
        let secret = BfvSecretKeyContext::try_new(&key, &owner).unwrap();
        let mut encryptor = BfvPublicKeyEncryptor::try_new(&public, &owner).unwrap();
        for (index, value) in [(0, 257), (N - 1, u64::MAX)] {
            let mut input = Polynomial(vec![1; N]);
            input.as_mut()[index] = value;
            for mode in 0..6 {
                let mut rng = StdRng::seed_from_u64(0x4246_5683);
                let mut reference_rng = StdRng::seed_from_u64(0x4246_5683);
                let mut output = BfvCiphertext::new(vec![99; parameters.size().rns_glwe_len()]);
                let workspace = encryptor.workspace.as_mut_slice();
                workspace.fill(73);
                let workspace_pointer = workspace.as_ptr();
                let workspace_length = workspace.len();
                assert!(
                    catch_unwind(AssertUnwindSafe(|| match mode {
                        0 => secret.encrypt_to(&input, &mut output, &mut rng),
                        1 => secret.encrypt_centered_to(&input, &mut output, &mut rng),
                        2 => encryptor.encrypt_to(&input, &mut output, &mut rng),
                        3 => encryptor.encrypt_centered_to(&input, &mut output, &mut rng),
                        4 => {
                            let _ = encryptor.encrypt(&input, &mut rng);
                        }
                        _ => {
                            let _ = encryptor.encrypt_centered(&input, &mut rng);
                        }
                    }))
                    .is_err()
                );
                assert!(output.as_ref().iter().all(|&value| value == 99));
                let workspace = encryptor.workspace.as_mut_slice();
                assert_eq!(workspace.as_ptr(), workspace_pointer);
                assert_eq!(workspace.len(), workspace_length);
                assert!(workspace.iter().all(|&value| value == 73));
                for _ in 0..4 {
                    assert_eq!(rng.next_u64(), reference_rng.next_u64());
                }
            }
        }
    }
}
