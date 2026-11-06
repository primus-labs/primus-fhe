//! Scheme-boundary identities and independent integer/DFT recovery oracles.

use primus_bfv::{
    BfvCiphertext, BfvContext, BfvDecryptWorkspace, BfvParameters, BfvPublicKey,
    BfvPublicKeyEncryptor, BfvSecretKeyContext,
};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweCiphertext, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::{CrtPolynomial, DcrtPolynomial, Polynomial};
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
fn private_embeddings_apply_delta_once_and_match_exact_recovery() {
    for (count, t, error) in [
        (1, 2, ErrorDistribution::CenteredBinomial { eta: 1 }),
        (
            1,
            254,
            ErrorDistribution::Gaussian {
                standard_deviation: 3.2,
            },
        ),
        (2, 257, ErrorDistribution::CenteredBinomial { eta: 1 }),
        (2, 12_289, ErrorDistribution::CenteredBinomial { eta: 21 }),
    ] {
        let parameters = parameters(count, t, error);
        let owner = BfvContext::try_new(parameters).unwrap();
        let parameters = owner.parameters();
        let table = owner.table();
        let secret: Vec<i64> = (0..N).map(|index| [-1, 0, 1][index % 3]).collect();
        let coefficient_key = GlweSecretKey::new(
            secret.clone(),
            parameters.size().glwe_size(),
            SecretKeyDistr::SparseTernary,
        );
        let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, table);
        let context = BfvSecretKeyContext::try_new(&key, &owner).unwrap();
        let message = Polynomial(
            (0..N)
                .map(|index| [0, 1, t / 2, (t / 2 + 1).min(t - 1), t - 1][index % 5])
                .collect::<Vec<_>>(),
        );
        let mut ciphertext = BfvCiphertext::<Vec<u64>>::zero_raw(parameters.size().rns_glwe_len());
        let mut expected_ciphertext = ciphertext.clone();
        let mut workspace = BfvDecryptWorkspace::new(parameters);
        for centered in [false, true] {
            let mut rng = StdRng::seed_from_u64(0x4246_5601);
            let mut expected_rng = StdRng::seed_from_u64(0x4246_5601);
            if centered {
                context.encrypt_centered_to(&message, &mut ciphertext, &mut rng);
            } else {
                context.encrypt_to(&message.as_view(), &mut ciphertext.as_mut_view(), &mut rng);
            }
            let encoded = independently_encoded(message.as_ref(), count, t, centered);
            context.encrypt_encoded_crt_to(
                &CrtPolynomial(&encoded[..]),
                &mut expected_ciphertext,
                &mut expected_rng,
            );
            assert_eq!(ciphertext.as_ref(), expected_ciphertext.as_ref());
            assert_eq!(rng.next_u64(), expected_rng.next_u64());

            let phase = phase_oracle(ciphertext.as_ref(), &secret, count);
            let product: u128 = Q[..count].iter().map(|&q| u128::from(q)).product();
            for (degree, &m) in message.as_ref().iter().enumerate() {
                let actual = compose(&phase, degree, count);
                let encoded = compose(&encoded, degree, count);
                let residual = (actual + product - encoded) % product;
                let magnitude = residual.min(product - residual);
                assert!(
                    magnitude
                        <= u128::from(
                            parameters
                                .encryption_parameters()
                                .noise_distribution()
                                .maximum_magnitude()
                        )
                );
                let exact_decoded =
                    ((u128::from(t) * actual + product / 2) / product) % u128::from(t);
                assert_eq!(exact_decoded, u128::from(m));
            }
            assert_eq!(context.decrypt(&ciphertext, &mut workspace), message);
            workspace.zeroize();
            assert_eq!(context.decrypt(&ciphertext, &mut workspace), message);

            if centered {
                // Explicit centered CRT lifts, without codec or delta, must
                // match the centered coefficient entry with the same coins.
                let lifted = CrtPolynomial(
                    Q[..count]
                        .iter()
                        .flat_map(|&q| {
                            message
                                .as_ref()
                                .iter()
                                .map(move |&m| if m >= t.div_ceil(2) { q - (t - m) } else { m })
                        })
                        .collect::<Vec<_>>(),
                );
                let mut rng = StdRng::seed_from_u64(0x4246_5601);
                context.encrypt_plaintext_lift_crt_to(
                    &lifted.as_view(),
                    &mut expected_ciphertext.as_mut_view(),
                    &mut rng,
                );
                assert_eq!(ciphertext.as_ref(), expected_ciphertext.as_ref());
            }
        }
    }
}

#[test]
fn plaintext_product_keeps_bfv_scaling() {
    let parameters = parameters(2, 257, ErrorDistribution::CenteredBinomial { eta: 21 });
    let owner = BfvContext::try_new(parameters).unwrap();
    let parameters = owner.parameters();
    let table = owner.table();
    let mut rng = StdRng::seed_from_u64(81);
    let key = GlweSecretKey::generate(
        parameters.size().glwe_size(),
        parameters.encryption_parameters().secret_key_sampler(),
        &mut rng,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&key, table);
    let context = BfvSecretKeyContext::try_new(&key, &owner).unwrap();
    let message = Polynomial(
        (0..N)
            .map(|index| (index * 7 % 257) as u64)
            .collect::<Vec<_>>(),
    );
    let multiplier = Polynomial(
        (0..N)
            .map(|index| u64::from(index % 5 == 0))
            .collect::<Vec<_>>(),
    );
    let mut multiplier_ntt = Q
        .iter()
        .flat_map(|_| multiplier.as_ref().iter().copied())
        .collect::<Vec<_>>();
    table.transform_slice(&mut multiplier_ntt);
    let mut input = BfvCiphertext::<Vec<u64>>::zero_raw(parameters.size().rns_glwe_len());
    let mut output = input.clone();
    context.encrypt_to(&message, &mut input, &mut rng);
    // This representation test applies plaintext multiplication directly to
    // both native components; it does not introduce a BFV evaluator API.
    for (input_component, output_component) in input
        .as_ref()
        .chunks_exact(parameters.size().rns_poly_len())
        .zip(
            output
                .as_mut()
                .chunks_exact_mut(parameters.size().rns_poly_len()),
        )
    {
        DcrtPolynomial(input_component).mul_to(
            &DcrtPolynomial(&multiplier_ntt[..]),
            &mut DcrtPolynomial(output_component),
            N,
            parameters.base_q().moduli(),
        );
    }
    let mut expected = vec![0i128; N];
    for (i, &left) in message.as_ref().iter().enumerate() {
        for (j, &right) in multiplier.as_ref().iter().enumerate() {
            expected[(i + j) % N] +=
                i128::from(left) * i128::from(right) * if i + j < N { 1 } else { -1 };
        }
    }
    let expected: Vec<_> = expected
        .into_iter()
        .map(|value| value.rem_euclid(257) as u64)
        .collect();
    assert_eq!(
        context
            .decrypt(&output, &mut BfvDecryptWorkspace::new(parameters))
            .as_ref(),
        expected
    );
}

#[test]
fn invalid_complete_layouts_are_rejected_before_randomness_or_output_writes() {
    let parameters = parameters(2, 257, ErrorDistribution::CenteredBinomial { eta: 1 });
    let owner = BfvContext::try_new(parameters).unwrap();
    let parameters = owner.parameters();
    let table = owner.table();
    let mut setup_rng = StdRng::seed_from_u64(82);
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
    for length in [0, N - 1, N + 1] {
        let input = Polynomial(vec![0; length]);
        for mode in 0..4 {
            let mut rng = StdRng::seed_from_u64(83);
            let mut reference_rng = StdRng::seed_from_u64(83);
            let mut output = BfvCiphertext::from_raw(vec![99; parameters.size().rns_glwe_len()]);
            assert!(
                catch_unwind(AssertUnwindSafe(|| match mode {
                    0 => secret.encrypt_to(&input, &mut output, &mut rng),
                    1 => secret.encrypt_centered_to(&input, &mut output, &mut rng),
                    2 => encryptor.encrypt_to(&input, &mut output, &mut rng),
                    _ => encryptor.encrypt_centered_to(&input, &mut output, &mut rng),
                }))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&value| value == 99));
            assert_eq!(rng.next_u64(), reference_rng.next_u64());
        }
    }
    for length in [
        0,
        parameters.size().rns_poly_len() - 1,
        parameters.size().rns_poly_len() + 1,
    ] {
        let input = CrtPolynomial(vec![0; length]);
        let mut rng = StdRng::seed_from_u64(84);
        let mut reference_rng = StdRng::seed_from_u64(84);
        let mut output = BfvCiphertext::from_raw(vec![99; parameters.size().rns_glwe_len()]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| secret.encrypt_plaintext_lift_crt_to(
                &input,
                &mut output,
                &mut rng
            )))
            .is_err()
        );
        assert!(
            catch_unwind(AssertUnwindSafe(
                || encryptor.encrypt_plaintext_lift_crt_to(&input, &mut output, &mut rng)
            ))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 99));
        assert_eq!(rng.next_u64(), reference_rng.next_u64());
    }
    let input = Polynomial(vec![0; N]);
    let mut rng = StdRng::seed_from_u64(85);
    let mut reference_rng = StdRng::seed_from_u64(85);
    let mut output = BfvCiphertext::from_raw(vec![99; parameters.size().rns_glwe_len() - 1]);
    assert!(
        catch_unwind(AssertUnwindSafe(|| secret.encrypt_to(
            &input,
            &mut output,
            &mut rng
        )))
        .is_err()
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| encryptor.encrypt_to(
            &input,
            &mut output,
            &mut rng
        )))
        .is_err()
    );
    assert_eq!(rng.next_u64(), reference_rng.next_u64());
    assert!(output.as_ref().iter().all(|&value| value == 99));

    let reversed = [BarrettModulus::new(Q[1]), BarrettModulus::new(Q[0])];
    let wrong_table = U64DcrtTable::new(parameters.poly_length(), &reversed).unwrap();
    assert!(
        BfvContext::try_with_table(parameters.clone(), 1, std::sync::Arc::new(wrong_table))
            .is_err()
    );
    let foreign_context = BfvContext::try_new(
        BfvParameters::try_with_error_distribution(
            parameters.poly_length(),
            BarrettModulus::new(257),
            BarrettModulus::new(2_199_023_190_017),
            &reversed,
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
    )
    .unwrap();
    assert!(BfvSecretKeyContext::try_new(&key, &foreign_context).is_err());
    assert!(BfvPublicKeyEncryptor::try_new(&public, &foreign_context).is_err());
    let foreign = parameters_with_length(64);
    let mut workspace = BfvDecryptWorkspace::new(&foreign);
    let ciphertext = BfvCiphertext::<Vec<u64>>::zero_raw(parameters.size().rns_glwe_len());
    let mut plaintext = Polynomial(vec![99; N]);
    assert!(
        catch_unwind(AssertUnwindSafe(|| secret.decrypt_to(
            &ciphertext,
            &mut plaintext,
            &mut workspace
        )))
        .is_err()
    );
    assert_eq!(plaintext.as_ref(), vec![99; N]);

    let mut workspace = BfvDecryptWorkspace::new(parameters);
    let mut short_plaintext = Polynomial(vec![99; N - 1]);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            secret.decrypt_to(&ciphertext, &mut short_plaintext, &mut workspace)
        }))
        .is_err()
    );
    assert_eq!(short_plaintext.as_ref(), vec![99; N - 1]);

    let short_ciphertext =
        BfvCiphertext::<Vec<u64>>::zero_raw(parameters.size().rns_glwe_len() - 1);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            secret.decrypt_to(&short_ciphertext, &mut plaintext, &mut workspace)
        }))
        .is_err()
    );
    assert_eq!(plaintext.as_ref(), vec![99; N]);
}

fn parameters_with_length(n: usize) -> BfvParameters {
    BfvParameters::try_new(
        PolyLength::new(n),
        BarrettModulus::new(257),
        BarrettModulus::new(2_199_023_190_017),
        &Q.map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        3.2,
    )
    .unwrap()
}

#[test]
fn native_components_preserve_the_actual_binary_secret_and_explicit_raw_bridge() {
    let parameters = BfvParameters::try_with_error_distribution(
        PolyLength::new(N),
        BarrettModulus::new(257),
        BarrettModulus::new(2_199_023_190_017),
        &Q.map(BarrettModulus::new),
        SecretKeyDistr::UniformBinary,
        ErrorDistribution::CenteredBinomial { eta: 1 },
    )
    .unwrap();
    let owner = BfvContext::try_new(parameters).unwrap();
    let parameters = owner.parameters();
    let table = owner.table();
    let secret: Vec<i64> = (0..N).map(|index| i64::from(index % 3 == 0)).collect();
    let coefficient_key = GlweSecretKey::new(
        secret.clone(),
        parameters.size().glwe_size(),
        SecretKeyDistr::UniformBinary,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, table);
    let context = BfvSecretKeyContext::try_new(&key, &owner).unwrap();
    let message = Polynomial((0..N).map(|i| (i * 13 % 257) as u64).collect::<Vec<_>>());
    let mut ciphertext = BfvCiphertext::zero_raw(parameters.size().rns_glwe_len());
    context.encrypt_to(
        &message,
        &mut ciphertext,
        &mut StdRng::seed_from_u64(0x4246_5630),
    );
    let phase = phase_oracle(ciphertext.as_ref(), &secret, 2);
    let encoded = independently_encoded(message.as_ref(), 2, 257, false);
    for degree in 0..N {
        let product = u128::from(Q[0]) * u128::from(Q[1]);
        let residual =
            (compose(&phase, degree, 2) + product - compose(&encoded, degree, 2)) % product;
        assert!(residual.min(product - residual) <= 1);
    }
    // Negating an asymmetric {0,1} secret would change the declared secret law
    // and gives a large error under this independent c0+c1*s oracle.
    let flipped: Vec<_> = secret.iter().map(|&value| -value).collect();
    assert_ne!(phase_oracle(ciphertext.as_ref(), &flipped, 2), phase);
    let mut raw = DcrtGlweCiphertext::<Vec<u64>>::zero(parameters.size().rns_glwe_len());
    ciphertext.write_raw_glwe_to(&mut raw, parameters);
    let length = parameters.size().rns_poly_len();
    for (limb, &q) in Q.iter().enumerate() {
        for i in 0..N {
            assert_eq!(
                raw.as_ref()[length + limb * N + i],
                ciphertext.as_ref()[limb * N + i]
            );
            assert_eq!(
                raw.as_ref()[limb * N + i],
                (q - ciphertext.as_ref()[length + limb * N + i]) % q
            );
        }
    }
    let mut recovered = BfvCiphertext::zero_raw(parameters.size().rns_glwe_len());
    recovered.set_from_raw_glwe(&raw, parameters);
    assert_eq!(recovered, ciphertext);
    let mut raw_phase = DcrtPolynomial::<Vec<u64>>::zero(length);
    key.phase_to(&raw, &mut raw_phase, parameters.base_q().moduli());
    table.inverse_transform_slice(raw_phase.as_mut());
    assert_eq!(raw_phase.as_ref(), phase);
}

#[test]
fn encoded_phase_entry_does_not_apply_delta_again() {
    let parameters = parameters(1, 257, ErrorDistribution::CenteredBinomial { eta: 1 });
    let owner = BfvContext::try_new(parameters).unwrap();
    let parameters = owner.parameters();
    let table = owner.table();
    let key = GlweSecretKey::new(
        vec![0i64; N],
        parameters.size().glwe_size(),
        SecretKeyDistr::UniformBinary,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&key, table);
    let context = BfvSecretKeyContext::try_new(&key, &owner).unwrap();
    let message = Polynomial(vec![3; N]);
    let encoded = CrtPolynomial(independently_encoded(message.as_ref(), 1, 257, false));
    let mut proper = BfvCiphertext::zero_raw(parameters.size().rns_glwe_len());
    let mut wrong = proper.clone();
    context.encrypt_encoded_crt_to(&encoded, &mut proper, &mut StdRng::seed_from_u64(27));
    context.encrypt_plaintext_lift_crt_to(&encoded, &mut wrong, &mut StdRng::seed_from_u64(27));
    let mut workspace = BfvDecryptWorkspace::new(parameters);
    assert_eq!(context.decrypt(&proper, &mut workspace), message);
    assert_ne!(context.decrypt(&wrong, &mut workspace), message);
}
