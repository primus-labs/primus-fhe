//! Native phase and exact recovery checks against integer/DFT arithmetic.
use dashu_int::UBig;
use primus_bgv::{BgvCiphertext, BgvClient, BgvContext, BgvParameters, BgvParametersError};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{
    DcrtGlwePublicKeyWorkspace, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_modulus::BarrettModulus;
use primus_poly::{DcrtPolynomial, Polynomial};
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};
use zeroize::Zeroize;

const N: usize = 32;
const P: u64 = 193;
const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];
fn context(count: usize, error: ErrorDistribution) -> BgvContext {
    BgvContext::try_new(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(N),
            BarrettModulus::new(P),
            &Q[..count]
                .iter()
                .copied()
                .map(BarrettModulus::new)
                .collect::<Vec<_>>(),
            SecretKeyDistr::SparseTernary,
            error,
        )
        .unwrap(),
    )
    .unwrap()
}
fn client<'a>(context: &'a BgvContext, secret: &[i64]) -> BgvClient<'a> {
    let coefficients = GlweSecretKey::new(
        secret.to_vec(),
        context.parameters().size().glwe_size(),
        SecretKeyDistr::SparseTernary,
    );
    BgvClient::try_from_secret_key(
        context,
        DcrtGlweSecretKey::from_coeff_secret_key(&coefficients, context.table()),
    )
    .unwrap()
}
fn mul(a: u64, b: u64, q: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(q)) as u64
}
fn pow(mut a: u64, mut exponent: u64, q: u64) -> u64 {
    let mut value = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            value = mul(value, a, q);
        }
        a = mul(a, a, q);
        exponent >>= 1;
    }
    value
}
fn points(q: u64) -> Vec<u64> {
    // Find and enumerate all primitive 2N-th roots independently of backend tables;
    // the backend's documented convention chooses their smallest representative.
    let witness = (2..)
        .map(|candidate| pow(candidate, (q - 1) / (2 * N) as u64, q))
        .find(|&root| pow(root, N as u64, q) == q - 1)
        .unwrap();
    let root = (0..N)
        .map(|k| pow(witness, (2 * k + 1) as u64, q))
        .min()
        .unwrap();
    (0usize..N)
        .map(|i| {
            pow(
                root,
                (2 * (i.reverse_bits() >> (usize::BITS - 5)) + 1) as u64,
                q,
            )
        })
        .collect()
}
fn phase_oracle(ciphertext: &[u64], secret: &[i64], count: usize) -> Vec<i128> {
    let length = N * count;
    let mut output = Vec::new();
    for (limb, &q) in Q[..count].iter().enumerate() {
        let points = points(q);
        let phase: Vec<_> = points
            .iter()
            .enumerate()
            .map(|(i, &x)| {
                let s = secret.iter().rev().fold(0, |acc, &s| {
                    (mul(acc, x, q) + i128::from(s).rem_euclid(i128::from(q)) as u64) % q
                });
                (ciphertext[limb * N + i] + mul(ciphertext[length + limb * N + i], s, q)) % q
            })
            .collect();
        for degree in 0..N {
            let sum = points.iter().zip(&phase).fold(0, |acc, (&point, &phase)| {
                (acc + mul(phase, pow(point, q - 1 - degree as u64, q), q)) % q
            });
            let coefficient = mul(sum, pow(N as u64, q - 2, q), q);
            output.push(if coefficient > q / 2 {
                i128::from(coefficient) - i128::from(q)
            } else {
                i128::from(coefficient)
            });
        }
    }
    output
}
fn product(a: &[i128], b: &[i128]) -> Vec<i128> {
    let mut out = vec![0; N];
    for (i, &a) in a.iter().enumerate() {
        for (j, &b) in b.iter().enumerate() {
            let k = i + j;
            if k < N {
                out[k] += a * b;
            } else {
                out[k - N] -= a * b;
            }
        }
    }
    out
}

#[test]
fn private_native_phase_has_one_shared_p_scaled_error_for_all_limbs() {
    let secret: Vec<_> = (0..N).map(|i| [-1, 0, 1][i % 3]).collect();
    for error in [
        ErrorDistribution::CenteredBinomial { eta: 1 },
        ErrorDistribution::CenteredBinomial { eta: 21 },
        ErrorDistribution::Gaussian {
            standard_deviation: 3.2,
        },
    ] {
        for count in [1, 2, 3] {
            let context = context(count, error);
            let mut client = client(&context, &secret);
            let message = Polynomial(
                (0..N)
                    .map(|i| [0, 1, P / 2, P / 2 + 1, P - 1][i % 5])
                    .collect::<Vec<_>>(),
            );
            for centered in [false, true] {
                let mut rng = StdRng::seed_from_u64(0x42475601);
                let mut coins = StdRng::seed_from_u64(0x42475601);
                let mut errors = vec![0i64; N];
                context
                    .parameters()
                    .encryption_parameters()
                    .noise_distribution()
                    .sample_signed_to(&mut errors, &mut coins);
                let mut ciphertext = context.new_ciphertext();
                if centered {
                    client.encrypt_centered_to(&message, &mut ciphertext, &mut rng);
                } else {
                    client.encrypt_to(&message.as_view(), &mut ciphertext.as_mut_view(), &mut rng);
                }
                let phase = phase_oracle(ciphertext.as_ref(), &secret, count);
                for limb in phase.as_chunks::<N>().0.iter() {
                    for ((&actual, &m), &e) in limb.iter().zip(message.as_ref()).zip(&errors) {
                        let m = if centered && m > P / 2 {
                            i128::from(m) - i128::from(P)
                        } else {
                            i128::from(m)
                        };
                        assert_eq!(actual, m + i128::from(P) * i128::from(e));
                    }
                }
                assert_eq!(client.decrypt(&ciphertext), message);
            }
        }
    }
}

#[test]
fn public_key_and_public_encryption_use_p_scaled_error_and_full_ring_secret() {
    let context = context(3, ErrorDistribution::CenteredBinomial { eta: 21 });
    let secret: Vec<_> = (0..N).map(|i| [-1, 1, 0, 1, 0][i % 5]).collect();
    let mut client = client(&context, &secret);
    let mut setup_rng = StdRng::seed_from_u64(333);
    let key = client.public_key(&mut setup_rng);
    let pkphase = phase_oracle(key.ciphertext().as_ref(), &secret, 3);
    let pkerror: Vec<_> = pkphase[..N]
        .iter()
        .map(|&x| {
            assert_eq!(x % i128::from(P), 0);
            x / i128::from(P)
        })
        .collect();
    assert!(pkerror.iter().all(|&e| e.abs() <= 21));
    let mut encryptor = context.public_key_encryptor(&key).unwrap();
    let mut rng = StdRng::seed_from_u64(99);
    let mut coins = StdRng::seed_from_u64(99);
    let mut r = Vec::new();
    for _ in 0..N / 16 {
        let word = coins.next_u32();
        for j in 0..16 {
            r.push([0, 0, 1, -1][((word >> (2 * j)) & 3) as usize]);
        }
    }
    let mut e0 = vec![0i64; N];
    let mut e1 = vec![0i64; N];
    let sampler = context
        .parameters()
        .encryption_parameters()
        .noise_distribution();
    sampler.sample_signed_to(&mut e0, &mut coins);
    sampler.sample_signed_to(&mut e1, &mut coins);
    let first = product(&pkerror, &r);
    let second = product(
        &e1.iter().map(|&e| i128::from(e)).collect::<Vec<_>>(),
        &secret.iter().map(|&s| i128::from(s)).collect::<Vec<_>>(),
    );
    let message = Polynomial(
        (0..N)
            .map(|i| if i % 3 == 0 { P - 1 } else { i as u64 })
            .collect::<Vec<_>>(),
    );
    let mut ciphertext = context.new_ciphertext();
    encryptor.encrypt_centered_to(&message, &mut ciphertext, &mut rng);
    assert_eq!(rng.next_u64(), coins.next_u64());
    for limb in phase_oracle(ciphertext.as_ref(), &secret, 3)
        .as_chunks::<N>()
        .0
        .iter()
    {
        for i in 0..N {
            let m = if message.as_ref()[i] > P / 2 {
                i128::from(message.as_ref()[i]) - i128::from(P)
            } else {
                i128::from(message.as_ref()[i])
            };
            assert_eq!(
                limb[i],
                m + i128::from(P) * (first[i] + i128::from(e0[i]) + second[i])
            );
        }
    }
    assert_eq!(client.decrypt(&ciphertext), message);
    encryptor.workspace_mut().zeroize();
    encryptor.encrypt_to(&message, &mut ciphertext, &mut rng);
    assert_eq!(client.decrypt(&ciphertext), message);
}

#[test]
fn exact_centered_recovery_handles_150_bit_q_and_half_interval_boundaries() {
    let context = context(3, ErrorDistribution::CenteredBinomial { eta: 1 });
    let secret = vec![1; N];
    let mut client = client(&context, &secret);
    let q = Q.into_iter().map(UBig::from).reduce(|a, b| a * b).unwrap();
    assert!(q > UBig::from(u128::MAX));
    let half = &q / UBig::from(2u8);
    let cases = [
        UBig::from(0u8),
        UBig::from(1u8),
        &half - UBig::from(1u8),
        half.clone(),
        &half + UBig::from(1u8),
        &q - UBig::from(1u8),
        &q - UBig::from(P),
    ];
    let values: Vec<_> = (0..N).map(|i| cases[i % cases.len()].clone()).collect();
    let expected = Polynomial(
        values
            .iter()
            .map(|x| {
                let residue = u64::try_from(x % UBig::from(P)).unwrap();
                if x > &half {
                    (residue + P - u64::try_from(&q % UBig::from(P)).unwrap()) % P
                } else {
                    residue
                }
            })
            .collect::<Vec<_>>(),
    );
    let mut ciphertext = context.new_ciphertext();
    let (mut c0, _) = ciphertext.c0_c1_mut(context.rns_poly_len());
    for (limb, &prime) in c0.as_mut().as_chunks_mut::<N>().0.iter_mut().zip(&Q) {
        for (out, x) in limb.iter_mut().zip(&values) {
            *out = u64::try_from(x % UBig::from(prime)).unwrap();
        }
    }
    context.table().transform_slice(c0.as_mut());
    let c0_expected = c0.as_ref().to_vec();
    assert_eq!(client.decrypt(&ciphertext), expected);
    assert_eq!(expected.as_ref()[5], P - 1); // canonical Q-1 modulo p is zero; centered phase is -1.
    let mut phase = DcrtPolynomial::<Vec<u64>>::zero(context.rns_poly_len());
    client.phase_to(&ciphertext, &mut phase);
    assert_eq!(phase.as_ref(), c0_expected);
}

#[test]
fn invalid_geometry_moduli_and_plaintext_are_rejected_before_writes_or_rng() {
    let moduli = Q[..1]
        .iter()
        .copied()
        .map(BarrettModulus::new)
        .collect::<Vec<_>>();
    assert!(matches!(
        BgvParameters::try_coefficients(
            PolyLength::new(N),
            BarrettModulus::new(17),
            &moduli,
            SecretKeyDistr::SparseTernary,
            1.0
        ),
        Err(BgvParametersError::PrimeCongruence { .. })
    ));
    let context = context(1, ErrorDistribution::CenteredBinomial { eta: 1 });
    let mut rng = StdRng::seed_from_u64(2);
    let client = BgvClient::generate(&context, &mut rng);
    let invalid = Polynomial(vec![P; N]);
    let mut output = context.new_ciphertext();
    output.as_mut().fill(77);
    let mut rng = StdRng::seed_from_u64(3);
    let mut expected_rng = StdRng::seed_from_u64(3);
    assert!(
        catch_unwind(AssertUnwindSafe(|| client.encrypt_to(
            &invalid,
            &mut output,
            &mut rng
        )))
        .is_err()
    );
    assert!(output.as_ref().iter().all(|&x| x == 77));
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
    let valid = Polynomial(vec![1u64; N]);
    let mut short = BgvCiphertext::new(vec![77; 2 * context.rns_poly_len() - 1]);
    let mut rng = StdRng::seed_from_u64(4);
    let mut expected_rng = StdRng::seed_from_u64(4);
    assert!(
        catch_unwind(AssertUnwindSafe(
            || client.encrypt_to(&valid, &mut short, &mut rng)
        ))
        .is_err()
    );
    assert!(short.as_ref().iter().all(|&x| x == 77));
    assert_eq!(rng.next_u64(), expected_rng.next_u64());

    let public = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public).unwrap();
    let wrong_rank = RnsGlweSize::try_new(
        GlweSize::try_new(GlweDimension::new(2), PolyLength::new(N)).unwrap(),
        1,
    )
    .unwrap();
    for size in [
        self::context(2, ErrorDistribution::CenteredBinomial { eta: 1 })
            .parameters()
            .size(),
        wrong_rank, // Same ephemeral length, but a different complete geometry.
    ] {
        *encryptor.workspace_mut() = DcrtGlwePublicKeyWorkspace::new(size);
        encryptor.workspace_mut().as_mut_slice().fill(55);
        output.as_mut().fill(77);
        let mut rng = StdRng::seed_from_u64(5);
        let mut expected_rng = StdRng::seed_from_u64(5);
        assert!(
            catch_unwind(AssertUnwindSafe(|| encryptor.encrypt_to(
                &valid,
                &mut output,
                &mut rng
            )))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&x| x == 77));
        assert!(
            encryptor
                .workspace_mut()
                .as_mut_slice()
                .iter()
                .all(|&x| x == 55)
        );
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}

#[test]
fn public_binding_rejects_different_plaintext_error_scale_on_the_same_basis() {
    use primus_bgv::BgvPublicKeyError;
    let context = context(1, ErrorDistribution::CenteredBinomial { eta: 1 });
    let mut rng = StdRng::seed_from_u64(45);
    let client = BgvClient::generate(&context, &mut rng);
    let public = client.public_key(&mut rng);
    let other = BgvContext::try_new(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(N),
            BarrettModulus::new(2),
            &[BarrettModulus::new(Q[0])],
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        other.public_key_encryptor(&public),
        Err(BgvPublicKeyError::PlainModulus {
            expected: 2,
            actual: P
        })
    ));
}

#[test]
fn centered_embedding_maps_the_even_plaintext_half_to_a_negative_integer() {
    let p = 2;
    let context = BgvContext::try_new(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(N),
            BarrettModulus::new(p),
            &[BarrettModulus::new(Q[0])],
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
    )
    .unwrap();
    let secret = vec![1; N];
    let mut client = client(&context, &secret);
    let message = Polynomial(vec![p / 2; N]);
    let mut ciphertext = context.new_ciphertext();
    let mut rng = StdRng::seed_from_u64(823);
    let mut coins = StdRng::seed_from_u64(823);
    let mut errors = vec![0i64; N];
    context
        .parameters()
        .encryption_parameters()
        .noise_distribution()
        .sample_signed_to(&mut errors, &mut coins);
    client.encrypt_centered_to(&message, &mut ciphertext, &mut rng);
    let phase = phase_oracle(ciphertext.as_ref(), &secret, 1);
    for (&actual, &error) in phase.iter().zip(&errors) {
        assert_eq!(actual, -1 + i128::from(p) * i128::from(error));
    }
    assert_eq!(client.decrypt(&ciphertext), message);
}
