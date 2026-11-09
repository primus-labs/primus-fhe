//! Native phase and exact recovery checks against integer/DFT arithmetic.
use crate::{BgvClient, BgvContext, BgvParameters};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{
    DcrtGlwePublicKeyWorkspace, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
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
        BgvParameters::try_coefficients(
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
fn public_key_and_public_encryption_use_p_scaled_error_and_full_ring_secret() {
    let context = context(3, ErrorDistribution::CenteredBinomial { eta: 21 });
    let secret: Vec<_> = (0..N).map(|i| [-1, 1, 0, 1, 0][i % 5]).collect();
    let mut client = client(&context, &secret);
    let mut setup_rng = StdRng::seed_from_u64(333);
    let key = client.public_key(&mut setup_rng);
    let pkphase = phase_oracle(key.ciphertext.as_ref(), &secret, 3);
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
    let mut ciphertext = context.new_ciphertext(0);
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
    assert_eq!(client.decrypt_at_level(&ciphertext, 0), message);
    let ephemeral_pointer = encryptor.workspace.as_mut_slice().as_ptr();
    let ephemeral_length = encryptor.workspace.as_mut_slice().len();
    encryptor.zeroize();
    assert_eq!(
        encryptor.workspace.as_mut_slice().as_ptr(),
        ephemeral_pointer
    );
    assert_eq!(encryptor.workspace.as_mut_slice().len(), ephemeral_length);
    assert!(
        encryptor
            .workspace
            .as_mut_slice()
            .iter()
            .all(|&value| value == 0)
    );
    encryptor.encrypt_to(&message, &mut ciphertext, &mut rng);
    assert_eq!(client.decrypt_at_level(&ciphertext, 0), message);
}

#[test]
fn malformed_private_workspace_is_rejected_before_writes_or_rng() {
    let context = context(1, ErrorDistribution::CenteredBinomial { eta: 1 });
    let mut rng = StdRng::seed_from_u64(2);
    let client = BgvClient::generate(&context, &mut rng);
    let public = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public).unwrap();
    let valid = Polynomial(vec![1u64; N]);
    let mut output = context.new_ciphertext(0);
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
        encryptor.workspace = DcrtGlwePublicKeyWorkspace::new(size);
        encryptor.workspace.as_mut_slice().fill(55);
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
        assert!(encryptor.workspace.as_mut_slice().iter().all(|&x| x == 55));
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}
