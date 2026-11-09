//! Public encryption for unsigned and centered messages using a shared workspace.

use primus_encoding::PlaintextEmbedding;
use primus_glwe::{
    GlweEncryptionParameters, GlweParameters, NttGlweCiphertext, NttGlwePublicEncryptWorkspace,
    NttGlwePublicKey, NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};

const DIMENSION: usize = 2;
// Functional ring size; keep the original word widths, moduli and decomposition.
const POLY_LENGTH: usize = 32;
const PLAIN_MODULUS: u64 = 256;
const CIPHER_MODULUS: u64 = 1_125_899_906_826_241;

#[test]
fn public_key_encoding_modes_reuse_workspace() {
    let modulus = BarrettModulus::new(CIPHER_MODULUS);
    let params = GlweParameters::new(
        GlweDimension::new(DIMENSION),
        PolyLength::new(POLY_LENGTH),
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let table = UintNttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (_, secret_key) = NttGlweSecretKey::generate_pair(
        params.size(),
        params.encryption_parameters(),
        &table,
        &mut rng,
    );
    let public_key = NttGlwePublicKey::generate(
        &secret_key,
        params.encryption_parameters(),
        &table,
        &mut rng,
    );
    let public_key_view = NttGlwePublicKey::from(NttGlweCiphertext::new(public_key.as_ref()));
    // Keep the centered sign boundary and endpoints even when N is smaller than t.
    let message = Polynomial::new(
        (0..POLY_LENGTH)
            .map(|index| {
                [
                    0,
                    1,
                    PLAIN_MODULUS / 2 - 1,
                    PLAIN_MODULUS / 2,
                    PLAIN_MODULUS - 1,
                ][index % 5]
            })
            .collect::<Vec<_>>(),
    );

    let ephemeral = params
        .try_ephemeral_sampler(Some(SecretKeyDistr::SparseTernary))
        .unwrap();
    let mut workspace = NttGlwePublicEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    // The same coins must yield the same ciphertext for explicit encoding and
    // the corresponding plaintext embedding, even after reusing the workspace.
    for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
        let seed = rng.next_u64();
        let mut actual_rng = StdRng::seed_from_u64(seed);
        let mut expected_rng = StdRng::seed_from_u64(seed);
        let mut fresh_workspace = NttGlwePublicEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));
        let expected = public_key.encrypt_message(
            &message,
            &params,
            &ephemeral,
            embedding,
            &table,
            &mut expected_rng,
            &mut fresh_workspace,
        );
        let mut encoded = Polynomial::new(vec![0; POLY_LENGTH]);
        params.plaintext_codec().add_encode_slice_assign(
            encoded.as_mut(),
            message.as_ref(),
            embedding,
        );
        let mut ciphertext: NttGlweCiphertext<Vec<u64>> =
            NttGlweCiphertext::zero(params.glwe_len());
        // Borrowed key/message/output follow the same encoding and RNG oracle.
        public_key_view.encrypt_encoded_to(
            &encoded.as_view(),
            &mut ciphertext.as_mut_view(),
            params.encryption_parameters(),
            &ephemeral,
            &table,
            &mut actual_rng,
            &mut workspace,
        );
        assert_eq!(ciphertext.as_ref(), expected.as_ref());
        assert_eq!(actual_rng.next_u64(), expected_rng.next_u64());
        assert_eq!(
            secret_key
                .decrypt_message(&ciphertext, &params, &table)
                .as_ref(),
            message.as_ref()
        );
    }

    let encrypted_zero = public_key.encrypt_zeros(
        params.encryption_parameters(),
        &ephemeral,
        &table,
        &mut rng,
        &mut workspace,
    );
    assert_eq!(
        secret_key
            .decrypt_message(&encrypted_zero, &params, &table)
            .as_ref(),
        vec![0; POLY_LENGTH]
    );
}

// Raw imported public keys have no size metadata. Reject incomplete masks/body
// and mismatched output before the shared encryption kernel consumes randomness.
#[test]
fn raw_public_encryption_checks_complete_key_and_output_layouts() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let n = POLY_LENGTH;
    let modulus = BarrettModulus::new(CIPHER_MODULUS);
    let inner = GlweEncryptionParameters::new(modulus, SecretKeyDistr::UniformBinary, 0.7);
    let table = UintNttTable::new(PolyLength::new(n), modulus).unwrap();
    let mut workspace = NttGlwePublicEncryptWorkspace::new(PolyLength::new(n));
    let ephemeral = primus_distr::SecretKeySampler::new(SecretKeyDistr::SparseTernary);
    let encoded = Polynomial::new(vec![1; n]);
    for (key_len, output_len) in [
        (0, 2 * n),
        (n, n),
        (2 * n - 1, 2 * n - 1),
        (2 * n + 1, 2 * n + 1),
        (2 * n, 3 * n),
    ] {
        let key = NttGlwePublicKey::from(NttGlweCiphertext::new(vec![1; key_len]));
        for zero in [false, true] {
            let mut output = NttGlweCiphertext::new(vec![7; output_len]);
            let mut rng = StdRng::seed_from_u64(43);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    if zero {
                        key.encrypt_zeros_to(
                            &mut output,
                            &inner,
                            &ephemeral,
                            &table,
                            &mut rng,
                            &mut workspace,
                        );
                    } else {
                        key.encrypt_encoded_to(
                            &encoded,
                            &mut output,
                            &inner,
                            &ephemeral,
                            &table,
                            &mut rng,
                            &mut workspace,
                        );
                    }
                }))
                .is_err()
            );
            assert_eq!(output.as_ref(), vec![7; output_len]);
            assert_eq!(rng.next_u64(), StdRng::seed_from_u64(43).next_u64());
        }
    }
}

/// Independent integer convolution, with sizes small enough for exact i128 products.
fn multiply<T: primus_integer::FheUint>(lhs: &[T], rhs: &[T], q: i128) -> Vec<T> {
    let mut result = vec![0i128; lhs.len()];
    for (i, &a) in lhs.iter().enumerate() {
        let a: u128 = a.as_into();
        for (j, &b) in rhs.iter().enumerate() {
            let b: u128 = b.as_into();
            let degree = i + j;
            result[degree & (lhs.len() - 1)] +=
                a as i128 * b as i128 * if degree < lhs.len() { 1 } else { -1 };
        }
    }
    result
        .into_iter()
        .map(|x| T::as_from(x.rem_euclid(q)))
        .collect()
}

/// Exact b-sum(a_i*s_i), without using production NTT multiplication/decryption.
fn phase<T: primus_integer::FheUint>(ciphertext: &[T], secret: &[T], n: usize, q: i128) -> Vec<T> {
    let mut result: Vec<i128> = ciphertext[secret.len()..]
        .iter()
        .map(|&x| {
            let x: u128 = x.as_into();
            x as i128
        })
        .collect();
    for (a, s) in primus_poly::PolynomialIter::new(&ciphertext[..secret.len()], n)
        .zip(primus_poly::PolynomialIter::new(secret, n))
    {
        for (out, product) in result.iter_mut().zip(multiply(a.as_ref(), s.as_ref(), q)) {
            let product: u128 = product.as_into();
            *out -= product as i128;
        }
    }
    result
        .into_iter()
        .map(|x| T::as_from(x.rem_euclid(q)))
        .collect()
}

/// Fresh r and fresh per-component noise must give exactly r*e_pk+e_b-sum(s_i*e_i).
/// Following reuses only the rank-one sampler; explicit laws describe full N at any rank.
fn check_ephemeral_phase<T: primus_integer::FheUint, Table: NttTable<ValueT = T>>(q: u64) {
    use primus_distr::{BlockOccupancy, SecretKeySampler};
    use primus_reduce::EncodeSigned;
    use rand::distr::Distribution;

    let n = PolyLength::new(32);
    let modulus = BarrettModulus::new(T::as_from(q));
    let table = Table::new(n, modulus).unwrap();
    let secret_law = SecretKeyDistr::BlockBinary {
        block_size: 4,
        occupancy: BlockOccupancy::ExactlyOne,
    };
    for rank in [1, 2] {
        let params = GlweParameters::new(
            GlweDimension::new(rank),
            n,
            T::as_from(2),
            modulus,
            secret_law,
            0.7,
        );
        let mut setup_rng = StdRng::seed_from_u64(60);
        let (secret, transformed) = NttGlweSecretKey::generate_pair(
            params.size(),
            params.encryption_parameters(),
            &table,
            &mut setup_rng,
        );
        let secret_coefficients: Vec<T> = secret
            .as_slice()
            .iter()
            .map(|&s| modulus.encode_signed(s))
            .collect();
        let public = NttGlwePublicKey::generate(
            &transformed,
            params.encryption_parameters(),
            &table,
            &mut setup_rng,
        );
        let mut public_coefficients = public.as_ref().to_vec();
        for mut polynomial in primus_poly::PolynomialIterMut::new(&mut public_coefficients, n.get())
        {
            table.inverse_transform_slice(polynomial.as_mut());
        }
        let public_error = phase(
            &public_coefficients,
            &secret_coefficients,
            n.get(),
            i128::from(q),
        );
        let mut workspace = NttGlwePublicEncryptWorkspace::new(n);
        let message = Polynomial::new((0..n.get()).map(T::as_from).collect::<Vec<_>>());
        for distribution in [
            None,
            Some(SecretKeyDistr::SparseTernary),
            Some(SecretKeyDistr::UniformBinary),
            Some(SecretKeyDistr::BlockBinary {
                block_size: 4,
                occupancy: BlockOccupancy::AtMostOne,
            }),
            Some(SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 3 }),
        ] {
            if rank > 1 && distribution.is_none() {
                assert!(matches!(
                    params.try_ephemeral_sampler(None),
                    Err(primus_glwe::GlweParameterError::EphemeralFollowingRequiresRankOne)
                ));
                continue;
            }
            let sampler = params.try_ephemeral_sampler(distribution).unwrap();
            if distribution.is_none() {
                assert!(std::ptr::eq(sampler.as_ref(), params.secret_key_sampler()));
            }
            let mut rng = StdRng::seed_from_u64(61);
            let mut reference_rng = StdRng::seed_from_u64(61);
            // Keep both streams advancing: the second call cannot reuse the first r.
            for _ in 0..2 {
                let mut output = NttGlweCiphertext::<Vec<T>>::zero(params.glwe_len());
                public.encrypt_encoded_to(
                    &message,
                    &mut output,
                    params.encryption_parameters(),
                    &sampler,
                    &table,
                    &mut rng,
                    &mut workspace,
                );
                let mut r = vec![T::ZERO; n.get()];
                if distribution == Some(SecretKeyDistr::SparseTernary) {
                    primus_distr::sample_sparse_ternary_values_to(
                        &mut r,
                        params.cipher_modulus_minus_one(),
                        &mut reference_rng,
                    );
                } else {
                    sampler.sample_encoded_to(
                        &mut r,
                        params.cipher_modulus_minus_one(),
                        &mut reference_rng,
                    );
                }
                let fresh: Vec<_> = (0..params.glwe_len())
                    .map(|_| params.noise_distribution().sample(&mut reference_rng))
                    .collect();
                let fresh_phase = phase(&fresh, &secret_coefficients, n.get(), i128::from(q));
                let propagated = multiply(&public_error, &r, i128::from(q));
                let expected: Vec<T> = propagated
                    .iter()
                    .zip(&fresh_phase)
                    .zip(message.as_ref())
                    .map(|((&a, &b), &m)| {
                        let a: u128 = a.as_into();
                        let b: u128 = b.as_into();
                        let m: u128 = m.as_into();
                        T::as_from((a + b + m) % u128::from(q))
                    })
                    .collect();
                let coefficients = output.into_coeff_form(&table);
                assert_eq!(
                    phase(
                        coefficients.as_ref(),
                        &secret_coefficients,
                        n.get(),
                        i128::from(q)
                    ),
                    expected
                );
            }
            assert_eq!(rng.next_u64(), reference_rng.next_u64());
        }
        for invalid in [
            SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 33 },
            SecretKeyDistr::BlockBinary {
                block_size: 3,
                occupancy: BlockOccupancy::ExactlyOne,
            },
        ] {
            assert!(params.try_ephemeral_sampler(Some(invalid)).is_err());
        }
        // Raw entry points still reject a wrong whole-N law before RNG or writes.
        let invalid =
            SecretKeySampler::new(SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 33 });
        let mut output = NttGlweCiphertext::new(vec![T::ONE; params.glwe_len()]);
        let mut rng = StdRng::seed_from_u64(62);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                public.encrypt_zeros_to(
                    &mut output,
                    params.encryption_parameters(),
                    &invalid,
                    &table,
                    &mut rng,
                    &mut workspace,
                );
            }))
            .is_err()
        );
        assert_eq!(output.as_ref(), vec![T::ONE; params.glwe_len()]);
        assert_eq!(rng.next_u64(), StdRng::seed_from_u64(62).next_u64());
    }
}

#[test]
fn ephemeral_laws_match_exact_phase_and_preflight() {
    check_ephemeral_phase::<u32, primus_ntt::U32NttTable>(998_244_353);
    check_ephemeral_phase::<u64, primus_ntt::U64NttTable>(CIPHER_MODULUS);
    let params = GlweParameters::new(
        GlweDimension::new(1),
        PolyLength::new(32),
        2,
        BarrettModulus::new(17u32),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    assert!(matches!(
        params.try_ephemeral_sampler(Some(SecretKeyDistr::Gaussian {
            standard_deviation: 10.0
        })),
        Err(primus_glwe::GlweParameterError::SecretKey(
            primus_distr::SecretKeySamplerError::ModulusTooSmall { .. }
        ))
    ));
}
