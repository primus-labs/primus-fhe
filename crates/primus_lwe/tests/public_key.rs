//! Small functional dimensions include vector blocks and incomplete tails.
use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lattice::lwe::Lwe;
use primus_lwe::{
    LweKeySwitchingKey, LweKeySwitchingParameters, LweParameters, LwePublicKey, LweSecretKey,
    SecretKeyDistr,
};
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_reduce::RingContext;
use rand::{Rng, SeedableRng, distr::Distribution, rngs::StdRng};

fn centered(value: i128, q: i128) -> i128 {
    if value > q / 2 { value - q } else { value }
}

fn check_equations<T: FheUint, M: RingContext<T>>(modulus: M) {
    let q = modulus
        .explicit_value()
        .map_or(1i128 << T::BITS, |q| q.as_into());
    for (dimension, distribution, noise_sigma) in [
        (1, SecretKeyDistr::UniformBinary, 3.2),
        (7, SecretKeyDistr::UniformTernary, 3.2),
        (65, SecretKeyDistr::gaussian(2.0), 3.2),
        (7, SecretKeyDistr::UniformTernary, 30.0),
    ] {
        // These are arithmetic fixtures, not evaluated security parameters.
        let params = LweParameters::new(
            LweDimension::new(dimension),
            T::as_from(4u32),
            modulus,
            distribution,
            noise_sigma,
        );
        let mut key_rng = StdRng::seed_from_u64(0x1_ee10);
        let secret = LweSecretKey::generate(params.encryption_parameters(), &mut key_rng);
        let signed_secret: Vec<i128> = secret
            .as_ref()
            .iter()
            .map(|&s| centered(s.as_into(), q))
            .collect();
        let mut rng = StdRng::seed_from_u64(0x1_ee11);
        let key = LwePublicKey::generate(
            secret.as_view(),
            params.dimension(),
            params.cipher_modulus(),
            params.cipher_modulus_uniform_distr(),
            params.noise_distribution(),
            &mut rng,
        );
        assert_eq!(key.dimension(), LweDimension::new(dimension));
        assert_eq!(key.as_slice().len(), dimension * (dimension + 1));

        // Verify the stored rows against independent integer arithmetic, including
        // the sign of the key-generation error and the interleaved body layout.
        let mut oracle_rng = StdRng::seed_from_u64(0x1_ee11);
        let mut key_errors = Vec::new();
        for row in key.as_slice().chunks_exact(dimension + 1) {
            for &a in &row[..dimension] {
                assert_eq!(
                    a,
                    params
                        .cipher_modulus_uniform_distr()
                        .sample(&mut oracle_rng)
                );
            }
            let error = centered(
                params
                    .noise_distribution()
                    .sample(&mut oracle_rng)
                    .as_into(),
                q,
            );
            key_errors.push(error);
            let dot: i128 = row[..dimension]
                .iter()
                .zip(&signed_secret)
                .map(|(&a, &s)| {
                    let a: i128 = a.as_into();
                    a * s
                })
                .sum();
            assert_eq!(row[dimension], T::as_from((dot + error).rem_euclid(q)));
        }

        for plaintext in [T::ZERO, T::as_from(q - 1)] {
            let plaintext_value: i128 = plaintext.as_into();
            let mut rng = StdRng::seed_from_u64(0x1_ee12);
            let mut output_rng = StdRng::seed_from_u64(0x1_ee12);
            let mut oracle_rng = StdRng::seed_from_u64(0x1_ee12);
            let ciphertext =
                key.encrypt_encoded(plaintext, modulus, params.noise_distribution(), &mut rng);
            let mut storage = vec![T::MAX; dimension + 3];
            key.encrypt_encoded_to(
                plaintext,
                &mut Lwe::new(&mut storage[1..dimension + 2]),
                modulus,
                params.noise_distribution(),
                &mut output_rng,
            );
            assert_eq!(&storage[1..dimension + 2], ciphertext.as_ref());
            assert_eq!(storage[0], T::MAX);
            assert_eq!(storage[dimension + 2], T::MAX);

            let fresh_errors: Vec<i128> = (0..=dimension)
                .map(|_| {
                    centered(
                        params
                            .noise_distribution()
                            .sample(&mut oracle_rng)
                            .as_into(),
                        q,
                    )
                })
                .collect();
            let mut expected = fresh_errors.clone();
            expected[dimension] += plaintext_value;
            let mut total_error = fresh_errors[dimension]
                - fresh_errors[..dimension]
                    .iter()
                    .zip(&signed_secret)
                    .map(|(&e, &s)| e * s)
                    .sum::<i128>();
            let words: Vec<u32> = (0..dimension.div_ceil(16))
                .map(|_| oracle_rng.next_u32())
                .collect();
            for (i, (row, &error)) in key
                .as_slice()
                .chunks_exact(dimension + 1)
                .zip(&key_errors)
                .enumerate()
            {
                // Independent spelling of Pr[0] = 1/2, Pr[+/-1] = 1/4.
                let r = match (words[i / 16] >> (2 * (i % 16))) & 3 {
                    0 | 1 => 0,
                    2 => 1,
                    _ => -1,
                };
                for (acc, &a) in expected.iter_mut().zip(row) {
                    let a: i128 = a.as_into();
                    *acc += a * r;
                }
                total_error += error * r;
            }
            for (&actual, expected) in ciphertext.as_ref().iter().zip(expected) {
                assert_eq!(actual, T::as_from(expected.rem_euclid(q)));
                let actual: i128 = actual.as_into();
                assert!(actual < q);
            }
            assert_eq!(
                secret.as_view().decrypt_phase(&ciphertext, modulus),
                T::as_from((plaintext_value + total_error).rem_euclid(q))
            );
            assert_eq!(rng.next_u64(), oracle_rng.next_u64());
        }
    }
}

#[test]
fn public_key_encryption_matches_matrix_and_noise_equations() {
    check_equations(NativeModulus::<u32>::new());
    check_equations(NativeModulus::<u64>::new());
    check_equations(PowOf2Modulus::new(1u32 << 30));
    check_equations(PowOf2Modulus::new(1u64 << 50));
    check_equations(BarrettModulus::new(132_120_577u32));
    check_equations(BarrettModulus::new(1_125_899_906_826_241u64));
}

#[test]
fn both_embeddings_decrypt_and_key_switch() {
    let modulus = BarrettModulus::new(132_120_577u32);
    let params = LweParameters::new(
        LweDimension::new(17),
        4,
        modulus,
        SecretKeyDistr::UniformTernary,
        3.2,
    );
    let output_params = LweParameters::new(
        LweDimension::new(5),
        4,
        modulus,
        SecretKeyDistr::UniformBinary,
        3.2,
    );
    let mut rng = StdRng::seed_from_u64(0x1_ee13);
    let secret = LweSecretKey::generate(params.encryption_parameters(), &mut rng);
    let key = LwePublicKey::generate(
        secret.as_view(),
        params.dimension(),
        params.cipher_modulus(),
        params.cipher_modulus_uniform_distr(),
        params.noise_distribution(),
        &mut rng,
    );
    let output_secret = LweSecretKey::generate(output_params.encryption_parameters(), &mut rng);
    let key_parameters = LweKeySwitchingParameters::new(
        output_params.encryption_parameters().clone(),
        ApproxSignedBasis::new(
            Some(modulus.value()),
            DecompositionBaseLog::new(2),
            Some(DecompositionLevelCount::new(13)),
        ),
    );
    let switching =
        LweKeySwitchingKey::generate(secret.as_view(), &output_secret, &key_parameters, &mut rng);
    let mut storage = [u32::MAX; 18];
    // Three has a negative representative under centered encoding.
    let message = 3u32;
    for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
        let mut output = Lwe::new(&mut storage[..]);
        key.encrypt_message_to(message, &mut output, &params, embedding, &mut rng);
        assert_eq!(secret.decrypt_message(&output, &params), message);
        let switched = switching.key_switch(&output, modulus);
        assert_eq!(
            output_secret.decrypt_message(&switched, &output_params),
            message
        );
    }
}

#[test]
fn public_key_boundaries_reject_before_writing_or_sampling() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let params = LweParameters::new(
        LweDimension::new(3),
        4,
        BarrettModulus::new(97u32),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x1_ee14);
    let secret = LweSecretKey::generate(params.encryption_parameters(), &mut rng);
    let key = LwePublicKey::generate(
        secret.as_view(),
        params.dimension(),
        params.cipher_modulus(),
        params.cipher_modulus_uniform_distr(),
        params.noise_distribution(),
        &mut rng,
    );
    for (length, dimension, q, message) in [
        (0, 3, 97, 0),
        (3, 3, 97, 0),
        (5, 3, 97, 0),
        (4, 2, 97, 0),
        (4, 3, 101, 0),
        (4, 3, 97, 4),
    ] {
        let bad_params = LweParameters::new(
            LweDimension::new(dimension),
            4,
            BarrettModulus::new(q),
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let mut storage = vec![11u32; length];
        let seed = rng.next_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut expected_rng = StdRng::seed_from_u64(seed);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.encrypt_message_to(
                    message,
                    &mut Lwe::new(storage.as_mut_slice()),
                    &bad_params,
                    PlaintextEmbedding::Unsigned,
                    &mut rng,
                );
            }))
            .is_err()
        );
        assert_eq!(storage, vec![11; length]);
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
    for dimension in [0, 2, 4] {
        let wrong_secret = LweSecretKey::new(
            vec![1u32; dimension],
            SecretKeyDistr::UniformBinary,
            params.cipher_modulus(),
        );
        let seed = rng.next_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut expected_rng = StdRng::seed_from_u64(seed);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                LwePublicKey::generate(
                    wrong_secret.as_view(),
                    params.dimension(),
                    params.cipher_modulus(),
                    params.cipher_modulus_uniform_distr(),
                    params.noise_distribution(),
                    &mut rng,
                )
            }))
            .is_err()
        );
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
    // Noise is supplied independently of the modulus; reject a mismatched
    // sampler at the generation boundary before consuming any random words.
    let wrong_noise = primus_distr::DiscreteGaussian::new(0.7, 100).unwrap();
    let seed = rng.next_u64();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut expected_rng = StdRng::seed_from_u64(seed);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            LwePublicKey::generate(
                secret.as_view(),
                params.dimension(),
                params.cipher_modulus(),
                params.cipher_modulus_uniform_distr(),
                &wrong_noise,
                &mut rng,
            )
        }))
        .is_err()
    );
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
}

#[test]
fn public_key_generation_matches_encoded_and_signed_secrets() {
    fn check<M: RingContext<u32>>(modulus: M) {
        let params = LweParameters::new(
            LweDimension::new(4),
            4,
            modulus,
            SecretKeyDistr::UniformTernary,
            0.7,
        );
        let signed = [1i32, -1, 0, -1];
        // Independent canonical encoding of the same small signed secret.
        let encoded = LweSecretKey::new(
            vec![1, modulus.minus_one(), 0, modulus.minus_one()],
            SecretKeyDistr::UniformTernary,
            modulus,
        );
        let mut signed_rng = StdRng::seed_from_u64(0x5055_424c_4943);
        let mut encoded_rng = StdRng::seed_from_u64(0x5055_424c_4943);
        let public = LwePublicKey::generate(
            primus_lwe::LweSecretKeyRef::Signed(&signed),
            params.dimension(),
            params.cipher_modulus(),
            params.cipher_modulus_uniform_distr(),
            params.noise_distribution(),
            &mut signed_rng,
        );
        let expected = LwePublicKey::generate(
            encoded.as_view(),
            params.dimension(),
            params.cipher_modulus(),
            params.cipher_modulus_uniform_distr(),
            params.noise_distribution(),
            &mut encoded_rng,
        );
        assert_eq!(public.as_slice(), expected.as_slice());
        assert_eq!(signed_rng.next_u64(), encoded_rng.next_u64());
    }
    check(NativeModulus::new());
    check(BarrettModulus::new(132_120_577));
}
