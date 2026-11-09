//! Small functional dimensions include vector blocks and incomplete tails.
use primus_encoding::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lattice::lwe::LweIter;
use primus_lwe::{LweParameters, LwePublicKey, LweSecretKey, SecretKeyDistr};
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_reduce::RingContext;
use rand::{Rng, SeedableRng, rngs::StdRng};

#[test]
fn public_batch_matches_independent_matrix_arithmetic() {
    use rand::distr::Distribution;
    fn check<M: RingContext<u32>>(modulus: M, noise_sigma: f64, dimension: usize, count: usize) {
        let q = modulus.explicit_value().map_or(1i128 << 32, i128::from);
        let row_len = dimension + 1;
        let signed: Vec<i128> = [-1, 0, 1, 2, -2, 1, -1]
            .into_iter()
            .cycle()
            .take(dimension)
            .collect();
        let params = LweParameters::new(
            LweDimension::new(dimension),
            4,
            modulus,
            SecretKeyDistr::gaussian(2.0),
            noise_sigma,
        );
        let secret = LweSecretKey::new(
            signed.iter().map(|s| s.rem_euclid(q) as u32).collect(),
            SecretKeyDistr::gaussian(2.0),
            modulus,
        );
        let mut rng = StdRng::seed_from_u64(0x1_ee26);
        let public = LwePublicKey::generate(
            secret.as_view(),
            params.dimension(),
            params.cipher_modulus(),
            params.cipher_modulus_uniform_distr(),
            params.noise_distribution(),
            &mut rng,
        );
        let plaintexts: Vec<u32> = [0, (q - 1) as u32, (q / 4) as u32]
            .into_iter()
            .cycle()
            .take(count)
            .collect();
        let mut rng = StdRng::seed_from_u64(0x1_ee27);
        let mut oracle_rng = StdRng::seed_from_u64(0x1_ee27);
        let batch = public.encrypt_encoded_batch(
            &plaintexts,
            modulus,
            params.noise_distribution(),
            &mut rng,
        );
        let mut expected = vec![vec![0i128; row_len]; count];
        // Each tile samples Gaussian errors, then packed row-major ternary
        // coefficients. Unused high bits never carry into the next tile.
        for (tile, plaintexts) in expected.chunks_mut(8).zip(plaintexts.chunks(8)) {
            for (row, &plaintext) in tile.iter_mut().zip(plaintexts) {
                for value in row.iter_mut() {
                    *value = i128::from(params.noise_distribution().sample(&mut oracle_rng));
                }
                row[dimension] += i128::from(plaintext);
            }
            let words: Vec<u32> = (0..(dimension * tile.len()).div_ceil(16))
                .map(|_| oracle_rng.next_u32())
                .collect();
            // Ordinary integer matrix multiplication independently checks the
            // row/body layout and each ciphertext's ephemeral coefficient.
            for (i, public_row) in public.as_slice().chunks_exact(row_len).enumerate() {
                let offset = i * tile.len();
                for (j, row) in tile.iter_mut().enumerate() {
                    let index = offset + j;
                    let r = [0, 0, 1, -1][((words[index / 16] >> (2 * (index % 16))) & 3) as usize];
                    for (out, &value) in row.iter_mut().zip(public_row) {
                        *out += i128::from(value) * r;
                    }
                }
            }
        }
        for (ciphertext, expected) in LweIter::new(&batch, row_len).zip(expected) {
            for (&actual, expected) in ciphertext.as_ref().iter().zip(&expected) {
                assert_eq!(i128::from(actual), expected.rem_euclid(q));
            }
        }
        assert_eq!(rng.next_u64(), oracle_rng.next_u64());
    }
    for noise_sigma in [3.2, 30.0] {
        // Cover short blocks and full row/ciphertext blocks followed by tails.
        for (dimension, count) in [(7, 3), (17, 19)] {
            check(NativeModulus::new(), noise_sigma, dimension, count);
            check(
                BarrettModulus::new(132_120_577),
                noise_sigma,
                dimension,
                count,
            );
        }
    }
}

fn check_batches<T: FheUint, M: RingContext<T>>(modulus: M, dimension: usize) {
    let lwe_len = dimension + 1;
    let params = LweParameters::new(
        LweDimension::new(dimension),
        T::as_from(4u32),
        modulus,
        SecretKeyDistr::UniformTernary,
        3.2,
    );
    let mut rng = StdRng::seed_from_u64(0x1_ee21);
    let secret = LweSecretKey::generate(params.encryption_parameters(), &mut rng);
    let public = LwePublicKey::generate(
        secret.as_view(),
        params.dimension(),
        params.cipher_modulus(),
        params.cipher_modulus_uniform_distr(),
        params.noise_distribution(),
        &mut rng,
    );
    for count in [0, 1, 7, 8, 17] {
        let messages: Vec<T> = (0..count).map(|i| T::as_from(i % 4)).collect();
        for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
            for use_public in [false, true] {
                let mut rng = StdRng::seed_from_u64(0x1_ee22);
                let mut raw_rng = StdRng::seed_from_u64(0x1_ee22);
                let mut storage = vec![T::MAX; count * lwe_len + 2];
                let batch = &mut storage[1..count * lwe_len + 1];
                if use_public {
                    public.encrypt_message_batch_to(&messages, batch, &params, embedding, &mut rng);
                } else {
                    secret.encrypt_message_batch_to(&messages, batch, &params, embedding, &mut rng);
                }
                let encoded: Vec<T> = messages
                    .iter()
                    .map(|&m| params.plaintext_codec().encode_value(m, embedding))
                    .collect();
                let raw = if use_public {
                    public.encrypt_encoded_batch(
                        &encoded,
                        modulus,
                        params.noise_distribution(),
                        &mut raw_rng,
                    )
                } else {
                    secret.encrypt_encoded_batch(
                        &encoded,
                        params.encryption_parameters(),
                        &mut raw_rng,
                    )
                };
                assert_eq!(raw.as_slice(), &*batch);
                assert_eq!(secret.decrypt_message_batch(batch, &params), messages);
                let mut decrypted = vec![T::MAX; count];
                secret.decrypt_message_batch_to(batch, &mut decrypted, &params);
                assert_eq!(decrypted, messages);
                let phases = secret.decrypt_phase_batch(batch, modulus);
                secret.decrypt_phase_batch_to(batch, &mut decrypted, modulus);
                assert_eq!(decrypted, phases);
                for (ciphertext, &phase) in LweIter::new(batch, lwe_len).zip(&phases) {
                    assert_eq!(secret.as_view().decrypt_phase(&ciphertext, modulus), phase);
                    assert!(
                        ciphertext
                            .as_ref()
                            .iter()
                            .all(|&c| c <= modulus.minus_one())
                    );
                }
                assert_eq!(storage[0], T::MAX);
                assert_eq!(storage[count * lwe_len + 1], T::MAX);
                if count == 0 {
                    let mut untouched = StdRng::seed_from_u64(0x1_ee22);
                    assert_eq!(rng.next_u64(), untouched.next_u64());
                }
            }
        }
    }
}

#[test]
fn batches_decrypt_across_moduli_embeddings_and_tail_sizes() {
    check_batches(NativeModulus::<u32>::new(), 7);
    check_batches(NativeModulus::<u64>::new(), 7);
    check_batches(PowOf2Modulus::new(1u32 << 30), 7);
    check_batches(BarrettModulus::new(132_120_577u32), 7);
    check_batches(BarrettModulus::new(1_125_899_906_826_241u64), 7);
    // A longer non-power-of-two mask exercises multiple vector blocks and a tail.
    check_batches(NativeModulus::<u32>::new(), 65);
    check_batches(BarrettModulus::new(132_120_577u32), 65);
}

#[test]
fn batch_boundaries_validate_layout_and_reject_invalid_messages() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let params = LweParameters::new(
        LweDimension::new(3),
        4u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x1_ee24);
    let secret = LweSecretKey::generate(params.encryption_parameters(), &mut rng);
    let public = LwePublicKey::generate(
        secret.as_view(),
        params.dimension(),
        params.cipher_modulus(),
        params.cipher_modulus_uniform_distr(),
        params.noise_distribution(),
        &mut rng,
    );
    for use_public in [false, true] {
        for length in [0, 7, 12] {
            let mut storage = vec![11; length];
            let mut rng = StdRng::seed_from_u64(31);
            let mut expected = StdRng::seed_from_u64(31);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    if use_public {
                        public.encrypt_message_batch_to(
                            &[0u32, 1],
                            &mut storage,
                            &params,
                            PlaintextEmbedding::Unsigned,
                            &mut rng,
                        );
                    } else {
                        secret.encrypt_message_batch_to(
                            &[0u32, 1],
                            &mut storage,
                            &params,
                            PlaintextEmbedding::Unsigned,
                            &mut rng,
                        );
                    }
                }))
                .is_err()
            );
            if !use_public {
                assert!(
                    catch_unwind(AssertUnwindSafe(|| {
                        secret.encrypt_encoded_batch_to(
                            &[0u32, 1],
                            &mut storage,
                            params.encryption_parameters(),
                            &mut rng,
                        );
                    }))
                    .is_err()
                );
            }
            assert!(storage.iter().all(|&c| c == 11));
            assert_eq!(rng.next_u64(), expected.next_u64());
        }
        // First-message failures occur before sampling; later failures may
        // leave completed ciphertexts or a partially initialized public-key tile.
        for index in [0, 9] {
            let mut messages = [1u32; 10];
            messages[index] = params.plain_modulus_value();
            let mut output = vec![17u32; 40];
            let mut rng = StdRng::seed_from_u64(32);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    if use_public {
                        public.encrypt_message_batch_to(
                            &messages,
                            &mut output,
                            &params,
                            PlaintextEmbedding::Unsigned,
                            &mut rng,
                        );
                    } else {
                        secret.encrypt_message_batch_to(
                            &messages,
                            &mut output,
                            &params,
                            PlaintextEmbedding::Unsigned,
                            &mut rng,
                        );
                    }
                }))
                .is_err()
            );
            if index == 0 {
                assert!(output.iter().all(|&c| c == 17));
                assert_eq!(rng.next_u64(), StdRng::seed_from_u64(32).next_u64());
            }
        }
    }
    let batch =
        public.encrypt_message_batch(&[1u32, 2], &params, PlaintextEmbedding::Unsigned, &mut rng);
    let mut messages = [17u32; 1];
    assert!(
        catch_unwind(AssertUnwindSafe(|| secret.decrypt_message_batch_to(
            &batch,
            &mut messages,
            &params
        )))
        .is_err()
    );
    assert_eq!(messages, [17]);

    // Slice-based APIs must reject incomplete tails before the chunk iterator
    // can omit them, including a tail with no complete ciphertext at all.
    for length in [1, 7] {
        let input = vec![0u32; length];
        assert!(catch_unwind(|| secret.decrypt_message_batch(&input, &params)).is_err());
        assert!(
            catch_unwind(|| secret.decrypt_phase_batch(&input, params.cipher_modulus())).is_err()
        );
        let mut output = vec![17u32; length / 4];
        assert!(
            catch_unwind(AssertUnwindSafe(|| secret.decrypt_message_batch_to(
                &input,
                &mut output,
                &params
            )))
            .is_err()
        );
        assert!(output.iter().all(|&value| value == 17));
    }
}
