//! Small functional dimensions include vector blocks and incomplete tails.

mod support;

use primus_encoding::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lattice::lwe::LweIter;
use primus_lwe::{LweParameters, LwePublicKey, LweSecretKey, SecretKeyDistr};
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_reduce::RingContext;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

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
        let public = support::public_key(&secret, params.encryption_parameters(), &mut rng);
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

fn check_batches<T: FheUint, M: RingContext<T>>(
    modulus: M,
    dimension: usize,
    cases: &[(usize, PlaintextEmbedding)],
) {
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
    let public = support::public_key(&secret, params.encryption_parameters(), &mut rng);
    for &(count, embedding) in cases {
        let messages: Vec<T> = (0..count).map(|i| T::as_from(i % 4)).collect();
        let end = count * lwe_len + 1;
        let mut storage = vec![T::MAX; end + 1];
        let check = |storage: &[T]| {
            let batch = &storage[1..end];
            let mut decrypted = vec![T::MAX; count];
            secret.decrypt_message_batch_to(batch, &mut decrypted, &params);
            assert_eq!(decrypted, messages);
            // Decoding can hide a phase error smaller than a message step.
            secret.decrypt_phase_batch_to(batch, &mut decrypted, modulus);
            for (ciphertext, phase) in LweIter::new(batch, lwe_len).zip(decrypted) {
                assert_eq!(phase, secret.as_view().decrypt_phase(&ciphertext, modulus));
            }
            assert_eq!(storage[0], T::MAX);
            assert_eq!(storage[end], T::MAX);
            assert!(batch.iter().all(|&c| c <= modulus.minus_one()));
        };
        let coins = || StdRng::seed_from_u64(0x1_ee22);
        secret.encrypt_message_batch_to(
            &messages,
            &mut storage[1..end],
            &params,
            embedding,
            &mut coins(),
        );
        check(&storage);
        storage[1..end].fill(T::MAX);
        public.encrypt_message_batch_to(
            &messages,
            &mut storage[1..end],
            &params,
            embedding,
            &mut coins(),
        );
        check(&storage);
    }
}

#[test]
fn batches_decrypt_across_moduli_embeddings_and_tail_sizes() {
    use PlaintextEmbedding::{Centered, Unsigned};

    // Cover the batch boundaries on both reduction paths. Dimension 65 also
    // leaves a coefficient tail after the full SIMD blocks.
    let batch_boundaries = [(1, Unsigned), (7, Centered), (8, Unsigned), (17, Centered)];
    check_batches(NativeModulus::<u32>::new(), 65, &batch_boundaries);
    check_batches(BarrettModulus::new(132_120_577u32), 65, &batch_boundaries);
    check_batches(NativeModulus::<u64>::new(), 65, &[(17, Centered)]);
    check_batches(
        BarrettModulus::new(1_125_899_906_826_241u64),
        65,
        &[(17, Centered)],
    );
    check_batches(PowOf2Modulus::new(1u32 << 30), 7, &[(3, Unsigned)]);
}

#[test]
fn encoded_and_message_batches_agree_with_the_same_coins() {
    let modulus = BarrettModulus::new(132_120_577u32);
    let params = LweParameters::new(
        LweDimension::new(17),
        4,
        modulus,
        SecretKeyDistr::UniformTernary,
        3.2,
    );
    let mut rng = StdRng::seed_from_u64(0x1_ee21);
    let secret = LweSecretKey::generate(params.encryption_parameters(), &mut rng);
    let public = support::public_key(&secret, params.encryption_parameters(), &mut rng);
    // Nine messages exercise a full public-key tile and its tail.
    let messages = [0, 1, 2, 3, 0, 1, 2, 3, 3];
    let embedding = PlaintextEmbedding::Centered;
    let residues = messages.map(|m| params.plaintext_codec().encode_value(m, embedding));
    let coins = || StdRng::seed_from_u64(0x1_ee22);
    let private_batch = secret.encrypt_message_batch(&messages, &params, embedding, &mut coins());
    let public_batch = public.encrypt_message_batch(&messages, &params, embedding, &mut coins());
    assert_eq!(
        private_batch,
        secret.encrypt_encoded_batch(&residues, params.encryption_parameters(), &mut coins())
    );
    assert_eq!(
        public_batch,
        public.encrypt_encoded_batch(
            &residues,
            modulus,
            params.noise_distribution(),
            &mut coins()
        )
    );

    for batch in [&private_batch, &public_batch] {
        assert_eq!(secret.decrypt_message_batch(batch, &params), messages);
        let expected: Vec<_> = LweIter::new(batch, params.dimension().ciphertext_len())
            .map(|sample| secret.as_view().decrypt_phase(&sample, modulus))
            .collect();
        assert_eq!(secret.decrypt_phase_batch(batch, modulus), expected);
    }
}

fn small_batch_keys() -> (
    LweParameters<u32, NativeModulus<u32>>,
    LweSecretKey<u32>,
    LwePublicKey<u32>,
) {
    let params = LweParameters::new(
        LweDimension::new(3),
        4u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x1_ee24);
    let secret = LweSecretKey::generate(params.encryption_parameters(), &mut rng);
    let public = support::public_key(&secret, params.encryption_parameters(), &mut rng);
    (params, secret, public)
}

#[test]
fn empty_batches_do_not_consume_randomness() {
    let (params, secret, public) = small_batch_keys();
    let coins = || StdRng::seed_from_u64(0x1_ee22);
    let expected = coins().next_u64();
    let embedding = PlaintextEmbedding::Unsigned;
    let mut rng = coins();
    secret.encrypt_message_batch_to(&[], &mut [], &params, embedding, &mut rng);
    assert_eq!(rng.next_u64(), expected);
    let mut rng = coins();
    public.encrypt_message_batch_to(&[], &mut [], &params, embedding, &mut rng);
    assert_eq!(rng.next_u64(), expected);
    assert!(secret.decrypt_message_batch(&[], &params).is_empty());
    assert!(
        secret
            .decrypt_phase_batch(&[], params.cipher_modulus())
            .is_empty()
    );
}

#[track_caller]
fn assert_rejected_before_encryption(length: usize, encrypt: impl FnOnce(&mut [u32], &mut StdRng)) {
    let mut output = vec![17; length];
    let mut rng = StdRng::seed_from_u64(31);
    let expected = StdRng::seed_from_u64(31).next_u64();
    assert!(catch_unwind(AssertUnwindSafe(|| encrypt(&mut output, &mut rng))).is_err());
    assert!(output.iter().all(|&value| value == 17));
    assert_eq!(rng.next_u64(), expected);
}

#[test]
fn batch_encryption_rejects_bad_output_lengths_before_writing_or_sampling() {
    let (params, secret, public) = small_batch_keys();
    let embedding = PlaintextEmbedding::Unsigned;
    // Two ciphertexts of four words each require exactly eight words.
    for length in [7, 12] {
        assert_rejected_before_encryption(length, |output, rng| {
            secret.encrypt_message_batch_to(&[0, 1], output, &params, embedding, rng);
        });
        assert_rejected_before_encryption(length, |output, rng| {
            public.encrypt_message_batch_to(&[0, 1], output, &params, embedding, rng);
        });
        assert_rejected_before_encryption(length, |output, rng| {
            secret.encrypt_encoded_batch_to(&[0, 1], output, params.encryption_parameters(), rng);
        });
    }
}

#[test]
fn batch_encryption_rejects_invalid_messages_at_the_start_and_in_the_tail() {
    let (params, secret, public) = small_batch_keys();
    let embedding = PlaintextEmbedding::Unsigned;
    let invalid = params.plain_modulus_value();
    let mut messages = [1; 10];
    messages[0] = invalid;
    assert_rejected_before_encryption(40, |output, rng| {
        secret.encrypt_message_batch_to(&messages, output, &params, embedding, rng);
    });
    assert_rejected_before_encryption(40, |output, rng| {
        public.encrypt_message_batch_to(&messages, output, &params, embedding, rng);
    });

    // The final message is in the second public-key tile. A late error may
    // leave partial output and consume randomness for earlier messages.
    messages[0] = 1;
    messages[9] = invalid;
    let mut output = [17; 40];
    let mut rng = StdRng::seed_from_u64(32);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            secret.encrypt_message_batch_to(&messages, &mut output, &params, embedding, &mut rng);
        }))
        .is_err()
    );
    output.fill(17);
    let mut rng = StdRng::seed_from_u64(32);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            public.encrypt_message_batch_to(&messages, &mut output, &params, embedding, &mut rng);
        }))
        .is_err()
    );
}

#[test]
fn batch_decryption_rejects_incomplete_input_and_mismatched_output() {
    let (params, secret, _) = small_batch_keys();
    let mut messages = [17u32; 1];
    assert!(
        catch_unwind(AssertUnwindSafe(|| secret.decrypt_message_batch_to(
            &[0; 8],
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
