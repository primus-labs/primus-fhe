use primus_encoding::{PlaintextEmbedding, phase_error_magnitude};
use primus_lattice::LweDimension;
use primus_lattice::lwe::Lwe;
use primus_lwe::{LweParameters, LweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use rand::{Rng, SeedableRng, rngs::StdRng};

// Owning generation must preserve the signed sampler's values and RNG stream,
// including both Gaussian backends and a whole-key fixed composition.
#[test]
fn key_generation_preserves_samples_and_rng_consumption() {
    use primus_integer::FheUint;
    use primus_lwe::LweEncryptionParameters;
    use primus_modulus::NativeModulus;
    use primus_reduce::RingContext;
    use rand::Rng;

    fn check<T: FheUint>(modulus: impl RingContext<T>) {
        for distribution in [
            SecretKeyDistr::UniformBinary,
            SecretKeyDistr::UniformTernary,
            SecretKeyDistr::fixed_composition_ternary(67, 22, 22),
            SecretKeyDistr::gaussian(3.2),
            SecretKeyDistr::gaussian(30.0),
        ] {
            let params =
                LweEncryptionParameters::new(LweDimension::new(67), modulus, distribution, 0.7);
            let mut rng = StdRng::seed_from_u64(201);
            let mut oracle_rng = StdRng::seed_from_u64(201);
            let signed = params
                .secret_key_sampler()
                .sample_signed(67, &mut oracle_rng);
            let key = LweSecretKey::generate(&params, &mut rng);
            assert_eq!(key.dimension(), signed.len());
            for (&actual, expected) in key.as_ref().iter().zip(signed) {
                assert_eq!(actual, modulus.encode_signed(expected), "{distribution:?}");
            }
            assert_eq!(rng.next_u64(), oracle_rng.next_u64(), "{distribution:?}");
        }
    }
    check(NativeModulus::<u32>::new());
    check(BarrettModulus::new(1009u32));
    check(NativeModulus::<u64>::new());
    check(BarrettModulus::new(1009u64));
}

#[test]
fn message_encryption_reuses_storage_for_both_embeddings() {
    let params = LweParameters::new(
        LweDimension::new(7),
        4,
        BarrettModulus::new(97u32),
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x1_ee06);
    let key = LweSecretKey::generate(params.encryption_parameters(), &mut rng);
    let mut storage = [u32::MAX; 8];
    for message in 0..4u32 {
        for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
            let seed = 0x1_ee06;
            let mut rng = StdRng::seed_from_u64(seed);
            let mut raw_rng = StdRng::seed_from_u64(seed);
            let mut output = Lwe::new(&mut storage[..]);
            key.encrypt_message_to(message, &mut output, &params, embedding, &mut rng);
            let encoded = params.plaintext_codec().encode_value(message, embedding);
            let expected =
                key.encrypt_encoded(encoded, params.encryption_parameters(), &mut raw_rng);
            assert_eq!(output.as_ref(), expected.as_ref());
            assert_eq!(
                key.encrypt_message(
                    message,
                    &params,
                    embedding,
                    &mut StdRng::seed_from_u64(seed)
                ),
                expected
            );
            key.encrypt_encoded_to(
                encoded,
                &mut output,
                params.encryption_parameters(),
                &mut StdRng::seed_from_u64(seed),
            );
            assert_eq!(output.as_ref(), expected.as_ref());
            assert_eq!(key.decrypt_message(&output, &params), message);
            assert_eq!(rng.next_u64(), raw_rng.next_u64());
        }
    }
}

#[test]
fn phase_error_uses_the_expected_message_embedding() {
    let params = LweParameters::new(
        LweDimension::new(1),
        4u32,
        BarrettModulus::new(97),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let key = LweSecretKey::new(
        vec![1u32],
        SecretKeyDistr::UniformBinary,
        params.cipher_modulus(),
    );

    // For m=2, q=97, t=4, ties away from zero give unsigned E(m)=49
    // and centered E(m)=-49 mod 97=48. Use an independent, known phase.
    for (embedding, encoded) in [
        (PlaintextEmbedding::Unsigned, 49i32),
        (PlaintextEmbedding::Centered, 48),
    ] {
        for noise in [-2i32, 0, 2, 24] {
            let body = (11 + encoded + noise).rem_euclid(97) as u32;
            let storage = [11u32, body];
            let ciphertext = Lwe::new(&storage[..]);
            let phase = key.decrypt_phase(&ciphertext, params.cipher_modulus());
            let reference = params.plaintext_codec().encode_value(2, embedding);
            assert_eq!(reference, encoded as u32);
            assert_eq!(
                phase_error_magnitude(phase, reference, params.cipher_modulus()),
                noise.unsigned_abs()
            );
            // The large error decodes to the wrong message but retains its magnitude.
            assert_eq!(
                key.decrypt_message(&ciphertext, &params),
                if noise == 24 { 3 } else { 2 }
            );
        }
    }
}

#[test]
fn owning_domain_is_preserved_and_rejected_before_sampling_or_writing() {
    use primus_integer::FheUint;
    use primus_modulus::{NativeModulus, PowOf2Modulus};
    use primus_reduce::{Modulus, RingContext};
    use rand::Rng;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn check<T: FheUint, M: RingContext<T>, Other: Modulus<ValueT = T>>(modulus: M, other: Other) {
        let params = LweParameters::new(
            LweDimension::new(4),
            T::TWO,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let mut rng = StdRng::seed_from_u64(0x4c57_4544);
        let generated = LweSecretKey::generate(params.encryption_parameters(), &mut rng);
        assert_eq!(generated.cipher_modulus_minus_one(), modulus.minus_one());

        // Both imports contain the same valid binary secret, so residue scans
        // cannot distinguish their domains. No secret copying is needed to bind.
        let matching = LweSecretKey::new(vec![T::ONE; 4], SecretKeyDistr::UniformBinary, modulus);
        let foreign = LweSecretKey::new(vec![T::ONE; 4], SecretKeyDistr::UniformBinary, other);
        assert_eq!(foreign.cipher_modulus_minus_one(), other.minus_one());
        let mut output =
            matching.encrypt_message(T::ONE, &params, PlaintextEmbedding::Unsigned, &mut rng);
        assert_eq!(matching.decrypt_message(&output, &params), T::ONE);
        let original = output.clone();
        let seed = rng.next_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut untouched = StdRng::seed_from_u64(seed);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                foreign.encrypt_message_to(
                    T::ONE,
                    &mut output,
                    &params,
                    PlaintextEmbedding::Unsigned,
                    &mut rng,
                );
            }))
            .is_err()
        );
        assert_eq!(output, original);
        assert_eq!(rng.next_u64(), untouched.next_u64());
        assert!(
            catch_unwind(AssertUnwindSafe(
                || foreign.decrypt_message(&output, &params)
            ))
            .is_err()
        );

        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                foreign.encrypt_encoded_to(
                    T::ONE,
                    &mut output,
                    params.encryption_parameters(),
                    &mut rng,
                );
            }))
            .is_err()
        );
        assert_eq!(output, original);
        assert_eq!(rng.next_u64(), untouched.next_u64());
        assert!(
            catch_unwind(AssertUnwindSafe(|| foreign.decrypt_phase(&output, modulus))).is_err()
        );

        // Batch checks precede the first entry, including empty batches.
        let mut batch = vec![T::ONE; 10];
        let seed = rng.next_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut untouched = StdRng::seed_from_u64(seed);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                foreign.encrypt_message_batch_to(
                    &[T::ZERO, T::ONE],
                    &mut batch,
                    &params,
                    PlaintextEmbedding::Unsigned,
                    &mut rng,
                );
            }))
            .is_err()
        );
        assert_eq!(batch, vec![T::ONE; 10]);
        assert_eq!(rng.next_u64(), untouched.next_u64());
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                foreign.decrypt_phase_batch_to(&[], &mut [], modulus);
            }))
            .is_err()
        );
    }

    check(NativeModulus::<u32>::new(), PowOf2Modulus::new(1 << 31));
    check(PowOf2Modulus::<u32>::new(1 << 31), NativeModulus::new());
    check(BarrettModulus::<u32>::new(97), BarrettModulus::new(101));
    check(NativeModulus::<u64>::new(), PowOf2Modulus::new(1 << 63));
    check(BarrettModulus::<u64>::new(97), BarrettModulus::new(101));
}
