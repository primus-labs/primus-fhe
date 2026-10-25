//! Small functional dimensions include vector blocks and incomplete tails.
use primus_encoding::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lattice::lwe::MultiMsgLwe;
use primus_lwe::{LweParameters, LweSecretKey, MultiMsgLweCiphertext, SecretKeyDistr};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::RingContext;
use rand::{Rng, SeedableRng, rngs::StdRng};

#[test]
fn packed_capacity_is_enforced() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let params = LweParameters::new(
        LweDimension::new(4),
        4u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x1_ee03);
    let key = LweSecretKey::generate(params.encryption_parameters(), &mut rng);

    // The first disallowed body reuses a mask up to sign.
    let count = params.dimension().ciphertext_len();
    let seed = rng.next_u64();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut untouched = StdRng::seed_from_u64(seed);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            key.encrypt_message_packed(
                &vec![0u32; count],
                &params,
                PlaintextEmbedding::Unsigned,
                &mut rng,
            )
        }))
        .is_err()
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            key.encrypt_encoded_packed(&vec![0u32; count], params.encryption_parameters(), &mut rng)
        }))
        .is_err()
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            key.encrypt_message_packed(&[4], &params, PlaintextEmbedding::Unsigned, &mut rng)
        }))
        .is_err()
    );
    assert_eq!(rng.next_u64(), untouched.next_u64());
    for length in [
        params.dimension().get() - 1,
        params.dimension().get() + count,
    ] {
        let malformed = MultiMsgLweCiphertext::new(vec![0u32; length]);
        assert!(catch_unwind(|| key.decrypt_message_packed(&malformed, &params)).is_err());
        assert!(
            catch_unwind(|| key.decrypt_phase_packed(&malformed, params.cipher_modulus())).is_err()
        );
    }
}

#[test]
fn packed_samples_decrypt_independently() {
    check_packed_samples(NativeModulus::<u32>::new());
    check_packed_samples(NativeModulus::<u64>::new());
    check_packed_samples(BarrettModulus::new(132_120_577u32));
    check_packed_samples(BarrettModulus::new(1_125_899_906_826_241u64));
}

fn check_packed_samples<T: FheUint, M: RingContext<T>>(modulus: M) {
    // Moving rotation splits exercise vector blocks and tails in both word widths.
    let dimension = 65;
    let params = LweParameters::new(
        LweDimension::new(dimension),
        T::as_from(4u32),
        modulus,
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    let pattern = [T::ONE, modulus.reduce_neg(T::ONE), T::ZERO, T::ONE];
    let key = LweSecretKey::new(
        (0..dimension).map(|i| pattern[i % pattern.len()]).collect(),
        SecretKeyDistr::UniformTernary,
        modulus,
    );
    let mut rng = StdRng::seed_from_u64(0x1_ee04);
    let messages: Vec<T> = (0..dimension).map(|i| T::as_from(i % 4)).collect();
    let check = |ciphertext: MultiMsgLweCiphertext<T>, messages: &[T]| {
        assert_eq!(ciphertext.0.len(), dimension + messages.len());
        let borrowed = MultiMsgLwe::new(ciphertext.0.as_slice());
        assert_eq!(key.decrypt_message_packed(&borrowed, &params), messages);
        let phases = key.decrypt_phase_packed(&borrowed, modulus);
        assert_eq!(phases.len(), messages.len());
        // The lattice extractor is independent of the packed phase helper,
        // exposing a rotation/sign error shared by encryption and decryption.
        for (index, &message) in messages.iter().enumerate() {
            let sample = ciphertext.extract_lwe_at(index, dimension, modulus);
            assert_eq!(key.decrypt_message(&sample, &params), message);
            assert_eq!(key.decrypt_phase(&sample, modulus), phases[index]);
        }
    };
    for count in [0, 3, dimension] {
        for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
            let seed = rng.next_u64();
            let mut rng = StdRng::seed_from_u64(seed);
            let mut raw_rng = StdRng::seed_from_u64(seed);
            let ciphertext =
                key.encrypt_message_packed(&messages[..count], &params, embedding, &mut rng);
            let encoded: Vec<T> = messages[..count]
                .iter()
                .map(|&m| params.plaintext_codec().encode_value(m, embedding))
                .collect();
            let raw =
                key.encrypt_encoded_packed(&encoded, params.encryption_parameters(), &mut raw_rng);
            assert_eq!(ciphertext, raw);
            assert_eq!(rng.next_u64(), raw_rng.next_u64());
            check(ciphertext, &messages[..count]);
        }
    }
    for count in [0, 3] {
        let zeros = &[T::ZERO; 3][..count];
        check(
            key.encrypt_encoded_packed(zeros, params.encryption_parameters(), &mut rng),
            zeros,
        );
    }
}
