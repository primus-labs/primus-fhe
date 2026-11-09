//! Small functional dimensions include vector blocks and incomplete tails.
use primus_integer::{AsFrom, AsInto, FheUint};
use primus_lattice::LweDimension;
use primus_lattice::lwe::Lwe;
use primus_lwe::{LweParameters, LweSecretKeyRef, SecretKeyDistr};
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_reduce::RingContext;
use rand::{Rng, SeedableRng, distr::Distribution, rngs::StdRng};

fn check_raw<T: FheUint, M: RingContext<T>>(modulus: M) {
    let q = modulus
        .explicit_value()
        .map_or(1i128 << T::BITS, |q| q.as_into());
    for dimension in [0, 7, 65] {
        let signed: Vec<T::SignedInteger> = (0..dimension)
            .map(|i| T::SignedInteger::as_from((i % 7) as i32 - 3))
            .collect();
        let encoded: Vec<T> = signed
            .iter()
            .map(|&s| {
                let s: i128 = s.as_into();
                T::as_from(s.rem_euclid(q))
            })
            .collect();
        // Reuse the sampler parameters while also exercising a zero-dimensional raw sample.
        let params = LweParameters::new(
            LweDimension::new(dimension.max(1)),
            T::as_from(4u32),
            modulus,
            SecretKeyDistr::UniformTernary,
            0.7,
        );
        for plaintext in [T::ZERO, T::as_from(q - 1)] {
            let mut rng = StdRng::seed_from_u64(0x1_ee05);
            let mut expected_rng = StdRng::seed_from_u64(0x1_ee05);
            let mut output_rng = StdRng::seed_from_u64(0x1_ee05);
            let mut oracle_rng = StdRng::seed_from_u64(0x1_ee05);
            let uniform = params.cipher_modulus_uniform_distr();
            let noise = params.noise_distribution();
            let signed_key = LweSecretKeyRef::Signed(&signed);
            let encoded_key = LweSecretKeyRef::Encoded(&encoded);
            let ciphertext =
                signed_key.encrypt_encoded(plaintext, modulus, uniform, noise, &mut rng);
            let expected =
                encoded_key.encrypt_encoded(plaintext, modulus, uniform, noise, &mut expected_rng);
            assert_eq!(ciphertext, expected);

            // Borrow a bounded output region whose previous contents are nonzero.
            let mut storage = vec![T::MAX; dimension + 3];
            let mut output = Lwe::new(&mut storage[1..dimension + 2]);
            signed_key.encrypt_encoded_to(
                plaintext,
                &mut output,
                modulus,
                uniform,
                noise,
                &mut output_rng,
            );
            assert_eq!(output.0, ciphertext.0.as_slice());
            assert!(output.0.iter().all(|&c| {
                let c: i128 = c.as_into();
                c < q
            }));

            // Independent signed arithmetic catches a shared sign/phase error.
            let dot = output
                .a()
                .iter()
                .zip(&signed)
                .map(|(&a, &s)| {
                    let a: i128 = a.as_into();
                    let s: i128 = s.as_into();
                    a * s
                })
                .sum::<i128>();
            let body: i128 = output.b().as_into();
            let phase = T::as_from((body - dot).rem_euclid(q));
            assert_eq!(signed_key.decrypt_phase(&output, modulus), phase);
            assert_eq!(encoded_key.decrypt_phase(&output, modulus), phase);
            for _ in 0..dimension {
                let _ = uniform.sample(&mut oracle_rng);
            }
            let error = noise.sample(&mut oracle_rng);
            assert_eq!(phase, {
                let plaintext: i128 = plaintext.as_into();
                let error: i128 = error.as_into();
                T::as_from((plaintext + error) % q)
            });
            assert_eq!(storage[0], T::MAX);
            assert_eq!(storage[dimension + 2], T::MAX);
        }
    }
}

#[test]
fn raw_encryption_and_phase_agree_across_key_representations() {
    check_raw(NativeModulus::<u32>::new());
    check_raw(NativeModulus::<u64>::new());
    check_raw(PowOf2Modulus::new(1u32 << 30));
    check_raw(PowOf2Modulus::new(1u64 << 50));
    check_raw(BarrettModulus::new(132_120_577u32));
    check_raw(BarrettModulus::new(1_125_899_906_826_241u64));
}

#[test]
fn raw_dimensions_are_checked_before_writing_or_sampling() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let params = LweParameters::new(
        LweDimension::new(2),
        4u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x1_ee07);
    let mut expected_rng = StdRng::seed_from_u64(0x1_ee07);
    let mut storage = [7u32; 2];
    let key = LweSecretKeyRef::Signed(&[1i32, -1]);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            key.encrypt_encoded_to(
                0,
                &mut Lwe::new(&mut storage[..]),
                params.cipher_modulus(),
                params.cipher_modulus_uniform_distr(),
                params.noise_distribution(),
                &mut rng,
            );
        }))
        .is_err()
    );
    assert_eq!(storage, [7; 2]);
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
    assert!(
        catch_unwind(|| key.decrypt_phase(&Lwe::new(&storage[..]), params.cipher_modulus()))
            .is_err()
    );
}
