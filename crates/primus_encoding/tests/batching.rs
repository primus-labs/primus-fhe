#![cfg(feature = "batching")]

use primus_encoding::BatchingEncoder;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn pow(mut base: u64, mut exponent: usize, p: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = (result as u128 * base as u128 % p as u128) as u64;
        }
        base = (base as u128 * base as u128 % p as u128) as u64;
        exponent >>= 1;
    }
    result
}

// Independent DFT: no NTT or production permutation is used by this oracle.
fn evaluate(coefficients: &[u64], p: u64) -> Vec<u64> {
    let n = coefficients.len();
    let root = (2..p).find(|&root| pow(root, n, p) == p - 1).unwrap();
    (0..n)
        .map(|slot| {
            let positive = pow(5, slot % (n / 2), (2 * n) as u64) as usize;
            let exponent = if slot < n / 2 {
                positive
            } else {
                2 * n - positive
            };
            let point = pow(root, exponent, p);
            coefficients.iter().rev().fold(0, |value, &coefficient| {
                ((value as u128 * point as u128 + coefficient as u128) % p as u128) as u64
            })
        })
        .collect()
}

fn convolution(lhs: &[u64], rhs: &[u64], p: u64) -> Vec<u64> {
    let n = lhs.len();
    let mut output = vec![0; n];
    for (i, &left) in lhs.iter().enumerate() {
        for (j, &right) in rhs.iter().enumerate() {
            let product = left as u128 * right as u128 % p as u128;
            let product = if i + j >= n {
                (p as u128 - product) % p as u128
            } else {
                product
            };
            let index = (i + j) % n;
            output[index] = ((output[index] as u128 + product) % p as u128) as u64;
        }
    }
    output
}

fn automorphism(coefficients: &[u64], exponent: usize, p: u64) -> Vec<u64> {
    let n = coefficients.len();
    let mut output = vec![0; n];
    for (degree, &coefficient) in coefficients.iter().enumerate() {
        let target = degree * exponent % (2 * n);
        output[target % n] = if target >= n && coefficient != 0 {
            p - coefficient
        } else {
            coefficient
        };
    }
    output
}

#[test]
fn encode_and_decode_match_independent_dft_with_zero_padding() {
    for (n, p) in [(32, 257), (64, 257), (128, 257), (32, 12_289), (64, 12_289)] {
        let encoder = BatchingEncoder::try_new(PolyLength::new(n), BarrettModulus::new(p)).unwrap();
        assert_eq!(encoder.slot_capacity(), n);
        assert_eq!(encoder.plain_modulus(), p);
        for slot in 0..n {
            let exponent = pow(5, slot % (n / 2), (2 * n) as u64) as usize;
            assert_eq!(
                encoder.slot_exponent(slot),
                if slot < n / 2 {
                    exponent
                } else {
                    2 * n - exponent
                }
            );
        }
        let coefficients: Vec<_> = (0..n)
            .map(|i| (17 * i as u64 * i as u64 + 31 * i as u64 + p - 1) % p)
            .collect();
        let expected = evaluate(&coefficients, p);
        let slots = encoder.decode(&coefficients);
        assert_eq!(slots, expected);

        // Encode is checked by direct evaluation, rather than an NTT roundtrip.
        let mut packed = vec![p - 1; n];
        for count in [0, 1, n / 2 - 1, n / 2 + 1, n] {
            encoder.encode_to(&expected[..count], &mut packed);
            let mut padded = vec![0; n];
            padded[..count].copy_from_slice(&expected[..count]);
            assert_eq!(evaluate(&packed, p), padded);
            assert!(packed.iter().all(|&value| value < p));
        }
    }
}

#[test]
fn slot_products_and_subring_embedding_match_negacyclic_convolution() {
    for (n, p, full_n) in [
        (32, 257, 32),
        (32, 257, 128),
        (32, 193, 128),
        (64, 12_289, 128),
    ] {
        let encoder = BatchingEncoder::try_new(PolyLength::new(n), BarrettModulus::new(p)).unwrap();
        let lhs: Vec<_> = (0..n).map(|i| (3 * i as u64 + 7) % p).collect();
        let rhs: Vec<_> = (0..n).map(|i| (i as u64 * i as u64 + p - 1) % p).collect();
        let left = encoder.encode(&lhs);
        let right = encoder.encode(&rhs);
        let product = convolution(&left, &right, p);
        let expected: Vec<_> = lhs.iter().zip(&rhs).map(|(&a, &b)| a * b % p).collect();
        assert_eq!(evaluate(&product, p), expected);

        let mut embedded_left = vec![p - 1; full_n];
        let mut embedded_right = vec![p - 1; full_n];
        encoder.embed_to(&left, &mut embedded_left);
        encoder.embed_to(&right, &mut embedded_right);
        let stride = full_n / n;
        assert!(
            embedded_left
                .iter()
                .enumerate()
                .all(|(i, &value)| i % stride == 0 || value == 0)
        );
        let embedded_product = convolution(&embedded_left, &embedded_right, p);
        let mut expected_embedded_product = vec![p - 1; full_n];
        encoder.embed_to(&product, &mut expected_embedded_product);
        assert_eq!(embedded_product, expected_embedded_product);
        let mut extracted = vec![p - 1; n];
        encoder.extract_to(&embedded_product, &mut extracted);
        assert_eq!(extracted, product);
    }
}

#[test]
fn every_odd_automorphism_matches_dft_and_signed_row_rotations() {
    for n in [32, 64] {
        let p = 257;
        let encoder = BatchingEncoder::try_new(PolyLength::new(n), BarrettModulus::new(p)).unwrap();
        let coefficients: Vec<_> = (0..n).map(|i| (i as u64 * 13 + p - 1) % p).collect();
        let slots = evaluate(&coefficients, p);
        let mut actual = vec![0; n];
        for exponent in (1..2 * n).step_by(2) {
            encoder.automorphism_slots_to(&slots, exponent, &mut actual);
            assert_eq!(
                actual,
                evaluate(&automorphism(&coefficients, exponent, p), p)
            );
        }
        for steps in [isize::MIN, -33, -1, 0, 1, 31, 64, isize::MAX] {
            encoder.automorphism_slots_to(&slots, encoder.rotation_exponent(steps), &mut actual);
            let shift = steps.rem_euclid((n / 2) as isize) as usize;
            for row in 0..2 {
                for column in 0..n / 2 {
                    assert_eq!(
                        actual[row * n / 2 + column],
                        slots[row * n / 2 + (column + shift) % (n / 2)]
                    );
                }
            }
        }
        encoder.automorphism_slots_to(&slots, encoder.row_swap_exponent(), &mut actual);
        assert_eq!(&actual[..n / 2], &slots[n / 2..]);
        assert_eq!(&actual[n / 2..], &slots[..n / 2]);
        // The exponent is explicitly modular, including values near usize::MAX.
        encoder.automorphism_slots_to(&slots, usize::MAX, &mut actual);
        assert_eq!(
            actual,
            evaluate(&automorphism(&coefficients, usize::MAX % (2 * n), p), p)
        );
    }
}

#[test]
fn invalid_batch_boundaries_fail_before_output_or_scratch_writes() {
    let encoder = BatchingEncoder::try_new(PolyLength::new(32), BarrettModulus::new(257)).unwrap();
    let invalid = [257; 32];
    let valid = [1; 32];
    let mut output = [19; 32];
    let mut scratch = [23; 32];
    for slots in [&invalid[..], &[0; 33][..]] {
        assert!(catch_unwind(AssertUnwindSafe(|| encoder.encode_to(slots, &mut output))).is_err());
        assert_eq!(output, [19; 32]);
    }
    assert!(
        catch_unwind(AssertUnwindSafe(
            || encoder.encode_to(&valid, &mut output[..31])
        ))
        .is_err()
    );
    assert_eq!(output, [19; 32]);
    assert!(
        catch_unwind(AssertUnwindSafe(|| encoder.decode_to(
            &invalid,
            &mut output,
            &mut scratch
        )))
        .is_err()
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| encoder.decode_to(
            &valid,
            &mut output,
            &mut scratch[..31]
        )))
        .is_err()
    );
    assert_eq!(output, [19; 32]);
    assert_eq!(scratch, [23; 32]);
    assert!(
        catch_unwind(AssertUnwindSafe(|| encoder.automorphism_slots_to(
            &valid,
            2,
            &mut output
        )))
        .is_err()
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| encoder.automorphism_slots_to(
            &invalid,
            1,
            &mut output
        )))
        .is_err()
    );
    assert!(catch_unwind(AssertUnwindSafe(|| encoder.embed_to(&invalid, &mut output))).is_err());
    assert!(
        catch_unwind(AssertUnwindSafe(
            || encoder.embed_to(&valid, &mut output[..31])
        ))
        .is_err()
    );
    let mut off_subring = [0; 64];
    off_subring[1] = 1;
    assert!(
        catch_unwind(AssertUnwindSafe(
            || encoder.extract_to(&off_subring, &mut output)
        ))
        .is_err()
    );
    assert_eq!(output, [19; 32]);
    assert!(BatchingEncoder::try_new(PolyLength::new(32), BarrettModulus::new(17)).is_err());
    // A valid 32-slot subring modulo 193 does not imply 128 plaintext slots.
    assert!(BatchingEncoder::try_new(PolyLength::new(128), BarrettModulus::new(193)).is_err());
}
