//! Sample order and phase signs, compact padding, and packed extraction.

use primus_lattice::{
    glwe::Glwe,
    lwe::{Lwe, MultiMsgLwe},
    ntru::Ntru,
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::{ReduceDotProduct, ReduceSub};

#[test]
fn indexed_extraction_matches_negacyclic_rotation_and_compact_prefix() {
    // Hand-written samples fix both mask-polynomial order and negacyclic signs.
    let glwe = Glwe(vec![
        1u32, 2, 3, 4, // first mask
        5, 6, 7, 8, // second mask
        9, 10, 11, 12, // body
    ]);
    let modulus = NativeModulus::new();
    let expected = [
        [1i32, -4, -3, -2, 5, -8, -7, -6, 9],
        [2, 1, -4, -3, 6, 5, -8, -7, 10],
        [3, 2, 1, -4, 7, 6, 5, -8, 11],
        [4, 3, 2, 1, 8, 7, 6, 5, 12],
    ]
    .map(|sample| sample.map(|x| x as u32));

    for (index, expected) in expected.iter().enumerate() {
        let mut full: Lwe<Vec<u32>> = Lwe::zero(8);
        glwe.extract_lwe_at_to(index, &mut full, 4, modulus);
        assert_eq!(full.0.as_slice(), expected);

        for active_key_len in [1, 3, 4, 5, 7, 8] {
            // Borrow a dirty, offset output; its final mask chunk may be partial.
            let mut storage = [u32::MAX; 11];
            let mut compact = Lwe::new(&mut storage[1..active_key_len + 2]);
            glwe.as_view()
                .extract_compact_lwe_at_to(index, &mut compact, 4, modulus);

            assert_eq!(compact.a(), &expected[..active_key_len]);
            assert_eq!(compact.b(), expected[8]);
            assert_eq!(storage[0], u32::MAX);
            assert!(storage[active_key_len + 2..].iter().all(|&v| v == u32::MAX));
        }
    }
}

#[test]
fn inverse_extraction_is_the_exact_inverse_of_sample_extraction() {
    // Full mask blocks use native wrapping; dirty body slots must be cleared.
    let lwe = Lwe(vec![1u32, 2, 3, 4, 5, 6, 7, 8, 9]);
    let mut glwe = Glwe(vec![u32::MAX; 12]);

    lwe.inverse_extract_glwe_to(&mut glwe, 4, NativeModulus::new());

    assert_eq!(
        glwe.as_ref(),
        [1i32, -4, -3, -2, 5, -8, -7, -6, 9, 0, 0, 0].map(|x| x as u32)
    );

    let mut extracted = Lwe::zero(8);
    glwe.extract_lwe_to(&mut extracted, 4, NativeModulus::new());
    assert_eq!(extracted, lwe);
}

#[test]
fn inverse_extraction_round_trips_with_an_explicit_modulus() {
    // A partial final mask additionally requires zero padding. Explicit q
    // has different negation semantics from the native case above.
    let modulus = BarrettModulus::new(257u64);
    let lwe = Lwe::new(&[1u64, 2, 128, 256, 5, 17, 42][..]);
    let mut storage = [u64::MAX; 14];
    let mut glwe = Glwe::new(&mut storage[1..13]);

    lwe.inverse_extract_glwe_to(&mut glwe, 4, modulus);

    assert_eq!(glwe.as_ref(), [1, 1, 129, 255, 5, 0, 0, 240, 42, 0, 0, 0]);

    let mut extracted: Lwe<Vec<u64>> = Lwe::zero(6);
    glwe.extract_compact_lwe_to(&mut extracted, 4, modulus);
    assert_eq!(extracted.as_ref(), lwe.as_ref());
    assert_eq!(storage[0], u64::MAX);
    assert_eq!(storage[13], u64::MAX);
}

#[test]
fn indexed_extraction_preserves_ntru_and_dimension_one_glwe_phases() {
    // Integer convolution fixes phase signs independently: NTRU uses c*f,
    // whereas GLWE uses b-a*s. A zero secret suffix permits compact extraction.
    const Q: u32 = 97;
    let modulus = BarrettModulus::new(Q);
    let ntru = Ntru::new(vec![13u32, 21, 34, 55, 8, 19, 27, 41]);
    let n = ntru.as_ref().len();
    let body: Vec<u32> = (0..n).map(|i| (i * 3 + 7) as u32).collect();
    let glwe = Glwe::new([ntru.as_ref(), &body].concat());
    // GLWE active lengths exercise both sides of the compact extraction split.
    // NTRU extraction always returns the full N-dimensional sample.
    for active in [1, 3, 5, n] {
        let secret: Vec<u32> = (0..n)
            .map(|i| if i < active { (i % 3 + 1) as u32 } else { 0 })
            .collect();
        let mut phase = vec![0i64; n];
        for (i, &a) in ntru.as_ref().iter().enumerate() {
            for (j, &b) in secret.iter().enumerate() {
                phase[(i + j) % n] += if i + j < n {
                    i64::from(a * b)
                } else {
                    -i64::from(a * b)
                };
            }
        }
        let phase: Vec<u32> = phase
            .into_iter()
            .map(|v| v.rem_euclid(i64::from(Q)) as u32)
            .collect();
        let mut storage = vec![u32::MAX; n + 3];
        let mut full = Lwe::new(&mut storage[1..n + 2]);
        let mut compact: Lwe<Vec<u32>> = Lwe::zero(active);
        for index in 0..n {
            ntru.extract_lwe_at_to(index, &mut full, modulus);
            assert_eq!(full.b(), 0);
            assert_eq!(
                modulus.reduce_sub(full.b(), modulus.reduce_dot_product(full.a(), &secret)),
                phase[index]
            );
            glwe.extract_lwe_at_to(index, &mut full, n, modulus);
            glwe.extract_compact_lwe_at_to(index, &mut compact, n, modulus);
            let expected = (body[index] + Q - phase[index]) % Q;
            for sample in [full.as_view(), compact.as_view()] {
                assert_eq!(
                    modulus.reduce_sub(
                        sample.b(),
                        modulus.reduce_dot_product(sample.a(), &secret[..sample.dimension()])
                    ),
                    expected
                );
            }
        }
        ntru.extract_lwe_to(&mut full, modulus);
        assert_eq!(
            modulus.reduce_sub(full.b(), modulus.reduce_dot_product(full.a(), &secret)),
            phase[0]
        );
        assert_eq!(storage[0], u32::MAX);
        assert_eq!(storage[n + 2], u32::MAX);
    }
}

#[test]
fn packed_extraction_matches_negacyclic_sample_order() {
    let modulus = BarrettModulus::new(97u32);
    // A constant-term extraction mask followed by four bodies. Hand-written
    // samples fix right rotations and the signs of coefficients crossing X^4.
    let storage = [1u32, 2, 3, 4, 10, 20, 30, 40];
    let expected = [
        [1, 2, 3, 4, 10],
        [93, 1, 2, 3, 20],
        [94, 93, 1, 2, 30],
        [95, 94, 93, 1, 40],
    ];
    for count in [1, 2, 4] {
        let packed = MultiMsgLwe::new(&storage[..4 + count]);
        let all = packed.extract_all(count, modulus);
        assert_eq!(all.len(), count);
        for (index, (sample, expected)) in all.iter().zip(&expected).enumerate() {
            assert_eq!(sample.as_ref(), expected);
            assert_eq!(packed.extract_lwe_at(index, 4, modulus).as_ref(), expected);
        }
    }
}

#[test]
fn packed_extraction_rejects_invalid_message_counts() {
    // The public batch extractor rejects zero messages or more messages than mask entries.
    let packed = MultiMsgLwe(vec![1u32, 2, 3, 4]);
    for count in [0, 3] {
        assert!(
            std::panic::catch_unwind(|| packed.extract_all(count, NativeModulus::new())).is_err()
        );
    }
}
