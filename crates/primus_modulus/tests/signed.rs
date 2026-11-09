use primus_integer::{AsFrom, AsInto, FheUint};
use primus_modulus::{BarrettModulus, CompactModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_reduce::{EncodeSigned, Modulus, ReduceDotProductSigned};

/// Widen signed products before modular reduction; mixed signs and maximal products stress accumulation.
#[test]
fn signed_dot_products_match_integer_remainders() {
    fn check<T: FheUint>(modulus: impl Modulus<ValueT = T> + ReduceDotProductSigned<T>) {
        let q = modulus
            .explicit_value()
            .map_or(1i128 << T::BITS, |q| q.as_into());
        let lo = (-(1i128 << (T::BITS - 1))).max(1 - q);
        let hi = ((1i128 << (T::BITS - 1)) - 1).min(q - 1);
        // Two scalar accumulation blocks plus a tail cover reuse without an arbitrary LWE size.
        let lengths = [0, 1, 15, 16, 17, 33].into_iter();
        #[cfg(feature = "simd")]
        let lengths = {
            let block = 16 * T::LANE_COUNT;
            lengths.chain([block - 1, block, block + 1, 2 * block + 1])
        };
        for len in lengths {
            // The first case maximizes each encoded product, exercising the
            // two-limb accumulator at the largest supported Barrett modulus.
            for mixed in [false, true] {
                let lhs: Vec<T> = (0..len)
                    .map(|i| {
                        T::as_from(if mixed {
                            [0, 1, q / 2, q - 2, q - 1][i % 5]
                        } else {
                            q - 1
                        })
                    })
                    .collect();
                let rhs: Vec<T::SignedInteger> = (0..len)
                    .map(|i| {
                        T::SignedInteger::as_from(if mixed {
                            [lo, hi, -1, 0, 1][(i / 5 + i) % 5]
                        } else {
                            -1
                        })
                    })
                    .collect();
                // An individual u64 * i64 product fits i128. Reduce each term
                // before adding so the oracle cannot overflow on long inputs.
                let expected = lhs.iter().zip(&rhs).fold(0i128, |acc, (&a, &s)| {
                    let a: i128 = a.as_into();
                    let s: i128 = s.as_into();
                    (acc + (a * s).rem_euclid(q)) % q
                });
                assert_eq!(
                    modulus.reduce_dot_product_signed(&lhs, &rhs),
                    T::as_from(expected),
                    "q={q}, len={len}, mixed={mixed}"
                );
            }
        }
        for (lhs, rhs) in [
            (&[T::ZERO][..], &[][..]),
            (&[][..], &[T::SignedInteger::as_from(0i32)][..]),
        ] {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    modulus.reduce_dot_product_signed(lhs, rhs)
                }))
                .is_err()
            );
        }
    }
    fn check_moduli<T: FheUint>() {
        check(NativeModulus::<T>::new());
        for q in [T::as_from(2u32), T::ONE << (T::BITS - 1)] {
            check(PowOf2Modulus::new(q));
        }
        for q in [
            T::as_from(2u32),
            T::as_from(97u32),
            (T::ONE << (T::BITS - 2)) - T::ONE,
        ] {
            check(BarrettModulus::new(q));
        }
    }
    check_moduli::<u16>();
    check_moduli::<u32>();
    check_moduli::<u64>();
    #[cfg(feature = "derive")]
    {
        #[derive(primus_modulus::Barrett)]
        #[modulus(ty = u32, value = 97)]
        struct SmallModulus;
        #[derive(primus_modulus::Barrett)]
        #[modulus(ty = u64, value = 4611686018427387903)]
        struct WideModulus;
        check(SmallModulus);
        check(WideModulus);
    }
}

/// Compare canonical signed encoding with Euclidean remainders at word and modulus boundaries.
#[test]
fn bounded_signed_encoding_matches_integer_remainders() {
    fn check<T: FheUint>(modulus: impl EncodeSigned<T>) {
        let q = modulus
            .explicit_value()
            .map_or(1i128 << T::BITS, |q| q.as_into());
        let min = -(1i128 << (T::BITS - 1));
        let max = -min - 1;
        let input: Vec<T::SignedInteger> = [
            min,
            min + 1,
            -(q - 1),
            -98,
            -97,
            -96,
            -1,
            0,
            1,
            96,
            97,
            98,
            q - 1,
            max,
        ]
        .into_iter()
        .filter(|&v| v >= min && v <= max && v.abs() < q)
        .map(T::SignedInteger::as_from)
        .cycle()
        .take(65)
        .collect();
        for length in [0, 1, input.len()] {
            let input = &input[..length];
            let expected: Vec<T> = input
                .iter()
                .map(|&v| {
                    let v: i128 = v.as_into();
                    T::as_from(v.rem_euclid(q))
                })
                .collect();
            let mut output = vec![T::MAX; input.len()];
            modulus.encode_signed_slice_to(input, &mut output);
            assert_eq!(output, expected);
            for (&value, &expected) in input.iter().zip(&expected) {
                assert_eq!(modulus.encode_signed(value), expected);
            }
        }
    }
    fn check_moduli<T: FheUint>() {
        check(NativeModulus::<T>::new());
        check(BarrettModulus::new(T::as_from(97u32)));
        check(CompactModulus::new(T::as_from(97u32)));
        check(UintModulus::new(T::as_from(97u32)));
        // A full-width explicit modulus includes signed MIN in the bounded domain.
        check(UintModulus::new(T::MAX));
        check(PowOf2Modulus::new(T::ONE << 7u32));
        check(PowOf2Modulus::new(T::ONE << (T::BITS - 1)));
    }
    check_moduli::<u16>();
    check_moduli::<u32>();
    check_moduli::<u64>();
    #[cfg(feature = "derive")]
    {
        #[derive(primus_modulus::Barrett)]
        #[modulus(ty = u64, value = 97)]
        struct DerivedModulus;
        check(DerivedModulus);
    }
}

/// A public slice mismatch must be rejected before modifying its destination.
#[test]
fn signed_slice_length_is_checked_before_writing() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let modulus = UintModulus::new(97u32);
    for input in [&[-1i32][..], &[-1, 0, 1][..]] {
        let mut output = [17; 2];
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                modulus.encode_signed_slice_to(input, &mut output);
            }))
            .is_err()
        );
        assert_eq!(output, [17; 2]);
    }
}
