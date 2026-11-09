//! Shared add/sub contracts for each modulus family, with an independent u128 oracle.
use primus_modulus::{BarrettModulus, CompactModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_reduce::{ReduceAddSlice, ReduceSubSlice};

/// Offset inputs/outputs and guard words cover alias-free slice variants and SIMD tails.
#[test]
fn add_sub_slices_cover_unaligned_ranges_and_vector_tails() {
    macro_rules! check {
        ($t:ty, $modulus:expr, $q:expr) => {{
            let modulus = $modulus;
            let q: u128 = $q;
            // One and two vector blocks with tails; no separate large-length dispatch.
            for len in [0, 1, 7, 8, 15, 16, 17, 31, 32, 33] {
                let lhs: Vec<_> = (0..len + 3)
                    .map(|i| {
                        if i % 2 == 0 {
                            (q - 1 - i as u128 % q) as $t
                        } else {
                            (i as u128 % q) as $t
                        }
                    })
                    .collect();
                let rhs: Vec<_> = (0..len + 3)
                    .map(|i| ((i * 31 + 1) as u128 % q) as $t)
                    .collect();
                let (lhs, rhs) = (&lhs[1..len + 1], &rhs[3..]);
                let add: Vec<_> = lhs
                    .iter()
                    .zip(rhs)
                    .map(|(&a, &b)| ((a as u128 + b as u128) % q) as $t)
                    .collect();
                let sub: Vec<_> = lhs
                    .iter()
                    .zip(rhs)
                    .map(|(&a, &b)| ((a as u128 + q - b as u128) % q) as $t)
                    .collect();
                let mut storage = vec![7; len + 2];
                let output = &mut storage[1..len + 1];
                modulus.reduce_add_slice_to(lhs, rhs, output);
                assert_eq!(output, add);
                output.copy_from_slice(lhs);
                modulus.reduce_add_slice_assign(output, rhs);
                assert_eq!(output, add);
                modulus.reduce_sub_slice_to(lhs, rhs, output);
                assert_eq!(output, sub);
                output.copy_from_slice(lhs);
                modulus.reduce_sub_slice_assign(output, rhs);
                assert_eq!(output, sub);
                output.copy_from_slice(rhs);
                modulus.reduce_sub_slice_rev_assign(lhs, output);
                assert_eq!(output, sub);
                assert_eq!((storage[0], storage[len + 1]), (7, 7));
            }
        }};
    }
    macro_rules! check_word {
        ($t:ty) => {{
            check!($t, NativeModulus::<$t>::new(), 1u128 << <$t>::BITS);
            // Small and largest legal compact moduli exercise both reduction outcomes.
            for q in [2 as $t, 257, (1 << (<$t>::BITS - 2)) - 1] {
                check!($t, BarrettModulus::new(q), q as u128);
                check!($t, CompactModulus::new(q), q as u128);
            }
            for q in [2 as $t, 1 << (<$t>::BITS - 1)] {
                check!($t, PowOf2Modulus::new(q), q as u128);
            }
            // Full-width moduli force wrapping carry/borrow rather than compact arithmetic.
            check!($t, UintModulus(<$t>::MAX - 4), (<$t>::MAX - 4) as u128);
        }};
    }
    check_word!(u32);
    check_word!(u64);
}
