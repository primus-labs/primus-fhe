//! Wide-product oracles cover scalar tails, portable SIMD, and native dispatch.

#[cfg(feature = "simd")]
use primus_factor::SimdFactorMul;
use primus_factor::{FactorMul, FactorSliceOps, LazyFactorSliceOps, ShoupFactor};
use primus_integer::FheUint;
#[cfg(feature = "simd")]
use primus_integer::{LaneArray, SimdArray, SimdInteger};

type ValueT = u32;

const MODULUS: ValueT = 536_813_569;
const SECOND_MODULUS: ValueT = 998_244_353;

/// Resetting either value or modulus must refresh the cached quotient.
#[test]
fn reset_matches_wide_product() {
    // Check the current state before another setter can repair a stale quotient.
    let check = |factor: ShoupFactor<u32>, value: u32, modulus: u32| {
        for rhs in [0, 1, modulus - 1, u32::MAX] {
            let expected = (u64::from(value) * u64::from(rhs) % u64::from(modulus)) as u32;
            assert_eq!(factor.factor_mul_modulo(rhs, modulus), expected);
        }
    };
    let mut factor = ShoupFactor::new(1, MODULUS);
    for value in [0, 1, MODULUS / 2, MODULUS - 1] {
        factor.set(value, MODULUS);
        check(factor, value, MODULUS);

        factor.set_modulus(SECOND_MODULUS);
        check(factor, value, SECOND_MODULUS);
    }
}

/// Distinct factors per lane test the vector representation, independently of broadcast slice kernels.
#[cfg(feature = "simd")]
#[test]
fn per_lane_simd_factors_match_scalar_multiplication() {
    type SimdValueT = u64;
    type SimdT = <SimdValueT as SimdInteger>::SimdT;

    const SIMD_MODULUS: SimdValueT = 1_152_921_504_606_830_593;

    let factors: Vec<_> = (0..<SimdValueT as SimdInteger>::LANE_COUNT)
        .map(|lane| ShoupFactor::new(17 * lane as SimdValueT + 3, SIMD_MODULUS))
        .collect();
    let rhs_array =
        <SimdValueT as SimdInteger>::Array::from_fn(|lane| 31 * lane as SimdValueT + 11);

    let simd_factor =
        <ShoupFactor<SimdValueT> as SimdFactorMul<SimdValueT>>::simd_from_factor_slice(&factors);
    let rhs = <SimdT as SimdArray<SimdValueT>>::from_array(rhs_array);
    let modulus = <SimdT as SimdArray<SimdValueT>>::splat(SIMD_MODULUS);
    let actual =
        <SimdT as SimdArray<SimdValueT>>::to_array(simd_factor.factor_mul_modulo(rhs, modulus));
    let expected: Vec<_> = factors
        .iter()
        .zip(rhs_array)
        .map(|(&factor, rhs)| factor.factor_mul_modulo(rhs, SIMD_MODULUS))
        .collect();

    assert_eq!(actual.as_ref(), expected);
}

/// Full-word operands and extreme factors check canonical/lazy output at vector and dispatch boundaries.
#[test]
fn slice_mul_against_wide_product() {
    fn check<T: FheUint + TryFrom<u64> + Into<u128>>(q: u64) {
        let convert = |value| T::try_from(value).ok().unwrap();
        let modulus = convert(q);
        let mut state = 0x1234_5678_9abc_def0u64;
        for len in [0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 64, 65] {
            let input: Vec<T> = (0..len)
                .map(|i| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    // Shoup's scalar formula also accepts full-word operands;
                    // exercise that range in both the vector body and tail.
                    convert(match i % 6 {
                        0 => 0,
                        1 => q - 1,
                        2 => T::MAX.into() as u64,
                        3 => q,
                        _ => state & (T::MAX.into() as u64),
                    })
                })
                .collect();
            for factor_value in [0, 1, 17 % q, q / 2, q - 1] {
                let factor = ShoupFactor::new(convert(factor_value), modulus);
                let expected: Vec<T> = input
                    .iter()
                    .map(|&value| {
                        convert((u128::from(factor_value) * value.into() % u128::from(q)) as u64)
                    })
                    .collect();
                // Offset the in-place slice and guard both ends, including empty input.
                let mut assign = vec![T::MAX; len + 2];
                assign[1..len + 1].copy_from_slice(&input);
                factor.factor_mul_slice_assign(&mut assign[1..len + 1], modulus);
                assert_eq!(&assign[1..len + 1], expected);
                assert_eq!(assign[0], T::MAX);
                assert_eq!(assign[len + 1], T::MAX);

                let mut output = vec![T::MAX; len + 2];
                factor.factor_mul_slice_to(&input, &mut output[1..len + 1], modulus);
                assert_eq!(&output[1..len + 1], expected);
                assert_eq!(output[0], T::MAX);
                assert_eq!(output[len + 1], T::MAX);

                let mut lazy_assign = input.clone();
                factor.lazy_factor_mul_slice_assign(&mut lazy_assign, modulus);
                factor.lazy_factor_mul_slice_to(&input, &mut output[1..len + 1], modulus);
                for values in [lazy_assign.as_slice(), &output[1..len + 1]] {
                    for (&actual, &expected) in values.iter().zip(&expected) {
                        let actual: u128 = actual.into();
                        assert!(actual < 2 * u128::from(q));
                        assert_eq!(actual % u128::from(q), expected.into());
                    }
                }
            }
        }
    }

    check::<u16>(32749);
    for q in [3, 132_120_577, 536_813_569, (1 << 31) - 1] {
        check::<u32>(q);
    }
    for q in [3, (1 << 32) - 5, 1_125_899_906_826_241, (1 << 63) - 1] {
        check::<u64>(q);
    }
}

/// A reduced u128 product supplies the oracle for fused add/subtract and overwrite operations.
#[test]
fn fused_slice_ops_against_wide_product() {
    fn check<T: FheUint + TryFrom<u64> + Into<u128>>(q: u64) {
        let convert = |value| T::try_from(value).ok().unwrap();
        let modulus = convert(q);
        let wide_q = u128::from(q);
        let mut state = 0xa076_1d64_78bd_642fu64;
        for len in [0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 64, 65] {
            let rhs: Vec<T> = (0..len)
                .map(|i| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    convert(match i % 4 {
                        0 => 0,
                        1 => q - 1,
                        2 => T::MAX.into() as u64,
                        _ => state & (T::MAX.into() as u64),
                    })
                })
                .collect();
            let acc: Vec<T> = (0..len)
                .map(|i| convert([0, q - 1, q / 2][i % 3]))
                .collect();
            for factor_value in [0, 1, 17 % q, q / 2, q - 1] {
                let factor = ShoupFactor::new(convert(factor_value), modulus);
                let products: Vec<u128> = rhs
                    .iter()
                    .map(|&value| u128::from(factor_value) * value.into() % wide_q)
                    .collect();
                let expected_add: Vec<T> = acc
                    .iter()
                    .zip(&products)
                    .map(|(&acc, &product)| convert(((acc.into() + product) % wide_q) as u64))
                    .collect();
                // Offset the output and guard both ends across dispatch and tail boundaries.
                let mut add_assign = vec![T::MAX; len + 2];
                add_assign[1..len + 1].copy_from_slice(&acc);
                factor.add_factor_mul_slice_assign(&mut add_assign[1..len + 1], &rhs, modulus);
                assert_eq!(&add_assign[1..len + 1], expected_add);
                assert_eq!(add_assign[0], T::MAX);
                assert_eq!(add_assign[len + 1], T::MAX);

                let expected_sub: Vec<T> = acc
                    .iter()
                    .zip(&products)
                    .map(|(&acc, &product)| {
                        convert(((acc.into() + wide_q - product) % wide_q) as u64)
                    })
                    .collect();
                let mut sub_assign = acc.clone();
                factor.sub_factor_mul_slice_assign(&mut sub_assign, &rhs, modulus);
                assert_eq!(sub_assign, expected_sub);

                let mut output = vec![T::MAX; len];
                factor.factor_mul_add_slice_to(&rhs, &acc, &mut output, modulus);
                assert_eq!(output, expected_add);
            }
        }
    }
    check::<u16>(32749);
    for q in [3, 132_120_577, (1 << 31) - 1] {
        check::<u32>(q);
    }
    for q in [3, (1 << 32) - 5, 1_125_899_906_826_241, (1 << 63) - 1] {
        check::<u64>(q);
    }
}
