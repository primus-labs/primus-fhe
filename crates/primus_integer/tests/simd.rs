#![cfg(feature = "simd")]
#![cfg_attr(feature = "simd", feature(portable_simd))]

use primus_integer::{
    BorrowingSub, CarryingAdd, CarryingMul, LaneArray, SimdArray, SimdInteger, SimdMaskArray,
    SimdUnsignedArray, WideningMul,
};

/// Mixed extreme lanes check carry, borrow, and widening products against scalar operations.
#[test]
fn u32_simd_word_operations_match_scalar_lanes() {
    type U32Simd = <u32 as SimdInteger>::SimdT;
    type U32Array = <u32 as SimdInteger>::Array;
    type U32Mask = <u32 as SimdInteger>::MaskT;

    let max = <U32Simd as SimdArray<u32>>::splat(u32::MAX);
    let one = <U32Simd as SimdArray<u32>>::splat(1);
    let zero = <U32Simd as SimdArray<u32>>::splat(0);
    let (sum, overflow) = SimdUnsignedArray::overflowing_add(max, one);
    assert_eq!(sum, zero);
    assert!(SimdMaskArray::<u32>::all(overflow));

    let lhs_array: U32Array = LaneArray::from_fn(|index| {
        [
            0,
            1,
            u32::MAX,
            u32::MAX,
            0x8000_0000,
            0x7fff_ffff,
            123_456_789,
            4_000_000_000,
        ][index % 8]
    });
    let rhs_array: U32Array = LaneArray::from_fn(|index| {
        [
            0,
            u32::MAX,
            1,
            u32::MAX,
            0x8000_0000,
            2,
            987_654_321,
            500_000_000,
        ][index % 8]
    });
    let carry_array: U32Array = LaneArray::from_fn(|index| index as u32);
    let add_array: U32Array = LaneArray::from_fn(|index| (u32::LANE_COUNT - 1 - index) as u32);
    let mask_array: <u32 as SimdInteger>::Selector =
        core::array::from_fn(|index| matches!(index % 8, 1 | 3 | 4 | 6));

    let lhs = <U32Simd as SimdArray<u32>>::from_array(lhs_array);
    let rhs = <U32Simd as SimdArray<u32>>::from_array(rhs_array);
    let carry = <U32Simd as SimdArray<u32>>::from_array(carry_array);
    let add = <U32Simd as SimdArray<u32>>::from_array(add_array);
    let mask = <U32Mask as SimdMaskArray<u32>>::from_array(mask_array);

    let (sum, sum_carry) = CarryingAdd::carrying_add(lhs, rhs, mask);
    let (difference, borrow) = BorrowingSub::borrowing_sub(lhs, rhs, mask);
    let (product_low, product_high) = WideningMul::widening_mul(lhs, rhs);
    let product_high_only = WideningMul::widening_mul_hw(lhs, rhs);
    let (carry_low, carry_high) = CarryingMul::carrying_mul(lhs, rhs, carry);
    let carry_high_only = CarryingMul::carrying_mul_hw(lhs, rhs, carry);
    let (add_low, add_high) = CarryingMul::carrying_mul_add(lhs, rhs, carry, add);
    let add_high_only = CarryingMul::carrying_mul_add_hw(lhs, rhs, carry, add);

    let lhs_array: &[u32] = lhs_array.as_ref();
    let rhs_array: &[u32] = rhs_array.as_ref();
    let carry_array: &[u32] = carry_array.as_ref();
    let add_array: &[u32] = add_array.as_ref();

    for index in 0..u32::LANE_COUNT {
        let carry_in = matches!(index % 8, 1 | 3 | 4 | 6);
        assert_eq!(
            (sum[index], sum_carry.test(index)),
            CarryingAdd::carrying_add(lhs_array[index], rhs_array[index], carry_in),
        );
        assert_eq!(
            (difference[index], borrow.test(index)),
            BorrowingSub::borrowing_sub(lhs_array[index], rhs_array[index], carry_in),
        );
        assert_eq!(
            (product_low[index], product_high[index]),
            WideningMul::widening_mul(lhs_array[index], rhs_array[index]),
        );
        assert_eq!(product_high_only[index], product_high[index]);
        assert_eq!(
            (carry_low[index], carry_high[index]),
            CarryingMul::carrying_mul(lhs_array[index], rhs_array[index], carry_array[index]),
        );
        assert_eq!(carry_high_only[index], carry_high[index]);
        assert_eq!(
            (add_low[index], add_high[index]),
            CarryingMul::carrying_mul_add(
                lhs_array[index],
                rhs_array[index],
                carry_array[index],
                add_array[index],
            ),
        );
        assert_eq!(add_high_only[index], add_high[index]);
    }
}

/// Full-width lane products exercise high halves and carry variants against scalar arithmetic.
#[test]
fn u64_simd_multiplication_matches_scalar_lanes() {
    type U64Simd = <u64 as SimdInteger>::SimdT;
    type U64Array = <u64 as SimdInteger>::Array;

    let lhs_array: U64Array =
        LaneArray::from_fn(|index| [0, 1, u64::MAX, 0x8000_0000_0000_0001][index % 4]);
    let rhs_array: U64Array =
        LaneArray::from_fn(|index| [u64::MAX, 7, u64::MAX, 0x7fff_ffff_ffff_ffff][index % 4]);
    let carry_array: U64Array = LaneArray::from_fn(|index| index as u64 + 1);
    let add_array: U64Array = LaneArray::from_fn(|index| (u64::LANE_COUNT - index) as u64);

    let lhs = <U64Simd as SimdArray<u64>>::from_array(lhs_array);
    let rhs = <U64Simd as SimdArray<u64>>::from_array(rhs_array);
    let carry = <U64Simd as SimdArray<u64>>::from_array(carry_array);
    let add = <U64Simd as SimdArray<u64>>::from_array(add_array);
    let (product_low, product_high) = WideningMul::widening_mul(lhs, rhs);
    let product_high_only = WideningMul::widening_mul_hw(lhs, rhs);
    let (carry_low, carry_high) = CarryingMul::carrying_mul(lhs, rhs, carry);
    let carry_high_only = CarryingMul::carrying_mul_hw(lhs, rhs, carry);
    let (add_low, add_high) = CarryingMul::carrying_mul_add(lhs, rhs, carry, add);
    let add_high_only = CarryingMul::carrying_mul_add_hw(lhs, rhs, carry, add);

    let lhs_array: &[u64] = lhs_array.as_ref();
    let rhs_array: &[u64] = rhs_array.as_ref();
    let carry_array: &[u64] = carry_array.as_ref();
    let add_array: &[u64] = add_array.as_ref();

    for index in 0..u64::LANE_COUNT {
        assert_eq!(
            (product_low[index], product_high[index]),
            WideningMul::widening_mul(lhs_array[index], rhs_array[index]),
        );
        assert_eq!(product_high_only[index], product_high[index]);
        assert_eq!(
            (carry_low[index], carry_high[index]),
            CarryingMul::carrying_mul(lhs_array[index], rhs_array[index], carry_array[index]),
        );
        assert_eq!(carry_high_only[index], carry_high[index]);
        assert_eq!(
            (add_low[index], add_high[index]),
            CarryingMul::carrying_mul_add(
                lhs_array[index],
                rhs_array[index],
                carry_array[index],
                add_array[index],
            ),
        );
        assert_eq!(add_high_only[index], add_high[index]);
    }
}
