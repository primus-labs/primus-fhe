use primus_decompose::{ApproxSignedBasisError, big_integer::BigUintApproxSignedBasis};
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_integer::{AsFrom, BigUint, FheUint};
use rand::{RngExt, SeedableRng, rngs::StdRng};

// Test products fit in u128, so the oracle does not depend on BigUint arithmetic.
fn to_u128<T: FheUint + Into<u128>>(limbs: &[T]) -> u128 {
    limbs
        .iter()
        .rev()
        .fold(0, |value, &limb| (value << T::BITS) | limb.into())
}

fn limbs<T: FheUint + AsFrom<u128>>(value: u128, len: usize) -> Vec<T> {
    (0..len)
        .map(|index| T::as_from(value >> (index as u32 * T::BITS)))
        .collect()
}

// Compute the centered-wrap threshold with a wide scalar oracle.
fn wrap_threshold(log_basis: u32, levels: usize, drop_bits: u32) -> u128 {
    let radix = 1u128 << log_basis;
    let step = 1u128 << drop_bits;
    (0..levels)
        .map(|level| (radix / 2 - 1) << (drop_bits + level as u32 * log_basis))
        .sum::<u128>()
        + if drop_bits == 0 { 1 } else { step / 2 }
}

// Round/drop thresholds and 32/64-bit limb crossings carry the regression
// coverage; a few fixed-seed interior samples check non-boundary digit patterns.
fn inputs(q: u128, log_basis: u32, levels: usize, drop_bits: u32) -> Vec<u128> {
    let step = 1u128 << drop_bits;
    let threshold = wrap_threshold(log_basis, levels, drop_bits);
    let mut values = vec![0, 1, q / 2, q - 1];
    for boundary in [step / 2, step, threshold, 1 << 32, 1 << 64] {
        for value in [boundary.saturating_sub(1), boundary, boundary + 1] {
            if value < q {
                values.push(value);
            }
        }
    }
    let mut rng = StdRng::seed_from_u64(0x4445_434f_4d50);
    values.extend((0..8).map(|_| rng.random_range(0..q)));
    values.sort_unstable();
    values.dedup();
    values
}

fn assert_contract<T>(moduli: &[T], log_basis: u32, retained: Option<usize>)
where
    T: FheUint + Into<u128> + AsFrom<u128>,
{
    let q: u128 = moduli.iter().map(|&m| m.into()).product();
    let modulus = BigUint(limbs::<T>(q, (q.ilog2() + 1).div_ceil(T::BITS) as usize));
    let basis = BigUintApproxSignedBasis::try_new(
        modulus.view(),
        DecompositionBaseLog::new(log_basis),
        retained.map(DecompositionLevelCount::new),
    )
    .unwrap();
    let levels = retained.unwrap_or(((q.ilog2() + 1) / log_basis) as usize);
    let drop_bits = q.ilog2() + 1 - levels as u32 * log_basis;
    let bound = if drop_bits == 0 {
        0
    } else {
        1 << (drop_bits - 1)
    };
    let radix = 1i128 << log_basis;
    let len = basis.big_uint_value_len();
    assert_eq!(to_u128(basis.modulus()), q);
    assert_eq!(basis.drop_bits(), drop_bits);
    assert_eq!(basis.level_count().get(), levels);
    assert_eq!(basis.decomposer_iter().len(), levels);
    assert_eq!(basis.scalar_iter().len(), levels);
    assert_eq!(to_u128(basis.approximate_error_bound().digits()), bound);

    for (level, scalar) in basis.scalar_iter().enumerate() {
        let expected = 1u128 << (drop_bits + level as u32 * log_basis);
        assert_eq!(to_u128(scalar), expected);
    }

    let threshold = wrap_threshold(log_basis, levels, drop_bits);
    let adjustment = (1u128 << (q.ilog2() + 1)) - q;
    let mut value = vec![T::ZERO; len];
    let mut adjusted = vec![T::ZERO; len];
    let mut digit = vec![T::ZERO; len];
    let mut carries = [false];
    for input in inputs(q, log_basis, levels, drop_bits) {
        for (index, limb) in value.iter_mut().enumerate() {
            *limb = T::as_from(input >> (index as u32 * T::BITS));
        }
        basis.init_value_carry_slice_to(&value, &mut adjusted, &mut carries);
        let expected_adjusted = input + if input >= threshold { adjustment } else { 0 };
        let mut expected_carry =
            drop_bits != 0 && expected_adjusted & (1u128 << (drop_bits - 1)) != 0;
        assert_eq!(to_u128(&adjusted), expected_adjusted);
        assert_eq!(carries[0], expected_carry);
        let mut sum = 0i128;
        for (level, decomposer) in basis.decomposer_iter().enumerate() {
            let (radix_digit, radix_carry) = decomposer.decompose_radix(&adjusted, carries[0]);
            decomposer.decompose_slice_to(&adjusted, &mut digit, &mut carries);
            let offset = drop_bits + level as u32 * log_basis;
            let window = ((expected_adjusted >> offset) & (radix as u128 - 1)) as i128;
            let temp = window + i128::from(expected_carry);
            expected_carry = temp >= radix / 2;
            let expected_digit = temp - if expected_carry { radix } else { 0 };
            assert_eq!(carries[0], expected_carry);
            assert_eq!(radix_carry, expected_carry);
            let radix_digit = radix_digit.into() as i128;
            assert!((0..radix).contains(&radix_digit));
            let centered = if radix_digit >= radix / 2 {
                radix_digit - radix
            } else {
                radix_digit
            };
            assert_eq!(centered, expected_digit);
            assert_eq!(to_u128(&digit), centered.rem_euclid(q as i128) as u128);
            sum += centered * (1i128 << (drop_bits + level as u32 * log_basis));
        }
        let output = sum.rem_euclid(q as i128) as u128;
        let distance = input.abs_diff(output);
        let error = distance.min(q - distance);
        assert!(
            error <= bound,
            "q={q}, logB={log_basis}, levels={levels}, input={input}, output={output}, error={error}, bound={bound}"
        );
    }
}

#[test]
fn retained_levels_match_modular_oracle() {
    // BigUint deliberately uses bit_width(Q), including for powers of two.
    // Cover both ends of the 64-bit-wide range, with/without rounding.
    for q in [1u64 << 63, u64::MAX] {
        for log_basis in [7, 8] {
            assert_contract(&[q], log_basis, None);
        }
    }
    let moduli = [134_215_681u32, 134_176_769];
    for log_basis in [3, 5, 7] {
        assert_contract(&moduli, log_basis, None);
    }
    // 49-bit product: start the retained levels before, at, and beyond bit 32.
    let moduli = [65_537u32, 65_539, 65_543];
    for (log_basis, retained) in [(3, 6), (17, 1), (4, 4), (4, 1), (31, 1)] {
        assert_contract(&moduli, log_basis, Some(retained));
    }
    // 100-bit product exercises the same boundaries for 64-bit limbs.
    let moduli = [1_125_899_906_826_241u64, 1_125_899_906_629_633];
    // logB=BITS-1 also exercises the highest carry bit in a crossing window.
    for (log_basis, retained) in [(4, 10), (3, 12), (4, 8), (63, 1)] {
        assert_contract(&moduli, log_basis, Some(retained));
    }
}

#[test]
fn batch_matches_scalar_decomposition() {
    check_batch::<u32>();
    check_batch::<u64>();
}

fn check_batch<T: FheUint>() {
    // Fixed strides 1/2/4 and fallback 3. A whole-limb bit width gives no
    // rounding with logB=16, and dropped bits/cross-limb windows with logB=17.
    for len in [1, 2, 3, 4] {
        let mut modulus = vec![T::MAX; len];
        modulus[0] -= T::as_from(58u8);
        modulus[len - 1] -= T::as_from(2u8);
        for log_basis in [16, 17] {
            let basis = BigUintApproxSignedBasis::new(
                BigUint(&modulus[..]),
                DecompositionBaseLog::new(log_basis),
                None,
            );
            // Empty input, a single value, and a batch with a vectorization tail.
            for count in [0, 1, 33] {
                let mut values: Vec<T> = (0..count * len)
                    .map(|i| T::as_from((i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)))
                    .collect();
                for value in values.chunks_exact_mut(len) {
                    value[len - 1] %= modulus[len - 1];
                }
                if count != 0 {
                    // Q-1 adjusts to all ones, exercising zero digits that
                    // still propagate carry through later levels.
                    values[..len].copy_from_slice(&modulus);
                    values[0] -= T::ONE;
                }
                let mut adjusted = vec![T::MAX; values.len()];
                let mut carries = vec![true; count];
                basis.init_value_carry_slice_to(&values, &mut adjusted, &mut carries);
                let mut in_place = values.clone();
                let mut in_place_carries = vec![true; count];
                basis.init_value_carry_slice_assign(&mut in_place, &mut in_place_carries);
                assert_eq!(adjusted, in_place);
                assert_eq!(carries, in_place_carries);
                let mut signed_digits = vec![T::MAX; values.len()];
                let mut radix_digits = vec![T::MAX; count];
                let mut expected_digit = vec![T::ZERO; len];
                let radix = basis.basis_value();
                for decomposer in basis.decomposer_iter() {
                    let previous_carries = carries.clone();
                    let mut radix_carries = carries.clone();
                    decomposer.decompose_slice_to(&adjusted, &mut signed_digits, &mut carries);
                    decomposer.decompose_radix_slice_to(
                        &adjusted,
                        &mut radix_digits,
                        &mut radix_carries,
                    );
                    assert_eq!(carries, radix_carries);
                    for (index, value) in adjusted.chunks_exact(len).enumerate() {
                        let (digit, carry) =
                            decomposer.decompose_radix(value, previous_carries[index]);
                        assert_eq!(
                            (radix_digits[index], carries[index]),
                            (digit, carry),
                            "limbs={len}, logB={log_basis}, count={count}, index={index}",
                        );
                        // Full-width digits encode the same centered value modulo Q,
                        // whereas compact digits encode it modulo B.
                        if digit >= radix / T::TWO {
                            expected_digit.copy_from_slice(&modulus);
                            let borrow =
                                BigUint(&mut expected_digit[..]).sub_value_assign(radix - digit);
                            assert!(!borrow);
                        } else {
                            expected_digit.fill(T::ZERO);
                            expected_digit[0] = digit;
                        }
                        assert_eq!(
                            &signed_digits[index * len..(index + 1) * len],
                            expected_digit,
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn invalid_parameters_and_modulus_representations_are_rejected() {
    let modulus = BigUint([17_u32 * 97]);
    for (log_basis, retained, expected) in [
        (
            32,
            None,
            ApproxSignedBasisError::InvalidLogBasis {
                log_basis: 32,
                limb_bits: 32,
            },
        ),
        (
            4,
            Some(3),
            ApproxSignedBasisError::LevelCountTooLarge {
                level_count: 3,
                full_level_count: 2,
            },
        ),
    ] {
        assert_eq!(
            BigUintApproxSignedBasis::try_new(
                modulus.view(),
                DecompositionBaseLog::new(log_basis),
                retained.map(DecompositionLevelCount::new)
            )
            .unwrap_err(),
            expected
        );
    }
    assert_eq!(
        BigUintApproxSignedBasis::try_new(BigUint(&[3_u32]), DecompositionBaseLog::new(2), None)
            .unwrap_err(),
        ApproxSignedBasisError::BasisExceedsModulus
    );
    for invalid in [&[][..], &[0][..], &[1649, 0][..]] {
        assert_eq!(
            BigUintApproxSignedBasis::<u32>::try_new(
                BigUint(invalid),
                DecompositionBaseLog::new(4),
                None
            )
            .unwrap_err(),
            ApproxSignedBasisError::InvalidModulusRepresentation
        );
    }
    // Zero low limbs are valid; only redundant high zero limbs are rejected.
    assert!(
        BigUintApproxSignedBasis::try_new(BigUint(&[0_u32, 1]), DecompositionBaseLog::new(4), None)
            .is_ok()
    );
}
