use primus_decompose::{
    ApproxSignedBasisError, DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount,
    primitive::ApproxSignedBasis,
};
use primus_integer::FheUint;

// Recompose with wide arithmetic, independently of the digit extraction,
// and check both centered digit bounds and low-to-high scalar ordering.
fn assert_decomposition_contract<T>(
    basis: &ApproxSignedBasis<T>,
    value: T,
    modulus: Option<T>,
) -> u128
where
    T: FheUint + Into<u128>,
{
    let q = modulus.map(Into::into).unwrap_or(1u128 << T::BITS);
    let input = value.into();
    let radix = 1u128 << basis.log_basis().get();
    let half_radix = radix / 2;

    assert_eq!(basis.scalar_iter().len(), basis.level_count().get());
    let (adjusted, mut carry) = basis.init_value_carry(value);
    let mut recomposed = 0u128;
    for (level, (decomposer, scalar)) in
        basis.decomposer_iter().zip(basis.scalar_iter()).enumerate()
    {
        let scalar = scalar.into();
        assert_eq!(
            scalar,
            1u128 << (basis.drop_bits() + level as u32 * basis.log_basis().get()),
            "level {level} is not ordered from low to high"
        );
        let (raw_digit, next_carry) = decomposer.decompose(adjusted, carry);
        carry = next_carry;

        let raw_digit = raw_digit.into();
        assert!(raw_digit < q);
        let centered_digit = if raw_digit >= q - half_radix {
            raw_digit as i128 - q as i128
        } else {
            raw_digit as i128
        };
        assert!(
            (-((half_radix) as i128)..(half_radix as i128)).contains(&centered_digit),
            "level {level}: digit {centered_digit} is outside [-B/2, B/2)"
        );

        recomposed = (recomposed + scalar * raw_digit) % q;
    }

    let clockwise = (recomposed + q - input) % q;
    let counterclockwise = (input + q - recomposed) % q;
    let error = clockwise.min(counterclockwise);
    assert!(
        error <= basis.approximate_error_bound().into(),
        "q={q}, input={input}, output={recomposed}, error={error}, bound={}",
        Into::<u128>::into(basis.approximate_error_bound())
    );

    recomposed
}

#[test]
fn exhaustive_explicit_moduli_match_contract() {
    // Keep the full 8-bit domain: changing q, radix and retained levels changes
    // the wrap threshold. This is the small independent oracle for wide tests.
    for q in 4u16..=255 {
        for log_basis in 2..u16::BITS {
            if (1u32 << log_basis) > u32::from(q) {
                break;
            }

            let value_bits = if q.is_power_of_two() {
                q.trailing_zeros()
            } else {
                u16::BITS - q.leading_zeros()
            };
            let full_length = value_bits / log_basis;
            for length in 1..=full_length as usize {
                let basis = ApproxSignedBasis::try_from((
                    DecompositionConfig {
                        log_basis: DecompositionBaseLog::new(log_basis),
                        level_count: Some(DecompositionLevelCount::new(length)),
                    },
                    Some(q),
                ))
                .unwrap();
                for value in 0..q {
                    assert_decomposition_contract(&basis, value, Some(q));
                }
            }
        }
    }
}

#[test]
fn native_dropped_bits_use_round_half_up() {
    // Exhaust u16 to cover carry propagation through every retained level,
    // including rounding across the native modulus.
    let basis = ApproxSignedBasis::<u16>::try_from((
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(4),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
        None,
    ))
    .unwrap();
    let q = 1u128 << u16::BITS;
    let step = 1u128 << basis.drop_bits();
    let half_step = step / 2;

    for value in u16::MIN..=u16::MAX {
        let actual = assert_decomposition_contract(&basis, value, None);
        let expected = ((u128::from(value) + half_step) / step * step) % q;
        assert_eq!(actual, expected, "input={value}");
    }
}

#[test]
fn representative_u32_u64_and_ntt_prime_cases_match_contract() {
    let native_u32 = ApproxSignedBasis::<u32>::new(
        None,
        DecompositionBaseLog::new(8),
        Some(DecompositionLevelCount::new(3)),
    );
    for value in [0, 1, (1 << 7) - 1, 1 << 7, (1 << 24) - 1, 1 << 24, u32::MAX] {
        assert_decomposition_contract(&native_u32, value, None);
    }

    let native_u64 = ApproxSignedBasis::<u64>::new(
        None,
        DecompositionBaseLog::new(8),
        Some(DecompositionLevelCount::new(4)),
    );
    for value in [
        0,
        1,
        (1 << 31) - 1,
        1 << 31,
        (1 << 32) - 1,
        1 << 32,
        u64::MAX,
    ] {
        assert_decomposition_contract(&native_u64, value, None);
    }

    const NTT_PRIME: u32 = 1_073_692_673;
    let explicit = ApproxSignedBasis::new(
        Some(NTT_PRIME),
        DecompositionBaseLog::new(8),
        Some(DecompositionLevelCount::new(3)),
    );
    for value in [
        0,
        1,
        NTT_PRIME / 2,
        NTT_PRIME / 2 + 1,
        NTT_PRIME - 2,
        NTT_PRIME - 1,
    ] {
        assert_decomposition_contract(&explicit, value, Some(NTT_PRIME));
    }
}

#[test]
fn invalid_parameters_are_rejected() {
    for (modulus, log_basis, retained, expected) in [
        (
            None,
            32,
            None,
            ApproxSignedBasisError::InvalidLogBasis {
                log_basis: 32,
                limb_bits: 32,
            },
        ),
        (
            Some(13),
            4,
            None,
            ApproxSignedBasisError::BasisExceedsModulus,
        ),
    ] {
        assert_eq!(
            ApproxSignedBasis::<u32>::try_from((
                DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(log_basis),
                    level_count: retained.map(DecompositionLevelCount::new),
                },
                modulus,
            ))
            .unwrap_err(),
            expected
        );
    }
}

#[test]
fn batch_initialization_and_digits_match_scalar() {
    // Plain, carry-only, adjustment-only and combined initialization modes;
    // these kernels use scalar loops, so five boundary values suffice.
    for (modulus, log_basis, retained) in [
        (None, 4, None),
        (None, 4, Some(2)),
        (Some(1 << 16), 6, None),
        (Some(697), 5, None),
        (Some(1_073_692_673), 8, Some(3)),
    ] {
        let basis = ApproxSignedBasis::<u32>::new(
            modulus,
            DecompositionBaseLog::new(log_basis),
            retained.map(DecompositionLevelCount::new),
        );
        let max = modulus.map_or(u32::MAX, |q| q - 1);
        let values = [0, 1, max / 2, max - 1, max];
        let mut adjusted = [u32::MAX; 5];
        let mut carries = [true; 5];
        basis.init_value_carry_slice_to(&values, &mut adjusted, &mut carries);
        if basis.modulus_is_power_of_2() {
            let mut carry_only = [true; 5];
            basis.init_carry_slice(&values, &mut carry_only);
            assert_eq!(adjusted, values);
            assert_eq!(carries, carry_only);
        }
        for index in 0..values.len() {
            assert_eq!(
                (adjusted[index], carries[index]),
                basis.init_value_carry(values[index])
            );
        }
        for decomposer in basis.decomposer_iter() {
            let previous_carries = carries;
            let mut output = [u32::MAX; 5];
            decomposer.decompose_slice_to(&adjusted, &mut output, &mut carries);
            for index in 0..values.len() {
                assert_eq!(
                    (output[index], carries[index]),
                    decomposer.decompose(adjusted[index], previous_carries[index])
                );
            }
        }
    }
}
