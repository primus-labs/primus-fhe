use primus_integer::DivRemScalar;

fn limbs_to_u128(limbs: &[u32]) -> u128 {
    limbs
        .iter()
        .enumerate()
        .fold(0u128, |value, (index, &limb)| {
            value | ((limb as u128) << (u32::BITS as usize * index))
        })
}

/// Prefilled high limbs reveal partial writes in division-by-one and trimmed-input paths.
#[test]
fn u32_special_cases_clear_the_full_quotient() {
    for (dividend, divisor, expected_quotient, expected_remainder) in [
        ([3u32, 5, 7, 11], 1, [3, 5, 7, 11], 0),
        ([29, 0, 0, 0], 7, [4, 0, 0, 0], 1),
    ] {
        let mut quotient = [u32::MAX; 4];
        let remainder = u32::div_rem_scalar(&dividend, divisor, &mut quotient);

        assert_eq!(quotient, expected_quotient);
        assert_eq!(remainder, expected_remainder);
    }
}

/// Half-word and full-word divisors use native u128 division as an independent oracle.
#[test]
fn u32_dense_and_trimmed_dividends_match_u128() {
    for (dividend, divisor) in [
        (
            [0xfedc_ba98, 0x7654_3210, 0x89ab_cdef, 0x0123_4567],
            132_120_577u32,
        ),
        ([0xfedc_ba98, 0x7654_3210, 0x89ab_cdef, 0x0123_4567], 65_521),
        ([0x89ab_cdef, 0x0123_4567, 0, 0], 132_120_577),
    ] {
        let mut quotient = [u32::MAX; 4];
        let remainder = u32::div_rem_scalar(&dividend, divisor, &mut quotient);
        let value = limbs_to_u128(&dividend);

        assert_eq!(limbs_to_u128(&quotient), value / divisor as u128);
        assert_eq!(remainder as u128, value % divisor as u128);
    }
}
