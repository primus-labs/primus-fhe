use primus_integer::DivRemScalar;

fn limbs_to_u128(limbs: [u32; 4]) -> u128 {
    limbs
        .into_iter()
        .rev()
        .fold(0, |value, limb| (value << u32::BITS) | u128::from(limb))
}

/// Check fast exits, dense division and high-zero trimming against native u128.
/// The prefilled quotient makes an omitted write to the high limbs visible.
#[test]
fn u32_quotient_and_remainder_match_u128() {
    let dense = [0xfedc_ba98, 0x7654_3210, 0x89ab_cdef, 0x0123_4567];
    for (dividend, divisor) in [
        ([3, 5, 7, 11], 1),
        ([29, 0, 0, 0], 7),
        (dense, 132_120_577),
        (dense, 65_521),
        ([0x89ab_cdef, 0x0123_4567, 0, 0], 132_120_577),
    ] {
        let mut quotient = [u32::MAX; 4];
        let remainder = u32::div_rem_scalar(&dividend, divisor, &mut quotient);
        let value = limbs_to_u128(dividend);
        let divisor = u128::from(divisor);

        assert_eq!(
            (limbs_to_u128(quotient), u128::from(remainder)),
            (value / divisor, value % divisor),
            "dividend {dividend:?}, divisor {divisor}",
        );
    }
}
