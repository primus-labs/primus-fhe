//! Scalar plaintext factors; none of these metadata operations walk ciphertexts.

#[derive(Clone, Copy, Debug)]
pub(crate) struct Alignment {
    pub(crate) factor: u64,
    pub(crate) lhs_scale: u64,
    pub(crate) rhs_scale: u64,
}

pub(crate) fn gcd(mut lhs: u64, mut rhs: u64) -> u64 {
    while rhs != 0 {
        (lhs, rhs) = (rhs, lhs % rhs);
    }
    lhs
}

pub(crate) fn is_unit(value: u64, modulus: u64) -> bool {
    modulus >= 2 && value != 0 && value < modulus && gcd(value, modulus) == 1
}

// Inputs are canonical units prepared by a public construction boundary. The
// product remains a unit, so ordinary operations need not repeat a gcd check.
pub(crate) fn multiply(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    if lhs == 1 {
        return rhs;
    }
    if rhs == 1 {
        return lhs;
    }
    (u128::from(lhs) * u128::from(rhs) % u128::from(modulus)) as u64
}

pub(crate) fn inverse(value: u64, modulus: u64) -> u64 {
    if value == 1 {
        return 1;
    }
    let (mut old_r, mut r) = (i128::from(modulus), i128::from(value));
    let (mut old_coefficient, mut coefficient) = (0_i128, 1_i128);
    while r != 0 {
        let quotient = old_r / r;
        (old_r, r) = (r, old_r - quotient * r);
        (old_coefficient, coefficient) = (coefficient, old_coefficient - quotient * coefficient);
    }
    assert_eq!(old_r, 1, "BGV correction factor must be invertible");
    old_coefficient.rem_euclid(i128::from(modulus)) as u64
}

pub(crate) fn centered_abs(value: u64, modulus: u64) -> u64 {
    value.min(modulus - value)
}

// Euclidean remainders supply inexpensive candidate pairs a,b with
// a*lhs == b*rhs mod p. Select a small centered norm among these candidates;
// this is not a global optimum weighted by the operands' actual phase bounds.
pub(crate) fn align(lhs: u64, rhs: u64, modulus: u64) -> Alignment {
    if lhs == rhs {
        return Alignment {
            factor: lhs,
            lhs_scale: 1,
            rhs_scale: 1,
        };
    }
    let ratio = multiply(rhs, inverse(lhs, modulus), modulus);
    let (mut best_lhs, mut best_rhs) = (ratio, 1);
    let mut best_norm = centered_abs(ratio, modulus) + 1;
    let (mut old_r, mut r) = (i128::from(modulus), i128::from(ratio));
    let (mut old_coefficient, mut coefficient) = (0_i128, 1_i128);
    while r != 0 {
        let left = r as u64;
        let right = coefficient.rem_euclid(i128::from(modulus)) as u64;
        if is_unit(left, modulus) && is_unit(right, modulus) {
            let norm = centered_abs(left, modulus) + centered_abs(right, modulus);
            if norm < best_norm {
                (best_lhs, best_rhs, best_norm) = (left, right, norm);
            }
        }
        let quotient = old_r / r;
        (old_r, r) = (r, old_r - quotient * r);
        (old_coefficient, coefficient) = (coefficient, old_coefficient - quotient * coefficient);
    }
    Alignment {
        factor: multiply(best_lhs, lhs, modulus),
        lhs_scale: best_lhs,
        rhs_scale: best_rhs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn euclidean_alignment_preserves_units_and_common_message_scale() {
        for modulus in [2, 5, 15, 193, u64::MAX] {
            let values = [1, 2, 3, 7, modulus / 2, modulus - 1];
            for lhs in values.into_iter().filter(|&x| is_unit(x, modulus)) {
                let inverse = inverse(lhs, modulus);
                assert_eq!(multiply(lhs, inverse, modulus), 1);
                for rhs in values.into_iter().filter(|&x| is_unit(x, modulus)) {
                    let alignment = align(lhs, rhs, modulus);
                    assert!(is_unit(alignment.factor, modulus));
                    assert!(is_unit(alignment.lhs_scale, modulus));
                    assert!(is_unit(alignment.rhs_scale, modulus));
                    assert_eq!(
                        multiply(alignment.lhs_scale, lhs, modulus),
                        alignment.factor
                    );
                    assert_eq!(
                        multiply(alignment.rhs_scale, rhs, modulus),
                        alignment.factor
                    );
                    if lhs == rhs {
                        assert_eq!(alignment.lhs_scale, 1);
                        assert_eq!(alignment.rhs_scale, 1);
                    }
                }
            }
        }
        assert!(!is_unit(0, 17));
        assert!(!is_unit(17, 17));
        assert!(!is_unit(3, 15));
        assert!(!is_unit(5, 15));
    }
}
