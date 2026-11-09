use core::cmp::Ordering;

use crate::multiplication::words::{
    add_words_assign, cmp_words, mul_scalar_to, shift_left, sub_words_assign,
};

// The exact quotient floor((t*r+floor(Q/2))/Q) fits in one u64 because
// 0<=r<Q and t<2^63. After normalizing Q's high limb, division by its high
// word overestimates the quotient by at most two. If B=2^64, normalized
// Q=v*B^(l-1)+low with v>=B/2. For the true h, W<(h+1)*Q, so the top-word
// estimate is <h+1+(h+1)/v<=h+3. It is >=h because the truncated denominator
// is <=Q. The codec checks t<gamma<=u64::MAX/2, hence h<=t<2^63 and h+2
// still fits u64. Full integer comparisons remove the overestimate; there is
// no precision or probabilistic fallback.
pub(super) struct ScalarQuotient {
    normalized_q: Vec<u64>,
    shift: u32,
    numerator: Vec<u64>,
    product: Vec<u64>,
}

impl ScalarQuotient {
    pub(super) fn new(q: &[u64]) -> Self {
        let live = q.iter().rposition(|&x| x != 0).expect("nonzero Q") + 1;
        let mut normalized_q = q[..live].to_vec();
        let shift = normalized_q[live - 1].leading_zeros();
        let carry = shift_left(&mut normalized_q, shift);
        debug_assert_eq!(carry, 0);
        Self {
            normalized_q,
            shift,
            numerator: vec![0; live + 1],
            product: vec![0; live + 1],
        }
    }

    pub(super) fn round(&mut self, r: &[u64], t: u64, half_q: &[u64]) -> u64 {
        let length = self.normalized_q.len();
        mul_scalar_to(&r[..length], t, &mut self.numerator);
        add_words_assign(&mut self.numerator, half_q);
        let carry = shift_left(&mut self.numerator, self.shift);
        debug_assert_eq!(carry, 0);
        let leading = ((self.numerator[length] as u128) << 64) | self.numerator[length - 1] as u128;
        let estimate = leading / self.normalized_q[length - 1] as u128;
        let mut quotient = u64::try_from(estimate).expect("BFV scale quotient fits u64");
        mul_scalar_to(&self.normalized_q, quotient, &mut self.product);
        let mut corrections = 0;
        while cmp_words(&self.product, &self.numerator) == Ordering::Greater {
            quotient -= 1;
            sub_words_assign(&mut self.product, &self.normalized_q);
            corrections += 1;
        }
        debug_assert!(corrections <= 2);
        quotient
    }
}

#[cfg(test)]
mod tests {
    use dashu_int::IBig;

    use super::ScalarQuotient;
    use crate::multiplication::words::half;

    fn words(value: &IBig, length: usize) -> Vec<u64> {
        let radix = IBig::ONE << 64;
        let mut value = value.clone();
        (0..length)
            .map(|_| {
                let word = u64::try_from(&value % &radix).unwrap();
                value >>= 64;
                word
            })
            .collect()
    }

    #[test]
    fn one_word_quotient_normalization_and_half_neighbors_match_integer_division() {
        let mut overestimates = 0;
        for bits in [61usize, 64, 65, 100, 127, 128, 129, 150, 190, 191] {
            let q = (IBig::ONE << bits) - 13u64;
            let q_words = words(&q, bits.div_ceil(64));
            let half_q = half(&q_words);
            let mut rounder = ScalarQuotient::new(&q_words);
            for t in [2u64, 193, (1 << 30) + 3, (1 << 62) - 57] {
                let mut inputs = vec![IBig::ZERO, IBig::ONE, &q / 2u64, &q - 2u64, &q - 1u64];
                for k in [0, 1, t / 3, t / 2, t - 1] {
                    let boundary = (&q * (2 * k + 1)) / IBig::from(2 * t);
                    for adjustment in [-1, 0, 1] {
                        let value = &boundary + adjustment;
                        if value >= IBig::ZERO && value < q {
                            inputs.push(value);
                        }
                    }
                }
                for r in inputs {
                    let expected = u64::try_from((&r * t + &q / 2u64) / &q).unwrap();
                    let actual = rounder.round(&words(&r, q_words.len()), t, &half_q);
                    assert_eq!(actual, expected, "Q bits={bits}, t={t}, r={r}");
                    let length = rounder.normalized_q.len();
                    let leading = ((rounder.numerator[length] as u128) << 64)
                        | rounder.numerator[length - 1] as u128;
                    let estimate = leading / rounder.normalized_q[length - 1] as u128;
                    assert!(estimate >= u128::from(expected));
                    assert!(estimate - u128::from(expected) <= 2);
                    overestimates += usize::from(estimate > u128::from(expected));
                }
            }
        }
        assert!(
            overestimates > 0,
            "fixtures must exercise full-word correction"
        );
    }
}
