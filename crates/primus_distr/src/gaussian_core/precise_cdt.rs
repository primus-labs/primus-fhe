use dashu_float::{Context, FBig, Repr, round::mode::HalfEven};
use dashu_int::IBig;

use super::GaussianParameters;

const PRECISION: usize = 512;

type BigFloat = FBig<HalfEven, 2>;

#[inline]
fn float_from_integer(context: Context<HalfEven>, value: impl Into<IBig>) -> BigFloat {
    context.convert_int::<2>(value.into()).value()
}

#[inline]
fn float_zero(context: Context<HalfEven>) -> BigFloat {
    FBig::from_repr(Repr::zero(), context)
}

#[inline]
fn float_one(context: Context<HalfEven>) -> BigFloat {
    FBig::from_repr(Repr::one(), context)
}

/// Builds the 256-bit CDT shared by signed and modular output adapters.
#[inline]
pub(crate) fn build_precise_cdt(parameters: GaussianParameters) -> (f64, Vec<[u64; 4]>) {
    let standard_deviation = parameters.standard_deviation();
    let length = parameters.maximum_magnitude() as usize + 1;
    let context = Context::<HalfEven>::new(PRECISION);
    let standard_deviation = BigFloat::try_from(standard_deviation)
        .expect("validated standard deviation must be finite")
        .with_precision(PRECISION)
        .value();
    let negative_twice_variance_reciprocal = -(standard_deviation.sqr() * 2u32).inv();

    let mut pdf = vec![float_zero(context); length];
    pdf[0] = float_one(context) / 2u32;
    let mut previous = negative_twice_variance_reciprocal.exp();
    pdf[1] = previous.clone();

    // If c = -1/(2σ²), then p_m / p_{m-1} = exp((2m - 1)c).
    // Consecutive ratios differ by the constant exp(2c), so two 512-bit
    // exponentials are enough and all subsequent work retains 512-bit guard
    // precision until the final 256-bit threshold conversion.
    let ratio_step = (&negative_twice_variance_reciprocal * 2u32).exp();
    let mut ratio = &previous * &ratio_step;
    for probability in pdf.iter_mut().skip(2) {
        previous *= &ratio;
        *probability = previous.clone();
        ratio *= &ratio_step;
    }

    let sum = pdf
        .iter()
        .fold(float_zero(context), |sum, value| sum + value);
    let scalar_integer = IBig::ONE << 256usize;
    let scalar = float_from_integer(context, scalar_integer.clone());
    let mut cumulative_probability = float_zero(context);
    let mut cdt = vec![[0; 4]; length + 1];
    for (probability, bound) in pdf.iter().zip(&mut cdt[1..]) {
        cumulative_probability += probability;
        *bound = if cumulative_probability < sum {
            let scaled = (&cumulative_probability / &sum) * &scalar;
            let integer = scaled.to_int().value();
            assert!(
                integer <= scalar_integer,
                "rounded CDT probability must not exceed 2^256"
            );
            if integer == scalar_integer {
                // Half-even conversion can round a value just below 2^256 up
                // to the unrepresentable upper endpoint.
                [u64::MAX; 4]
            } else {
                let words = integer
                    .as_ubig()
                    .expect("scaled CDT probability must be non-negative")
                    .as_words();

                let mut result = [0; 4];
                result[..words.len()].copy_from_slice(words);
                result
            }
        } else {
            [u64::MAX; 4]
        };
    }

    (parameters.standard_deviation(), cdt)
}

#[inline(always)]
/// Compare little-endian limbs from most to least significant for the CDT search.
pub(crate) fn compare_u256(left: &[u64; 4], right: &[u64; 4]) -> std::cmp::Ordering {
    for index in (0..4).rev() {
        match left[index].cmp(&right[index]) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    std::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A higher-precision direct exponential oracle avoids the production mass recurrence.
    #[test]
    fn recurrence_matches_direct_exponentials_at_higher_precision() {
        // Independently evaluate each mass at 768 bits instead of using the
        // production recurrence at 512 bits. Compare every rounded 256-bit
        // integer, including tails that round to the saturated endpoint.
        for (sigma, tail) in [(0.7, 0.5), (1.0, 3.0), (3.2, 12.0), (1.0, 24.0)] {
            let parameters = GaussianParameters::new(sigma, tail).unwrap();
            let (_, actual) = build_precise_cdt(parameters);
            let sigma = BigFloat::try_from(sigma)
                .unwrap()
                .with_precision(768)
                .value();
            let masses: Vec<_> = (0..=parameters.maximum_magnitude())
                .map(|m| {
                    if m == 0 {
                        BigFloat::from(1u32).with_precision(768).value() / 2u32
                    } else {
                        let m = BigFloat::from(m).with_precision(768).value();
                        (-(m.sqr() / (sigma.sqr() * 2u32))).exp()
                    }
                })
                .collect();
            let total: BigFloat = masses.iter().cloned().sum();
            let scale = IBig::ONE << 256usize;
            let maximum = &scale - 1u32;
            let mut cumulative = BigFloat::from(0u32).with_precision(768).value();
            assert_eq!(actual.len(), masses.len() + 1);
            assert_eq!(actual[0], [0; 4]);
            assert_eq!(*actual.last().unwrap(), [u64::MAX; 4]);
            assert!(
                actual
                    .windows(2)
                    .all(|pair| compare_u256(&pair[0], &pair[1]).is_le())
            );
            for (m, mass) in masses.into_iter().enumerate() {
                cumulative += mass;
                let expected = ((&cumulative / &total) * &scale)
                    .to_int()
                    .value()
                    .min(maximum.clone());
                let threshold = actual[m + 1].iter().rev().fold(IBig::ZERO, |value, &word| {
                    (value << 64usize) + IBig::from(word)
                });
                assert_eq!(threshold, expected, "threshold mismatch at magnitude {m}");
            }
        }
    }
}
