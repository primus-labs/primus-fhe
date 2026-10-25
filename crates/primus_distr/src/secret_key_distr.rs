/// Distribution used to sample secret-key coefficients.
///
/// Individual cryptosystems may support only a subset of these distributions.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecretKeyDistr {
    /// Uniform binary coefficients with `P(0) = P(1) = 1/2`.
    UniformBinary,
    /// Binary coefficients with the configured probability of sampling `1`.
    Binary {
        /// Probability of sampling `1`; the remaining probability belongs to `0`.
        one_probability: f64,
    },
    /// Sparse ternary coefficients with `P(0) = 1/2` and `P(-1) = P(1) = 1/4`.
    SparseTernary,
    /// Uniform ternary coefficients with `P(-1) = P(0) = P(1) = 1/3`.
    UniformTernary,
    /// Ternary coefficients with independently configured `-1` and `1` probabilities.
    Ternary {
        /// Probability of sampling `-1`.
        negative_one_probability: f64,
        /// Probability of sampling `1`; the remaining probability belongs to `0`.
        one_probability: f64,
    },
    /// Binary coefficients with an exact number of ones.
    /// Use [`Self::fixed_hamming_weight_binary`] to check the logical key length.
    FixedHammingWeightBinary {
        /// Exact number of coefficients equal to `1`.
        hamming_weight: usize,
    },
    /// Exactly `hamming_weight` uniformly selected nonzero positions, with
    /// independent uniform signs. Positive and negative counts are not fixed.
    FixedHammingWeightTernary {
        /// Exact number of nonzero coefficients in the complete logical key.
        hamming_weight: usize,
    },
    /// Ternary coefficients with exact numbers of negative and positive ones.
    /// Use [`Self::fixed_composition_ternary`] to check the logical key length.
    FixedCompositionTernary {
        /// Exact number of coefficients equal to `-1`.
        negative_one_weight: usize,
        /// Exact number of coefficients equal to `1`.
        one_weight: usize,
    },
    /// Centered discrete Gaussian coefficients with the given standard deviation.
    Gaussian {
        /// Standard deviation of the centered discrete Gaussian.
        standard_deviation: f64,
    },
}

impl SecretKeyDistr {
    /// Constructs a binary distribution with the given probability of `1`.
    ///
    /// # Panics
    ///
    /// Panics if the probability is not finite or is outside `[0, 1]`.
    #[must_use]
    #[inline]
    pub fn binary(one_probability: f64) -> Self {
        validate_probability(one_probability);
        Self::Binary { one_probability }
    }

    /// Constructs a ternary distribution with the given probabilities of `-1`
    /// and `1`; the remaining probability belongs to `0`.
    ///
    /// # Panics
    ///
    /// Panics if either probability is not finite or is outside `[0, 1]`,
    /// or their sum exceeds one.
    #[must_use]
    #[inline]
    pub fn ternary(negative_one_probability: f64, one_probability: f64) -> Self {
        validate_ternary_probabilities(negative_one_probability, one_probability);
        Self::Ternary {
            negative_one_probability,
            one_probability,
        }
    }

    /// Constructs a binary distribution with exactly `hamming_weight` ones
    /// in a complete logical key of `length` coefficients.
    ///
    /// The length is checked but not stored; sampling checks the actual output
    /// length again because it may differ from this length.
    ///
    /// # Panics
    ///
    /// Panics if `hamming_weight > length`.
    #[must_use]
    #[inline]
    pub fn fixed_hamming_weight_binary(length: usize, hamming_weight: usize) -> Self {
        assert!(
            hamming_weight <= length,
            "binary Hamming weight must not exceed the key length"
        );
        Self::FixedHammingWeightBinary { hamming_weight }
    }

    /// Constructs a ternary distribution with exactly `hamming_weight` nonzero
    /// coefficients at uniformly selected positions and independent uniform signs.
    /// The length is checked but not stored; sampling checks the actual length.
    ///
    /// # Panics
    ///
    /// Panics if `hamming_weight > length`.
    #[must_use]
    #[inline]
    pub fn fixed_hamming_weight_ternary(length: usize, hamming_weight: usize) -> Self {
        assert!(
            hamming_weight <= length,
            "ternary Hamming weight must not exceed the key length"
        );
        Self::FixedHammingWeightTernary { hamming_weight }
    }

    /// Constructs a ternary distribution with exact negative and positive
    /// weights in a complete logical key of `length` coefficients.
    ///
    /// The length is checked but not stored; sampling checks the actual output
    /// length again because it may differ from this length.
    ///
    /// # Panics
    ///
    /// Panics if the weight sum overflows `usize` or exceeds `length`.
    #[must_use]
    #[inline]
    pub fn fixed_composition_ternary(
        length: usize,
        negative_one_weight: usize,
        one_weight: usize,
    ) -> Self {
        let nonzero_weight = negative_one_weight
            .checked_add(one_weight)
            .expect("ternary Hamming weights must fit in usize");
        assert!(
            nonzero_weight <= length,
            "ternary Hamming weights must not exceed the key length"
        );
        Self::FixedCompositionTernary {
            negative_one_weight,
            one_weight,
        }
    }

    /// Describes a centered discrete Gaussian with the given standard deviation.
    ///
    /// Validation is deferred to sampler construction, where the output type,
    /// modulus (if any), and Gaussian backend are known.
    #[must_use]
    #[inline]
    pub const fn gaussian(standard_deviation: f64) -> Self {
        Self::Gaussian { standard_deviation }
    }

    /// Returns whether the distribution produces only coefficients in `{0, 1}`.
    #[must_use]
    #[inline]
    pub const fn is_binary(self) -> bool {
        matches!(
            self,
            Self::UniformBinary | Self::Binary { .. } | Self::FixedHammingWeightBinary { .. }
        )
    }

    /// Returns whether this is one of the ternary-family distributions.
    #[must_use]
    #[inline]
    pub const fn is_ternary(self) -> bool {
        matches!(
            self,
            Self::SparseTernary
                | Self::UniformTernary
                | Self::Ternary { .. }
                | Self::FixedHammingWeightTernary { .. }
                | Self::FixedCompositionTernary { .. }
        )
    }
}

#[inline]
fn validate_probability(probability: f64) {
    assert!(
        probability.is_finite() && (0.0..=1.0).contains(&probability),
        "secret-key coefficient probability must be finite and in [0, 1]"
    );
}

#[inline]
pub(crate) fn validate_ternary_probabilities(negative: f64, positive: f64) {
    check_ternary_probabilities(negative, positive).unwrap_or_else(|error| panic!("{error}"));
}

/// Checks the distribution before integer thresholds are prepared.
pub(crate) fn check_ternary_probabilities(
    negative: f64,
    positive: f64,
) -> Result<(), crate::SecretKeySamplerError> {
    if !negative.is_finite()
        || !positive.is_finite()
        || !(0.0..=1.0).contains(&negative)
        || !(0.0..=1.0).contains(&positive)
        || negative > 1.0 - positive
    {
        return Err(crate::SecretKeySamplerError::InvalidProbabilities);
    }
    Ok(())
}
