use num_traits::{ConstOne, ConstZero};
use primus_integer::{AsInto, FheInt, FheUint};
use rand::distr::Bernoulli;

use crate::{
    SecretKeyDistr, SecretKeySamplerError, SignedDiscreteGaussian, ternary::TernarySampler,
};

/// Prepared whole-key sampling with shared signed and modular output paths.
///
/// `T` is the unsigned coefficient type. The same probability thresholds and
/// Gaussian tables produce signed `T::SignedInteger` coefficients or canonical
/// residues modulo a caller-supplied modulus. No ciphertext modulus is stored.
/// Fixed weights apply to the complete output slice.
#[derive(Clone)]
pub struct SecretKeySampler<T: FheUint> {
    distr: SecretKeyDistr,
    method: SamplingMethod<SignedDiscreteGaussian<T::SignedInteger>>,
}

/// Prepared state for one algorithm; dispatch stays outside coefficient loops.
#[derive(Clone)]
enum SamplingMethod<G> {
    UniformBinary,
    Binary(Bernoulli),
    SparseTernary,
    UniformTernary,
    Ternary(TernarySampler),
    FixedHammingWeightBinary {
        hamming_weight: usize,
    },
    FixedHammingWeightTernary {
        hamming_weight: usize,
    },
    FixedCompositionTernary {
        negative_one_weight: usize,
        one_weight: usize,
    },
    Gaussian(G),
}

impl<T: FheUint> SecretKeySampler<T> {
    /// Prepares one distribution for both signed and encoded output.
    ///
    /// # Panics
    ///
    /// Panics if probabilities are invalid or Gaussian construction violates
    /// [`SignedDiscreteGaussian::new`]'s validity rules for `T::SignedInteger`.
    /// Fixed weights are checked against the complete output length when sampling.
    #[must_use]
    pub fn new(distr: SecretKeyDistr) -> Self {
        Self::try_new(distr).expect("invalid secret-key sampler")
    }

    /// Prepares probabilities and Gaussian tables, returning their validation
    /// errors. Fixed weights are checked separately by [`Self::validate_length`]
    /// or when sampling into the actual output.
    pub fn try_new(distr: SecretKeyDistr) -> Result<Self, SecretKeySamplerError> {
        let method = match distr {
            SecretKeyDistr::UniformBinary => SamplingMethod::UniformBinary,
            SecretKeyDistr::Binary { one_probability } => SamplingMethod::Binary(
                Bernoulli::new(one_probability)
                    .map_err(|_| SecretKeySamplerError::InvalidProbabilities)?,
            ),
            SecretKeyDistr::SparseTernary => SamplingMethod::SparseTernary,
            SecretKeyDistr::UniformTernary => SamplingMethod::UniformTernary,
            SecretKeyDistr::Ternary {
                negative_one_probability,
                one_probability,
            } => SamplingMethod::Ternary(TernarySampler::try_new(
                negative_one_probability,
                one_probability,
            )?),
            SecretKeyDistr::FixedHammingWeightBinary { hamming_weight } => {
                SamplingMethod::FixedHammingWeightBinary { hamming_weight }
            }
            SecretKeyDistr::FixedHammingWeightTernary { hamming_weight } => {
                SamplingMethod::FixedHammingWeightTernary { hamming_weight }
            }
            SecretKeyDistr::FixedCompositionTernary {
                negative_one_weight,
                one_weight,
            } => SamplingMethod::FixedCompositionTernary {
                negative_one_weight,
                one_weight,
            },
            SecretKeyDistr::Gaussian { standard_deviation } => {
                SamplingMethod::Gaussian(SignedDiscreteGaussian::new(standard_deviation)?)
            }
        };
        Ok(Self { distr, method })
    }

    /// Checks fixed weights against a complete logical key before key generation.
    /// Returns an error if the weight sum overflows or exceeds `length`.
    /// Sampling still checks the actual output, which may have a different length.
    pub fn validate_length(&self, length: usize) -> Result<(), SecretKeySamplerError> {
        let weight = match self.distr {
            SecretKeyDistr::FixedHammingWeightBinary { hamming_weight }
            | SecretKeyDistr::FixedHammingWeightTernary { hamming_weight } => Some(hamming_weight),
            SecretKeyDistr::FixedCompositionTernary {
                negative_one_weight,
                one_weight,
            } => negative_one_weight.checked_add(one_weight),
            _ => Some(0),
        };
        if weight.is_none_or(|weight| weight > length) {
            return Err(SecretKeySamplerError::InvalidWeight { length });
        }
        Ok(())
    }

    /// Checks the output-domain precondition of [`Self::sample_encoded_to`].
    /// Call once when preparing parameters, and once per modulus for RNS output.
    /// `T::MAX` denotes the native modulus; no modulus is stored by the sampler.
    /// Returns an error if the inclusive support bound exceeds `modulus_minus_one`.
    pub fn validate_modulus(&self, modulus_minus_one: T) -> Result<(), SecretKeySamplerError> {
        let maximum_magnitude = self.maximum_magnitude();
        if maximum_magnitude > modulus_minus_one {
            return Err(SecretKeySamplerError::ModulusTooSmall {
                maximum_magnitude: maximum_magnitude.as_into(),
                modulus_minus_one: modulus_minus_one.as_into(),
            });
        }
        Ok(())
    }

    /// Returns the configured coefficient distribution.
    #[must_use]
    #[inline]
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    /// Returns an inclusive unsigned bound on every sample's magnitude.
    /// Use [`Self::validate_modulus`] before encoded sampling. Gaussian uses its
    /// truncated support; binary/ternary return one.
    #[must_use]
    #[inline]
    pub fn maximum_magnitude(&self) -> T {
        match &self.method {
            SamplingMethod::Gaussian(gaussian) => gaussian.maximum_magnitude().as_into(),
            _ => T::ONE,
        }
    }

    /// Samples a complete signed key into a newly allocated vector.
    ///
    /// # Panics
    ///
    /// Panics if a fixed weight exceeds `length` or its sum overflows.
    #[must_use]
    pub fn sample_signed<R: rand::Rng + rand::CryptoRng>(
        &self,
        length: usize,
        rng: &mut R,
    ) -> Vec<T::SignedInteger> {
        if let SamplingMethod::Gaussian(gaussian) = &self.method {
            return gaussian.sample_vec(length, rng);
        }
        let mut output = vec![T::SignedInteger::ZERO; length];
        self.sample_signed_to(&mut output, rng);
        output
    }

    /// Overwrites a complete signed key without allocating.
    /// Fixed weights apply to the whole slice, not independently to chunks.
    /// Randomness consumption follows the underlying vector samplers and may
    /// change with their algorithms; empty slices may consume randomness.
    /// A panicking RNG may leave partially written output.
    ///
    /// # Panics
    ///
    /// Panics before writing or sampling if a fixed weight exceeds the output
    /// length or its sum overflows.
    #[inline]
    pub fn sample_signed_to<R: rand::Rng + rand::CryptoRng>(
        &self,
        output: &mut [T::SignedInteger],
        rng: &mut R,
    ) {
        self.sample_to_with(
            output,
            -T::SignedInteger::ONE,
            rng,
            SignedDiscreteGaussian::sample_to,
        );
    }

    /// Samples a complete key as canonical residues into a newly allocated vector.
    /// No intermediate signed vector is allocated.
    ///
    /// # Correctness
    ///
    /// `modulus_minus_one >= self.maximum_magnitude()` must hold. `T::MAX`
    /// denotes the native modulus. Establish this with [`Self::validate_modulus`]
    /// once when preparing parameters.
    ///
    /// # Panics
    ///
    /// Panics if a fixed weight exceeds `length` or its sum overflows.
    #[must_use]
    pub fn sample_encoded<R: rand::Rng + rand::CryptoRng>(
        &self,
        length: usize,
        modulus_minus_one: T,
        rng: &mut R,
    ) -> Vec<T> {
        if let SamplingMethod::Gaussian(gaussian) = &self.method {
            return gaussian.sample_encoded(length, modulus_minus_one, rng);
        }
        let mut output = vec![T::ZERO; length];
        self.sample_encoded_to(&mut output, modulus_minus_one, rng);
        output
    }

    /// Overwrites a complete key with canonical residues without allocating.
    /// Fixed weights apply to the whole slice. RNG consumption follows
    /// [`Self::sample_signed_to`]; a panicking RNG may leave partial output.
    ///
    /// # Correctness
    ///
    /// `modulus_minus_one >= self.maximum_magnitude()` must hold. `T::MAX`
    /// denotes the native modulus. Establish this with [`Self::validate_modulus`]
    /// once when preparing parameters.
    ///
    /// # Panics
    ///
    /// Panics before writing or sampling if a fixed weight exceeds the output
    /// length or its sum overflows.
    #[inline]
    pub fn sample_encoded_to<R: rand::Rng + rand::CryptoRng>(
        &self,
        output: &mut [T],
        modulus_minus_one: T,
        rng: &mut R,
    ) {
        self.sample_to_with(output, modulus_minus_one, rng, |gaussian, output, rng| {
            gaussian.sample_encoded_to(output, modulus_minus_one, rng)
        });
    }

    /// Shared distribution dispatch. The representation-specific wrapper supplies
    /// the Gaussian batch method, so this layer does not name Gaussian backends.
    // Keep this large batch switch out of callers: inlining it regressed binary
    // and dense fixed-weight cases in the sample_secret_key benchmark.
    #[inline(never)]
    fn sample_to_with<U: FheInt, R: rand::Rng + rand::CryptoRng>(
        &self,
        output: &mut [U],
        minus_one: U,
        rng: &mut R,
        sample_gaussian: impl FnOnce(&SignedDiscreteGaussian<T::SignedInteger>, &mut [U], &mut R),
    ) {
        match &self.method {
            SamplingMethod::UniformBinary => crate::sample_uniform_binary_values_to(output, rng),
            SamplingMethod::Binary(distribution) => {
                crate::binary::fill_binary(output, distribution, rng)
            }
            SamplingMethod::SparseTernary => {
                crate::sample_sparse_ternary_values_to(output, minus_one, rng)
            }
            SamplingMethod::UniformTernary => {
                crate::sample_uniform_ternary_values_to(output, minus_one, rng)
            }
            SamplingMethod::Ternary(distribution) => distribution.sample_to(output, minus_one, rng),
            SamplingMethod::FixedHammingWeightBinary { hamming_weight } => {
                crate::sample_fixed_hamming_weight_binary_values_to(output, *hamming_weight, rng)
            }
            SamplingMethod::FixedHammingWeightTernary { hamming_weight } => {
                crate::sample_fixed_hamming_weight_ternary_values_to(
                    output,
                    minus_one,
                    *hamming_weight,
                    rng,
                )
            }
            SamplingMethod::FixedCompositionTernary {
                negative_one_weight,
                one_weight,
            } => crate::sample_fixed_composition_ternary_values_to(
                output,
                minus_one,
                *negative_one_weight,
                *one_weight,
                rng,
            ),
            SamplingMethod::Gaussian(gaussian) => sample_gaussian(gaussian, output, rng),
        }
    }
}
