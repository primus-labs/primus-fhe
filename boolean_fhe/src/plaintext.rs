use algebra::{modulus::PowOf2Modulus, reduce::Reduce};

/// LWE Plain text
pub type LWEPlaintext = bool;

/// LWE ciphertext inner value type
pub type LWEType = u16;

/// Performs dot product for two slices
#[inline]
pub fn dot_product(u: &[LWEType], v: &[LWEType], modulus: PowOf2Modulus<LWEType>) -> LWEType {
    debug_assert_eq!(u.len(), v.len());
    u.iter()
        .zip(v)
        .fold(LWEType::default(), |acc, (&x, &y)| {
            acc.wrapping_add(x.wrapping_mul(y))
        })
        .reduce(modulus)
}

/// The normal distribution `N(mean, std_dev**2)` for [`LWEValue`].
#[derive(Clone, Copy, Debug)]
pub struct LWEValueNormal {
    inner: rand_distr::Normal<f64>,
    std_dev_min: f64,
    std_dev_max: f64,
    modulus: LWEType,
}

impl LWEValueNormal {
    /// Construct, from mean and standard deviation
    ///
    /// Parameters:
    ///
    /// -   mean (`μ`, unrestricted)
    /// -   standard deviation (`σ`, must be finite)
    #[inline]
    pub fn new(
        modulus: LWEType,
        mean: f64,
        std_dev: f64,
    ) -> Result<LWEValueNormal, algebra::AlgebraError> {
        match rand_distr::Normal::new(mean, std_dev) {
            Ok(inner) => {
                let std_dev_max = std_dev * 6.0;
                let std_dev_min = -std_dev_max;
                Ok(LWEValueNormal {
                    inner,
                    std_dev_max,
                    std_dev_min,
                    modulus,
                })
            }
            Err(_) => Err(algebra::AlgebraError::DistributionError),
        }
    }

    /// Returns the mean (`μ`) of the distribution.
    #[inline]
    pub fn mean(&self) -> f64 {
        self.inner.mean()
    }

    /// Returns the standard deviation (`σ`) of the distribution.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.inner.std_dev()
    }

    /// Returns `6σ` of the distribution.
    #[inline]
    pub fn std_dev_max(&self) -> f64 {
        self.std_dev_max
    }

    /// Returns `-6σ` of the distribution.
    #[inline]
    pub fn std_dev_min(&self) -> f64 {
        self.std_dev_min
    }
}

impl rand::distributions::Distribution<LWEType> for LWEValueNormal {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> LWEType {
        let float_p: f64 = self.modulus as f64;
        let mut value = self.inner.sample(rng);
        while value < self.std_dev_min {
            value += self.std_dev();
        }
        while value >= self.std_dev_max {
            value -= self.std_dev();
        }
        if value < 0. {
            if value.ceil() == 0. {
                0
            } else {
                value = float_p + value.ceil();
                value as LWEType
            }
        } else {
            value as LWEType
        }
    }
}

/// The binary distribution for [`LWEValueBinary`].
///
/// prob\[1] = prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct LWEValueBinary {
    inner: rand_distr::Bernoulli,
}

impl LWEValueBinary {
    /// Creates a new [`LWEValueBinary`].
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: rand_distr::Bernoulli::new(0.5).unwrap(),
        }
    }
}

impl Default for LWEValueBinary {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl rand::distributions::Distribution<LWEType> for LWEValueBinary {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> LWEType {
        if self.inner.sample(rng) {
            1
        } else {
            0
        }
    }
}

/// The ternary distribution for [`LWEValueTernary`].
///
/// prob\[1] = prob\[-1] = 0.25
///
/// prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct LWEValueTernary {
    lwe_modulus_mask: LWEType,
    inner1: rand_distr::Bernoulli,
    inner2: rand_distr::Bernoulli,
}

impl LWEValueTernary {
    /// Creates a new [`LWEValueTernary`].
    #[inline]
    pub fn new(lwe_modulus: LWEType) -> Self {
        Self {
            lwe_modulus_mask: lwe_modulus - 1,
            inner1: rand_distr::Bernoulli::new(0.5).unwrap(),
            inner2: rand_distr::Bernoulli::new(0.5).unwrap(),
        }
    }
}

impl rand::distributions::Distribution<LWEType> for LWEValueTernary {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> LWEType {
        if self.inner1.sample(rng) {
            0
        } else if self.inner2.sample(rng) {
            1
        } else {
            self.lwe_modulus_mask
        }
    }
}
