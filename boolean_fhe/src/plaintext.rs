use algebra::{modulus::PowOf2Modulus, reduce::Reduce};
use rand_distr::Normal;

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

/// The gaussian distribution `N(mean, std_dev**2)` for [`LWEValue`].
#[derive(Clone, Copy, Debug)]
pub struct LWEValueGaussian {
    inner: Normal<f64>,
    max_std_dev: f64,
    modulus: LWEType,
}

impl LWEValueGaussian {
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
    ) -> Result<LWEValueGaussian, algebra::AlgebraError> {
        let max_std_dev = std_dev * 6.0;
        if std_dev < 0. {
            return Err(algebra::AlgebraError::DistributionError);
        }
        match Normal::new(mean, std_dev) {
            Ok(inner) => Ok(LWEValueGaussian {
                inner,
                max_std_dev,
                modulus,
            }),
            Err(_) => Err(algebra::AlgebraError::DistributionError),
        }
    }

    /// Construct, from mean and standard deviation
    ///
    /// Parameters:
    ///
    /// -   mean (`μ`, unrestricted)
    /// -   standard deviation (`σ`, must be finite)
    #[inline]
    pub fn new_with_max_limit(
        modulus: LWEType,
        mean: f64,
        std_dev: f64,
        max_std_dev: f64,
    ) -> Result<LWEValueGaussian, algebra::AlgebraError> {
        if max_std_dev <= std_dev || std_dev < 0. {
            return Err(algebra::AlgebraError::DistributionError);
        }
        match Normal::new(mean, std_dev) {
            Ok(inner) => Ok(LWEValueGaussian {
                inner,
                max_std_dev,
                modulus,
            }),
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
    pub fn max_std_dev(&self) -> f64 {
        self.max_std_dev
    }
}

impl rand::distributions::Distribution<LWEType> for LWEValueGaussian {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> LWEType {
        let mean = self.inner.mean();
        loop {
            let value = self.inner.sample(rng);
            if (value - mean).abs() < self.max_std_dev {
                let round = value.round();
                if round < 0. {
                    return self.modulus - ((-value) as LWEType);
                } else {
                    return value as LWEType;
                }
            }
        }
    }
}

/// The binary distribution for [`LWEValueBinary`].
///
/// prob\[1] = prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct LWEValueBinary;

impl rand::distributions::Distribution<LWEType> for LWEValueBinary {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> LWEType {
        (rng.next_u32() & 0b1) as LWEType
    }
}

/// The ternary distribution for [`LWEValueTernary`].
///
/// prob\[1] = prob\[-1] = 0.25
///
/// prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct LWEValueTernary {
    neg_one: LWEType,
}

impl LWEValueTernary {
    /// Creates a new [`LWEValueTernary`].
    #[inline]
    pub fn new(lwe_modulus: LWEType) -> Self {
        Self {
            neg_one: lwe_modulus - 1,
        }
    }
}

impl rand::distributions::Distribution<LWEType> for LWEValueTernary {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> LWEType {
        [0, 0, 1, self.neg_one][(rng.next_u32() & 0b11) as usize]
    }
}

/// Sample a binary vector whose values are `LWEType`.
pub fn sample_binary_lwe_vec<R>(length: usize, rng: &mut R) -> Vec<LWEType>
where
    R: rand::Rng + rand::CryptoRng,
{
    let mut v = vec![0; length];
    let mut iter = v.chunks_exact_mut(32);
    for chunk in &mut iter {
        let mut r = rng.next_u32();
        for elem in chunk.iter_mut() {
            *elem = (r & 0b1) as LWEType;
            r >>= 1;
        }
    }
    let mut r = rng.next_u32();
    for elem in iter.into_remainder() {
        *elem = (r & 0b1) as LWEType;
        r >>= 1;
    }
    v
}

/// Sample a ternary vector whose values are `LWEType`.
pub fn sample_ternary_lwe_vec<R>(lwe_modulus: LWEType, length: usize, rng: &mut R) -> Vec<LWEType>
where
    R: rand::Rng + rand::CryptoRng,
{
    let neg_one = lwe_modulus - 1;
    let s = [0, 0, 1, neg_one];
    let mut v = vec![0; length];
    let mut iter = v.chunks_exact_mut(16);
    for chunk in &mut iter {
        let mut r = rng.next_u32();
        for elem in chunk.iter_mut() {
            *elem = s[(r & 0b11) as usize];
            r >>= 2;
        }
    }
    let mut r = rng.next_u32();
    for elem in iter.into_remainder() {
        *elem = s[(r & 0b11) as usize];
        r >>= 2;
    }
    v
}
