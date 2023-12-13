use algebra::ring::Ring;

/// the distribution type of the secret key
#[derive(Debug, Clone, Copy)]
pub enum SecretKeyDistribution {
    /// Binary SecretKey Distribution
    Binary,
    /// Ternary SecretKey Distribution
    Ternary,
    /// Gaussian SecretKey Distribution
    Gaussian,
}

/// secret key
#[derive(Debug, Clone)]
pub struct SecretKey<R: Ring> {
    data: Vec<R>,
    distribution: SecretKeyDistribution,
}

impl<R: Ring> SecretKey<R> {
    /// Creates a new [`SecretKey<R>`].
    #[inline]
    pub fn new(secret_key: Vec<R>, distribution: SecretKeyDistribution) -> Self {
        Self {
            data: secret_key,
            distribution,
        }
    }

    /// Returns a reference to the data of this [`SecretKey<R>`].
    #[inline]
    pub fn data(&self) -> &[R] {
        self.data.as_ref()
    }

    /// Returns the distribution type of this [`SecretKey<R>`].
    #[inline]
    pub fn distribution(&self) -> SecretKeyDistribution {
        self.distribution
    }
}
