use algebra::{field::NTTField, polynomial::Polynomial, ring::Ring};

/// the distribution type of the secret key
#[derive(Debug, Clone, Copy)]
pub enum LWESecretKeyDistribution {
    /// Binary SecretKey Distribution
    Binary,
    /// Ternary SecretKey Distribution
    Ternary,
    /// Gaussian SecretKey Distribution
    Gaussian,
}

/// secret key
#[derive(Debug, Clone)]
pub struct LWESecretKey<R: Ring> {
    data: Vec<R>,
    distribution: LWESecretKeyDistribution,
}

impl<R: Ring> LWESecretKey<R> {
    /// Creates a new [`LWESecretKey<R>`].
    #[inline]
    pub fn new(secret_key: Vec<R>, distribution: LWESecretKeyDistribution) -> Self {
        Self {
            data: secret_key,
            distribution,
        }
    }

    /// Returns a reference to the data of this [`LWESecretKey<R>`].
    #[inline]
    pub fn data(&self) -> &[R] {
        self.data.as_ref()
    }

    /// Returns the distribution type of this [`LWESecretKey<R>`].
    #[inline]
    pub fn distribution(&self) -> LWESecretKeyDistribution {
        self.distribution
    }
}

/// secret key
#[derive(Debug, Clone)]
pub struct RLWESecretKey<F: NTTField> {
    data: Polynomial<F>,
}

impl<F: NTTField> RLWESecretKey<F> {
    /// Creates a new [`RLWESecretKey<F>`].
    pub fn new(data: Polynomial<F>) -> Self {
        Self { data }
    }

    /// Returns a reference to the data of this [`RLWESecretKey<F>`].
    pub fn data(&self) -> &Polynomial<F> {
        &self.data
    }
}
