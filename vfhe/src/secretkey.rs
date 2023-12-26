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

/// lwe secret key
pub type LWESecretKey<R> = Vec<R>;

/// rlwe secret key
pub type RLWESecretKey<F> = algebra::polynomial::Polynomial<F>;
