/// The distribution type of the LWE Secret key
#[derive(Debug, Clone, Copy)]
pub enum LWESecretKeyDistribution {
    /// Binary SecretKey Distribution
    Binary,
    /// Ternary SecretKey Distribution
    Ternary,
}

/// LWE Secret key
pub type LWESecretKey<R> = Vec<R>;

/// RLWE Secret key
pub type RLWESecretKey<F> = algebra::Polynomial<F>;

/// NTT version RLWE Secret key
pub type NTTRLWESecretKey<F> = algebra::NTTPolynomial<F>;
