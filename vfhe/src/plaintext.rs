/// LWE Plaintext type
pub type LWEPlaintext<R> = R;

/// RLWE Plaintext type
pub type RLWEPlaintext<F> = algebra::polynomial::Polynomial<F>;
