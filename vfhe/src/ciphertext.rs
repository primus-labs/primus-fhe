/// cipher text
pub type LWECiphertext<R> = lattice::LWE<R>;

/// cipher text
pub type RLWECiphertext<F> = lattice::RLWE<F>;

/// cipher text
pub type NTTRLWECiphertext<F> = lattice::NTTRLWE<F>;
