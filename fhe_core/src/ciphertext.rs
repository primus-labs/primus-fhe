/// LWE Ciphertext
pub type LWECiphertext<C> = lattice::LWE<C>;

/// RLWE Ciphertext
pub type RLWECiphertext<F> = lattice::RLWE<F>;

/// NTT version RLWE Ciphertext
pub type NTTRLWECiphertext<F> = lattice::NTTRLWE<F>;
