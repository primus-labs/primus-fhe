/// LWE Cipher text
pub type LWECiphertext<R> = lattice::LWE<R>;

/// RLWE Cipher text
pub type RLWECiphertext<F> = lattice::RLWE<F>;

/// NTT version RLWE Cipher text
pub type NTTRLWECiphertext<F> = lattice::NTTRLWE<F>;
