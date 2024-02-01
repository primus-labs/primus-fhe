use crate::LWEValue;

/// LWE Cipher text
pub type LWECiphertext = lattice::LWE<LWEValue>;

/// RLWE Cipher text
pub type RLWECiphertext<F> = lattice::RLWE<F>;

/// NTT version RLWE Cipher text
pub type NTTRLWECiphertext<F> = lattice::NTTRLWE<F>;
