use crate::LWEModulusType;

/// LWE Ciphertext
pub type LWECiphertext = lattice::LWE<LWEModulusType>;

/// RLWE Ciphertext
pub type RLWECiphertext<F> = lattice::RLWE<F>;

/// NTT version RLWE Ciphertext
pub type NTTRLWECiphertext<F> = lattice::NTTRLWE<F>;

/// NTRU Cipher text
pub type NTRUCiphertext<F> = lattice::NTRU<F>;

/// NTT version NTRU Cipher text
pub type NTTNTRUCiphertext<F> = lattice::NTTNTRU<F>;
