use crate::LWEPlaintext;

/// LWE Cipher text
pub type LWECiphertext = lattice::LWE<LWEPlaintext>;

/// NTRU Cipher text
pub type NTRUCiphertext<F> = lattice::NTRU<F>;

/// NTT version NTRU Cipher text
pub type NTTNTRUCiphertext<F> = lattice::NTTNTRU<F>;
