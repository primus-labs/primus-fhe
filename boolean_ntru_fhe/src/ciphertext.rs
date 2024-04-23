use crate::LWEContainer;

/// Cipher text type of the first layer scheme
pub type LWECiphertext = lattice::LWE<LWEContainer>;

/// Cipher text of the second layer ntru scheme
pub type NTRUCiphertext<F> = lattice::NTRU<F>;

/// NTT version Cipher text of the second layer scheme
pub type NTTNTRUCiphertext<F> = lattice::NTTNTRU<F>;
