use crate::LWEPlaintext;

/// LWE Cipher text
pub type LWECiphertext = lattice::LWE<LWEPlaintext>;

/// NTRU Cipher text
pub type NTRUCiphertext<F> = lattice::NTRU<F>;

/// NTT version NTRU Cipher text
pub type NTTNTRUCiphertext<F> = lattice::NTTNTRU<F>;

/// NTRU Modulus Switch Result
pub struct NTRUModulusSwitch {
    data: Vec<LWEPlaintext>,
}

impl NTRUModulusSwitch {
    /// Creates a new [`NTRUModulusSwitch`].
    #[inline]
    pub fn new(data: Vec<LWEPlaintext>) -> Self {
        Self { data }
    }

    /// .
    #[inline]
    pub fn data(self) -> Vec<LWEPlaintext> {
        self.data
    }
}
