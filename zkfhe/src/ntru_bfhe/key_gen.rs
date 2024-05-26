//! implementation of key generation.

use algebra::NTTField;
use fhe_core::{NTRUSecretKeyPack, Parameters};

/// struct of key generation.
pub struct KeyGen;

impl KeyGen {
    /// Generate key pair
    #[inline]
    pub fn generate_secret_key<F: NTTField>(params: Parameters<F>) -> NTRUSecretKeyPack<F> {
        NTRUSecretKeyPack::new(params)
    }
}
