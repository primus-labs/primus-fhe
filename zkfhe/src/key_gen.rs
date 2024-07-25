//! implementation of key generation.

use algebra::NTTField;
use fhe_core::{LWEModulusType, Parameters, SecretKeyPack};

/// Struct of key generation.
pub struct KeyGen;

impl KeyGen {
    /// Generate key pair
    #[inline]
    pub fn generate_secret_key<C: LWEModulusType, F: NTTField>(
        params: Parameters<C, F>,
    ) -> SecretKeyPack<C, F> {
        SecretKeyPack::new(params)
    }
}
