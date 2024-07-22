//! implementation of key generation.

use algebra::NTTField;
use fhe_core::{LWECipherValueContainer, LWEPlainContainer, Parameters, SecretKeyPack};

/// Struct of key generation.
pub struct KeyGen;

impl KeyGen {
    /// Generate key pair
    #[inline]
    pub fn generate_secret_key<M: LWEPlainContainer<C>, C: LWECipherValueContainer, F: NTTField>(
        params: Parameters<M, C, F>,
    ) -> SecretKeyPack<M, C, F> {
        SecretKeyPack::new(params)
    }
}
