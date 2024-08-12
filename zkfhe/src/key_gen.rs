//! implementation of key generation.

use algebra::NTTField;
use fhe_core::{LWEModulusType, Parameters, SecretKeyPack};

/// Struct of key generation.
pub struct KeyGen;

impl KeyGen {
    /// Generate key pair
    #[inline]
    pub fn generate_secret_key<C: LWEModulusType, Q: NTTField, Qks: NTTField>(
        params: Parameters<C, Q, Qks>,
    ) -> SecretKeyPack<C, Q, Qks> {
        SecretKeyPack::new(params)
    }
}
