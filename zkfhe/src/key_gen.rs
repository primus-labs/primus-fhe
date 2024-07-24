//! implementation of key generation.

use algebra::NTTField;
use fhe_core::{LWEModulusType, LWEMsgType, Parameters, SecretKeyPack};

/// Struct of key generation.
pub struct KeyGen;

impl KeyGen {
    /// Generate key pair
    #[inline]
    pub fn generate_secret_key<M: LWEMsgType, C: LWEModulusType, F: NTTField>(
        params: Parameters<M, C, F>,
    ) -> SecretKeyPack<M, C, F> {
        SecretKeyPack::new(params)
    }
}
